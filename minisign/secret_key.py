import base64
import copy
import hashlib
import hmac
import os
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import TracebackType
from typing import NoReturn

from cryptography.hazmat.primitives.asymmetric import ed25519
from typing_extensions import Self

from .algo import (
    CksumAlgorithm,
    KDFAlgorithm,
    SignatureAlgorithm,
)
from .const import (
    ALG_LEN,
    BYTE_ORDER,
    CHECKSUM_LEN,
    DEFAULT_SIGNATURE_UNTRUSTED_COMMENT,
    DEFAULT_SK_PATH,
    KDF_PARAM_LEN,
    KEY_ID_LEN,
    KEY_LEN,
    KEYNUM_SK_LEN,
    SALT_LEN,
    SECRET_KEY_LEN,
    SIG_EXT,
    TRUSTED_COMMENT_MAX_LEN,
    UNTRUSTED_COMMENT_PREFIX,
    PathLike,
)
from .exceptions import Error, ParseError
from .helpers import (
    BytesReaderProto,
    Reader,
    check_comment,
    decode_base64,
    decode_comment,
    read_data,
    split_lines,
)
from .public_key import PublicKey
from .scrypt import (
    MEMLIMIT,
    OPSLIMIT,
    xor_crypt,
)
from .signature import Signature


@dataclass(slots=True, kw_only=True, repr=False)
class KeynumSK:
    key_id: bytearray
    secret_key: bytearray
    public_key: bytearray
    checksum: bytearray

    @classmethod
    def from_bytes(cls, data: bytes | Reader) -> Self:
        if len(data) != KEYNUM_SK_LEN:
            raise ParseError("invalid secret key length")
        if isinstance(data, bytes):
            data = Reader(data)
        return cls(
            key_id=bytearray(data.read(KEY_ID_LEN)),
            secret_key=bytearray(data.read(KEY_LEN)),
            public_key=bytearray(data.read(KEY_LEN)),
            checksum=bytearray(data.read(CHECKSUM_LEN)),
        )

    def wipe(self) -> None:
        for value in (
            self.key_id,
            self.secret_key,
            self.public_key,
            self.checksum,
        ):
            value[:] = bytes(len(value))

    def xor(self, key: bytes | bytearray) -> None:
        if len(key) != KEYNUM_SK_LEN:
            raise ValueError("invalid XOR stream length")
        offset = 0
        for value in (
            self.key_id,
            self.secret_key,
            self.public_key,
            self.checksum,
        ):
            for index in range(len(value)):
                value[index] ^= key[offset + index]
            offset += len(value)

    def __bytes__(self) -> bytes:
        return (
            bytes(self.key_id)
            + bytes(self.secret_key)
            + bytes(self.public_key)
            + bytes(self.checksum)
        )


@dataclass(slots=True, kw_only=True, repr=False)
class SecretKey:
    _untrusted_comment: str | None = field(compare=False)
    _signature_algorithm: SignatureAlgorithm
    _kdf_algorithm: KDFAlgorithm
    _cksum_algorithm: CksumAlgorithm
    _kdf_salt: bytes
    _kdf_opslimit: int
    _kdf_memlimit: int
    _keynum_sk: KeynumSK
    _is_wiped: bool = field(default=False, init=False, compare=False, repr=False)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.wipe()

    def __copy__(self) -> NoReturn:
        raise TypeError("secret keys cannot be shallow-copied")

    @classmethod
    def from_base64(cls, s: str | bytes) -> Self:
        buf = Reader(decode_base64(s, SECRET_KEY_LEN))
        try:
            signature_algorithm = SignatureAlgorithm(buf.read(ALG_LEN))
            kdf_algorithm = KDFAlgorithm(buf.read(ALG_LEN))
            cksum_algorithm = CksumAlgorithm(buf.read(ALG_LEN))
        except ValueError as err:
            raise ParseError("unsupported key algorithm") from err
        if signature_algorithm == SignatureAlgorithm.PREHASHED_ED_DSA:
            raise ParseError("invalid signature algorithm")
        return cls(
            _untrusted_comment=None,
            _signature_algorithm=signature_algorithm,
            _kdf_algorithm=kdf_algorithm,
            _cksum_algorithm=cksum_algorithm,
            _kdf_salt=buf.read(SALT_LEN),
            _kdf_opslimit=int.from_bytes(buf.read(KDF_PARAM_LEN), BYTE_ORDER),
            _kdf_memlimit=int.from_bytes(buf.read(KDF_PARAM_LEN), BYTE_ORDER),
            _keynum_sk=KeynumSK.from_bytes(buf),
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        lines = split_lines(data, 2)
        v = cls.from_base64(lines[1])
        v.untrusted_comment = decode_comment(lines[0], UNTRUSTED_COMMENT_PREFIX)
        return v

    @classmethod
    def from_file(
        cls,
        path: PathLike | None = None,
    ) -> Self:
        if path is None:
            path = Path(DEFAULT_SK_PATH).expanduser().resolve(strict=True)
        with open(path, "rb") as f:
            return cls.from_bytes(f.read())

    @property
    def untrusted_comment(self) -> str | None:
        return self._untrusted_comment

    @untrusted_comment.setter
    def untrusted_comment(self, value: str | None) -> None:
        if value is not None:
            check_comment(value)
        self._untrusted_comment = value

    def get_public_key(self) -> PublicKey:
        self._check_is_wiped()
        return PublicKey.from_secret_key(self)

    def is_wiped(self) -> bool:
        return self._is_wiped

    def wipe(self) -> None:
        self._keynum_sk.wipe()
        self._is_wiped = True

    def _check_is_wiped(self) -> None:
        if self._is_wiped:
            raise Error("secret key has been wiped")

    def is_encrypted(self) -> bool:
        self._check_is_wiped()
        if self._kdf_algorithm == KDFAlgorithm.NONE:
            return False
        return not hmac.compare_digest(
            self._calc_checksum(), bytes(self._keynum_sk.checksum)
        )

    def decrypt(self, password: str) -> None:
        self._check_is_wiped()
        if not self.is_encrypted():
            return
        candidate = copy.deepcopy(self._keynum_sk)
        try:
            xor_crypt(
                keynum_sk=candidate,
                password=password,
                salt=self._kdf_salt,
                opslimit=self._kdf_opslimit,
                memlimit=self._kdf_memlimit,
            )
            if not hmac.compare_digest(
                self._calc_checksum(candidate), bytes(candidate.checksum)
            ):
                raise Error("wrong password for that key")
        except BaseException:
            candidate.wipe()
            raise
        encrypted = self._keynum_sk
        self._keynum_sk = candidate
        encrypted.wipe()

    def encrypt(
        self,
        password: str,
        *,
        opslimit: int = OPSLIMIT,
        memlimit: int = MEMLIMIT,
    ) -> None:
        self._check_is_wiped()
        if self.is_encrypted():
            raise Error("secret key is already encrypted")
        salt = secrets.token_bytes(SALT_LEN)
        xor_crypt(
            keynum_sk=self._keynum_sk,
            password=password,
            salt=salt,
            opslimit=opslimit,
            memlimit=memlimit,
        )
        self._kdf_algorithm = KDFAlgorithm.SCRYPT
        self._kdf_salt = salt
        self._kdf_opslimit = opslimit
        self._kdf_memlimit = memlimit

    def sign(
        self,
        data: bytes | BytesReaderProto,
        *,
        prehash: bool = True,
        untrusted_comment: str | None = None,
        trusted_comment: str | None = None,
    ) -> Signature:
        self._check_is_wiped()
        if self.is_encrypted():
            raise Error("secret key is encrypted; decrypt it before signing")
        if untrusted_comment is None:
            untrusted_comment = DEFAULT_SIGNATURE_UNTRUSTED_COMMENT
        else:
            check_comment(untrusted_comment)
        if trusted_comment is None:
            trusted_comment = f"timestamp:{int(time.time())}"
        else:
            check_comment(trusted_comment)
            if len(trusted_comment) > TRUSTED_COMMENT_MAX_LEN:
                raise ParseError("trusted comment too long")
        pk = ed25519.Ed25519PrivateKey.from_private_bytes(self._keynum_sk.secret_key)
        sig_sig = pk.sign(read_data(data, prehash))
        return Signature(
            _untrusted_comment=untrusted_comment,
            _signature_algorithm=(
                SignatureAlgorithm.PREHASHED_ED_DSA
                if prehash
                else SignatureAlgorithm.PURE_ED_DSA
            ),
            _key_id=bytes(self._keynum_sk.key_id),
            _signature=sig_sig,
            _trusted_comment=trusted_comment,
            _global_signature=pk.sign(sig_sig + trusted_comment.encode()),
        )

    def sign_file(
        self,
        path: PathLike,
        *,
        prehash: bool = False,
        untrusted_comment: str | None = None,
        trusted_comment: str | None = None,
        drop_signature: bool = False,
    ) -> Signature:
        if trusted_comment is None:
            suffix = "\thashed" if prehash else ""
            trusted_comment = f"timestamp:{int(time.time())}\tfile:{os.path.basename(os.fspath(path))}{suffix}"
        with open(path, "rb") as f:
            sig = self.sign(
                f,
                prehash=prehash,
                untrusted_comment=untrusted_comment,
                trusted_comment=trusted_comment,
            )
        if drop_signature:
            with open(f"{os.fspath(path)}.{SIG_EXT}", "wb") as f1:
                f1.write(bytes(sig))
                f1.write(b"\n")
        return sig

    def _calc_checksum(self, keynum_sk: KeynumSK | None = None) -> bytes:
        if keynum_sk is None:
            keynum_sk = self._keynum_sk
        hasher = hashlib.blake2b(digest_size=CHECKSUM_LEN)
        hasher.update(self._signature_algorithm.value)
        hasher.update(keynum_sk.key_id)
        hasher.update(keynum_sk.secret_key)
        hasher.update(keynum_sk.public_key)
        return hasher.digest()

    def _update_checksum(self) -> None:
        self._keynum_sk.checksum[:] = self._calc_checksum()

    def remove_password(self, password: str) -> None:
        self.decrypt(password)
        self._kdf_algorithm = KDFAlgorithm.NONE
        self._kdf_salt = bytes(SALT_LEN)
        self._kdf_opslimit = 0
        self._kdf_memlimit = 0

    def to_base64(self) -> bytes:
        self._check_is_wiped()
        return base64.standard_b64encode(
            self._signature_algorithm.value
            + self._kdf_algorithm.value
            + self._cksum_algorithm.value
            + self._kdf_salt
            + self._kdf_opslimit.to_bytes(KDF_PARAM_LEN, BYTE_ORDER)
            + self._kdf_memlimit.to_bytes(KDF_PARAM_LEN, BYTE_ORDER)
            + bytes(self._keynum_sk)
        )

    def __bytes__(self) -> bytes:
        self._check_is_wiped()
        comment = self._untrusted_comment
        if comment is None:
            comment = f"{UNTRUSTED_COMMENT_PREFIX}minisign {'encrypted ' if self.is_encrypted() else ''}secret key"
        else:
            comment = f"{UNTRUSTED_COMMENT_PREFIX}{comment}"
        return b"\n".join((comment.encode(), self.to_base64()))
