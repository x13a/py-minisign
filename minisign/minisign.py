"""
https://jedisct1.github.io/minisign
"""

from __future__ import annotations

import base64
import binascii
import enum
import hashlib
import hmac
import os
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.kdf import scrypt

from .exceptions import (
    Error,
    ParseError,
    VerifyError,
)
from .helpers import (
    BytesReaderProto,
    Reader,
    check_comment,
    read_data,
)

ALG_LEN = 2
KDF_PARAM_LEN = 8
KEY_ID_LEN = 8
KEY_LEN = 32
SALT_LEN = 32
CHECKSUM_LEN = 32
SIG_LEN = 64
SIG_0_LEN = ALG_LEN + KEY_ID_LEN + SIG_LEN

KEYNUM_PK_LEN = KEY_ID_LEN + KEY_LEN
KEYNUM_SK_LEN = KEY_ID_LEN + (KEY_LEN << 1) + CHECKSUM_LEN
PUBLIC_KEY_LEN = ALG_LEN + KEYNUM_PK_LEN
SECRET_KEY_LEN = (ALG_LEN * 3) + SALT_LEN + (KDF_PARAM_LEN * 2) + KEYNUM_SK_LEN

OPSLIMIT = 1_048_576
MEMLIMIT = 33_554_432
MEMLIMIT_MAX = 1_073_741_824
N_LOG2_MAX = 20

SIG_EXT = "minisig"
BYTE_ORDER: Literal["little", "big"] = "little"
DEFAULT_SK_PATH = "~/.minisign/minisign.key"

UNTRUSTED_COMMENT_PREFIX = "untrusted comment: "
UNTRUSTED_COMMENT_PREFIX_LEN = len(UNTRUSTED_COMMENT_PREFIX)
TRUSTED_COMMENT_PREFIX = "trusted comment: "
TRUSTED_COMMENT_PREFIX_LEN = len(TRUSTED_COMMENT_PREFIX)
DEFAULT_SIGNATURE_UNTRUSTED_COMMENT = "signature from minisign secret key"
TRUSTED_COMMENT_MAX_LEN = 8192 - TRUSTED_COMMENT_PREFIX_LEN


@enum.unique
class SignatureAlgorithm(bytes, enum.Enum):
    PURE_ED_DSA = bytes([0x45, 0x64])
    PREHASHED_ED_DSA = bytes([0x45, 0x44])


@enum.unique
class KDFAlgorithm(bytes, enum.Enum):
    NONE = bytes([0x00, 0x00])
    SCRYPT = bytes([0x53, 0x63])


@enum.unique
class CksumAlgorithm(bytes, enum.Enum):
    BLAKE2b = bytes([0x42, 0x32])


def _decode_base64(data: str | bytes, expected_len: int) -> bytes:
    try:
        decoded = base64.b64decode(data, validate=True)
    except (ValueError, binascii.Error) as err:
        raise ParseError("invalid base64 encoding") from err
    if len(decoded) != expected_len:
        raise ParseError("invalid encoded length")
    return decoded


def _decode_comment(data: bytes, prefix: str) -> str:
    try:
        comment = data.decode()
    except UnicodeDecodeError as err:
        raise ParseError("invalid comment encoding") from err
    if not comment.startswith(prefix):
        raise ParseError("invalid comment prefix")
    return comment[len(prefix) :]


def _split_lines(data: bytes, expected_len: int) -> list[bytes]:
    lines = data.splitlines()
    if len(lines) != expected_len:
        raise ParseError("invalid number of lines")
    return lines


@dataclass(frozen=True)
class Signature:
    _untrusted_comment: str = field(compare=False)
    _signature_algorithm: SignatureAlgorithm
    _key_id: bytes
    _signature: bytes
    _trusted_comment: str
    _global_signature: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> Signature:
        lines = _split_lines(data, 4)
        glob_sig = _decode_base64(lines[3], SIG_LEN)
        buf = Reader(_decode_base64(lines[1], SIG_0_LEN))
        try:
            signature_algorithm = SignatureAlgorithm(buf.read(ALG_LEN))
        except ValueError as err:
            raise ParseError("unsupported signature algorithm") from err
        return cls(
            _untrusted_comment=_decode_comment(lines[0], UNTRUSTED_COMMENT_PREFIX),
            _signature_algorithm=signature_algorithm,
            _key_id=buf.read(KEY_ID_LEN),
            _signature=buf.read(SIG_LEN),
            _trusted_comment=_decode_comment(lines[2], TRUSTED_COMMENT_PREFIX),
            _global_signature=glob_sig,
        )

    @classmethod
    def from_file(cls, path: str | os.PathLike[str]) -> Signature:
        with open(path, "rb") as f:
            return cls.from_bytes(f.read())

    @property
    def untrusted_comment(self) -> str:
        return self._untrusted_comment

    def set_untrusted_comment(self, value: str) -> None:
        check_comment(value)
        self.__dict__["_untrusted_comment"] = value

    @property
    def trusted_comment(self) -> str:
        return self._trusted_comment

    def __bytes__(self) -> bytes:
        return b"\n".join(
            (
                f"{UNTRUSTED_COMMENT_PREFIX}{self._untrusted_comment}".encode(),
                base64.standard_b64encode(
                    self._signature_algorithm.value + self._key_id + self._signature
                ),
                f"{TRUSTED_COMMENT_PREFIX}{self._trusted_comment}".encode(),
                base64.standard_b64encode(self._global_signature),
            )
        )

    def is_prehashed(self) -> bool:
        return self._signature_algorithm == SignatureAlgorithm.PREHASHED_ED_DSA


@dataclass(frozen=True)
class KeynumPK:
    key_id: bytes
    public_key: bytes

    @classmethod
    def from_bytes(cls, data: bytes | Reader) -> KeynumPK:
        assert len(data) == KEYNUM_PK_LEN
        if isinstance(data, bytes):
            data = Reader(data)
        return cls(key_id=data.read(KEY_ID_LEN), public_key=data.read(KEY_LEN))

    def __bytes__(self) -> bytes:
        return self.key_id + self.public_key


@dataclass(frozen=True)
class PublicKey:
    _untrusted_comment: str | None = field(compare=False)
    _signature_algorithm: SignatureAlgorithm
    _keynum_pk: KeynumPK

    @classmethod
    def from_base64(cls, s: str | bytes) -> PublicKey:
        buf = Reader(_decode_base64(s, PUBLIC_KEY_LEN))
        try:
            signature_algorithm = SignatureAlgorithm(buf.read(ALG_LEN))
        except ValueError as err:
            raise ParseError("unsupported signature algorithm") from err
        if signature_algorithm == SignatureAlgorithm.PREHASHED_ED_DSA:
            raise ParseError("invalid signature algorithm")
        return cls(
            _untrusted_comment=None,
            _signature_algorithm=signature_algorithm,
            _keynum_pk=KeynumPK.from_bytes(buf),
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> PublicKey:
        lines = _split_lines(data, 2)
        pk = cls.from_base64(lines[1])
        pk.set_untrusted_comment(_decode_comment(lines[0], UNTRUSTED_COMMENT_PREFIX))
        return pk

    @classmethod
    def from_file(cls, path: str | os.PathLike[str]) -> PublicKey:
        with open(path, "rb") as f:
            return cls.from_bytes(f.read())

    @classmethod
    def from_secret_key(cls, secret_key: SecretKey) -> PublicKey:
        secret_key._check_is_wiped()
        key_id = bytes(secret_key._keynum_sk.key_id)
        return cls(
            _untrusted_comment=None,
            _signature_algorithm=secret_key._signature_algorithm,
            _keynum_pk=KeynumPK(
                key_id=key_id,
                public_key=bytes(secret_key._keynum_sk.public_key),
            ),
        )

    @property
    def untrusted_comment(self) -> str | None:
        return self._untrusted_comment

    def set_untrusted_comment(self, value: str | None) -> None:
        if value is not None:
            check_comment(value)
        self.__dict__["_untrusted_comment"] = value

    def verify(self, data: bytes | BytesReaderProto, signature: Signature) -> None:
        if self._keynum_pk.key_id != signature._key_id:
            raise VerifyError("incompatible key identifiers")
        pk = ed25519.Ed25519PublicKey.from_public_bytes(self._keynum_pk.public_key)
        try:
            pk.verify(
                signature._signature,
                read_data(data, signature.is_prehashed()),
            )
            pk.verify(
                signature._global_signature,
                signature._signature + signature.trusted_comment.encode(),
            )
        except InvalidSignature as err:
            raise VerifyError(err)

    def verify_file(
        self,
        path: str | os.PathLike[str],
        signature: Signature | None = None,
    ) -> None:
        if signature is None:
            signature = Signature.from_file(f"{os.fspath(path)}.{SIG_EXT}")
        with open(path, "rb") as f:
            self.verify(f, signature)

    def to_base64(self) -> bytes:
        return base64.standard_b64encode(
            self._signature_algorithm.value + bytes(self._keynum_pk)
        )

    def __bytes__(self) -> bytes:
        comment = self._untrusted_comment
        if comment is None:
            comment = f"{UNTRUSTED_COMMENT_PREFIX}minisign public key {self._keynum_pk.key_id.hex().upper()}"
        else:
            comment = f"{UNTRUSTED_COMMENT_PREFIX}{comment}"
        return b"\n".join((comment.encode(), self.to_base64()))


@dataclass(frozen=True, repr=False)
class KeynumSK:
    key_id: bytearray
    secret_key: bytearray
    public_key: bytearray
    checksum: bytearray

    @classmethod
    def from_bytes(cls, data: bytes | Reader) -> KeynumSK:
        assert len(data) == KEYNUM_SK_LEN
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
            value[0:] = b"\0" * len(value)

    def xor(self, key: bytes) -> None:
        assert len(key) == KEYNUM_SK_LEN
        buf = Reader(key)
        for l, size in (
            (self.key_id, KEY_ID_LEN),
            (self.secret_key, KEY_LEN),
            (self.public_key, KEY_LEN),
            (self.checksum, CHECKSUM_LEN),
        ):
            for idx, (v1, v2) in enumerate(zip(l[:], buf.read(size))):
                l[idx] = v1 ^ v2

    def __bytes__(self) -> bytes:
        return (
            bytes(self.key_id)
            + bytes(self.secret_key)
            + bytes(self.public_key)
            + bytes(self.checksum)
        )


@dataclass(frozen=True, repr=False)
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

    @classmethod
    def from_base64(cls, s: str | bytes) -> SecretKey:
        buf = Reader(_decode_base64(s, SECRET_KEY_LEN))
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
    def from_bytes(cls, data: bytes) -> SecretKey:
        lines = _split_lines(data, 2)
        v = cls.from_base64(lines[1])
        v.set_untrusted_comment(_decode_comment(lines[0], UNTRUSTED_COMMENT_PREFIX))
        return v

    @classmethod
    def from_file(
        cls,
        path: str | os.PathLike[str] | None = None,
    ) -> SecretKey:
        if path is None:
            path = Path(DEFAULT_SK_PATH).expanduser().resolve(strict=True)
        with open(path, "rb") as f:
            return cls.from_bytes(f.read())

    @property
    def untrusted_comment(self) -> str | None:
        return self._untrusted_comment

    def set_untrusted_comment(self, value: str | None) -> None:
        if value is not None:
            check_comment(value)
        self.__dict__["_untrusted_comment"] = value

    def get_public_key(self) -> PublicKey:
        self._check_is_wiped()
        return PublicKey.from_secret_key(self)

    def is_wiped(self) -> bool:
        return self._is_wiped

    def wipe(self) -> None:
        self._keynum_sk.wipe()
        self.__dict__["_is_wiped"] = True

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
        encrypted_keynum = bytes(self._keynum_sk)
        self._crypt(password)
        if not hmac.compare_digest(
            self._calc_checksum(), bytes(self._keynum_sk.checksum)
        ):
            self.__dict__["_keynum_sk"] = KeynumSK.from_bytes(encrypted_keynum)
            raise Error("wrong password for that key")

    def encrypt(self, password: str) -> None:
        self._check_is_wiped()
        if self.is_encrypted():
            raise Error("secret key is already encrypted")
        if self._kdf_algorithm == KDFAlgorithm.NONE:
            self.__dict__.update(
                _kdf_algorithm=KDFAlgorithm.SCRYPT,
                _kdf_salt=secrets.token_bytes(SALT_LEN),
                _kdf_opslimit=OPSLIMIT,
                _kdf_memlimit=MEMLIMIT,
            )
        elif self._kdf_algorithm != KDFAlgorithm.SCRYPT:
            raise Error("unsupported KDF algorithm")
        self._crypt(password)

    def _crypt(self, password: str) -> None:
        if self._kdf_memlimit > MEMLIMIT_MAX:
            raise Error("memlimit too high")
        opslimit = max(32768, self._kdf_opslimit)
        n_log2 = 1
        r = 8
        p = 0
        if opslimit < self._kdf_memlimit // 32:
            maxn = opslimit // (r * 4)
            p = 1
        else:
            maxn = self._kdf_memlimit // (r * 128)
        while n_log2 < 63:
            if 1 << n_log2 > maxn // 2:
                break
            n_log2 += 1
        if not p:
            p = min(0x3FFFFFFF, (opslimit // 4) // (1 << n_log2)) // r
        if n_log2 > N_LOG2_MAX:
            raise Error("n_log2 too high")
        self._keynum_sk.xor(
            scrypt.Scrypt(
                salt=self._kdf_salt,
                length=KEYNUM_SK_LEN,
                n=1 << n_log2,
                r=r,
                p=p,
            ).derive(password.encode())
        )

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
        path: str | os.PathLike[str],
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

    def _calc_checksum(self) -> bytes:
        hasher = hashlib.blake2b(digest_size=CHECKSUM_LEN)
        hasher.update(self._signature_algorithm.value)
        hasher.update(self._keynum_sk.key_id)
        hasher.update(self._keynum_sk.secret_key)
        hasher.update(self._keynum_sk.public_key)
        return hasher.digest()

    def _update_checksum(self) -> None:
        self._keynum_sk.checksum[0:] = self._calc_checksum()

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


@dataclass(frozen=True, repr=False)
class KeyPair:
    secret_key: SecretKey
    public_key: PublicKey

    @classmethod
    def generate(
        cls,
        *,
        kdf_algorithm: KDFAlgorithm = KDFAlgorithm.NONE,
    ) -> KeyPair:
        is_script = kdf_algorithm == KDFAlgorithm.SCRYPT
        private_key = ed25519.Ed25519PrivateKey.generate()
        key_id = secrets.token_bytes(KEY_ID_LEN)
        sk = SecretKey(
            _untrusted_comment=None,
            _signature_algorithm=SignatureAlgorithm.PURE_ED_DSA,
            _kdf_algorithm=kdf_algorithm,
            _cksum_algorithm=CksumAlgorithm.BLAKE2b,
            _kdf_salt=(secrets.token_bytes(SALT_LEN) if is_script else bytes(SALT_LEN)),
            _kdf_opslimit=OPSLIMIT if is_script else 0,
            _kdf_memlimit=MEMLIMIT if is_script else 0,
            _keynum_sk=KeynumSK(
                key_id=bytearray(key_id),
                secret_key=bytearray(
                    private_key.private_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PrivateFormat.Raw,
                        encryption_algorithm=serialization.NoEncryption(),
                    )
                ),
                public_key=bytearray(
                    private_key.public_key().public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw,
                    )
                ),
                checksum=bytearray(CHECKSUM_LEN),
            ),
        )
        sk._update_checksum()
        return cls(secret_key=sk, public_key=PublicKey.from_secret_key(sk))
