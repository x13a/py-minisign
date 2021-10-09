"""
https://jedisct1.github.io/minisign
"""

from __future__ import annotations

import base64
import enum
import hashlib
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import (
    BinaryIO,
    Optional,
    Union,
)

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

KEYNUM_PK_LEN = KEY_ID_LEN + KEY_LEN
KEYNUM_SK_LEN = KEY_ID_LEN + (KEY_LEN << 1) + CHECKSUM_LEN

OPSLIMIT = 1_048_576
MEMLIMIT = 33_554_432
MEMLIMIT_MAX = 1_073_741_824
N_LOG2_MAX = 20

SIG_EXT = 'minisig'
BYTE_ORDER = 'little'
DEFAULT_SK_PATH = '~/.minisign/minisign.key'

UNTRUSTED_COMMENT_PREFIX = 'untrusted comment: '
TRUSTED_COMMENT_PREFIX = 'trusted comment: '
TRUSTED_COMMENT_PREFIX_LEN = len(TRUSTED_COMMENT_PREFIX)


@enum.unique
class SignatureAlgorithm(bytes, enum.Enum):
    PURE_ED_DSA = bytes([0x45, 0x64])
    PREHASHED_ED_DSA = bytes([0x45, 0x44])


@enum.unique
class KDFAlgorithm(bytes, enum.Enum):
    SCRYPT = bytes([0x53, 0x63])


@enum.unique
class CksumAlgorithm(bytes, enum.Enum):
    BLAKE2b = bytes([0x42, 0x32])


@dataclass(frozen=True)
class Signature:
    _untrusted_comment: str
    _signature_algorithm: SignatureAlgorithm
    _key_id: bytes
    _signature: bytes
    _trusted_comment: str
    _global_signature: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> Signature:
        lines = data.splitlines()
        if len(lines) < 4:
            raise ParseError('incomplete encoded signature')
        glob_sig = base64.standard_b64decode(lines[3])
        if len(glob_sig) != SIG_LEN:
            raise ParseError('invalid encoded signature')
        buf = Reader(base64.standard_b64decode(lines[1]))
        return cls(
            _untrusted_comment=lines[0].decode(),
            _signature_algorithm=SignatureAlgorithm(buf.read(ALG_LEN)),
            _key_id=buf.read(KEY_ID_LEN),
            _signature=buf.read(SIG_LEN),
            _trusted_comment=lines[2].decode(),
            _global_signature=glob_sig,
        )

    @classmethod
    def from_file(cls, path: Union[str, os.PathLike]) -> Signature:
        with open(path, 'rb') as f:
            return cls.from_bytes(f.read())

    @property
    def untrusted_comment(self) -> str:
        return self._untrusted_comment

    def set_untrusted_comment(self, value: str):
        check_comment(value)
        self.__dict__['_untrusted_comment'] = value

    @property
    def trusted_comment(self) -> str:
        return self._trusted_comment[TRUSTED_COMMENT_PREFIX_LEN:]

    def __bytes__(self) -> bytes:
        return b'\n'.join((
            self._untrusted_comment.encode(),
            base64.standard_b64encode(
                self._signature_algorithm.value +
                self._key_id +
                self._signature
            ),
            self._trusted_comment.encode(),
            base64.standard_b64encode(self._global_signature),
        ))

    def _is_prehashed(self) -> bool:
        return self._signature_algorithm == SignatureAlgorithm.PREHASHED_ED_DSA


@dataclass(frozen=True)
class KeynumPK:
    key_id: bytes
    public_key: bytes

    @classmethod
    def from_bytes(cls, data: Union[bytes, Reader]) -> KeynumPK:
        assert len(data) == KEYNUM_PK_LEN
        if isinstance(data, bytes):
            data = Reader(data)
        return cls(
            key_id=data.read(KEY_ID_LEN),
            public_key=data.read(KEY_LEN),
        )

    def __bytes__(self) -> bytes:
        return self.key_id + self.public_key


@dataclass(frozen=True)
class PublicKey:
    _untrusted_comment: Optional[str]
    _signature_algorithm: SignatureAlgorithm
    _keynum_pk: KeynumPK

    @classmethod
    def from_base64(cls, s: Union[bytes, str]) -> PublicKey:
        buf = Reader(base64.standard_b64decode(s))
        return cls(
            _untrusted_comment=None,
            _signature_algorithm=SignatureAlgorithm(buf.read(ALG_LEN)),
            _keynum_pk=KeynumPK.from_bytes(buf),
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> PublicKey:
        lines = data.splitlines()
        if len(lines) < 2:
            raise ParseError('incomplete encoded public key')
        pk = cls.from_base64(lines[1])
        pk.set_untrusted_comment(lines[0].decode())
        return pk

    @classmethod
    def from_file(cls, path: Union[str, os.PathLike]) -> PublicKey:
        with open(path, 'rb') as f:
            return cls.from_bytes(f.read())

    @classmethod
    def from_secret_key(cls, secret_key: SecretKey) -> PublicKey:
        key_id = bytes(secret_key._keynum_sk.key_id)
        return cls(
            _untrusted_comment=f'{UNTRUSTED_COMMENT_PREFIX}'
                               f'minisign public key '
                               f'{key_id.hex().upper()}',
            _signature_algorithm=secret_key._signature_algorithm,
            _keynum_pk=KeynumPK(
                key_id=key_id,
                public_key=bytes(secret_key._keynum_sk.public_key),
            ),
        )

    @property
    def untrusted_comment(self) -> Optional[str]:
        return self._untrusted_comment

    def set_untrusted_comment(self, value: Optional[str]):
        check_comment(value)
        self.__dict__['_untrusted_comment'] = value

    def verify(self, data: Union[bytes, BinaryIO], signature: Signature):
        if self._keynum_pk.key_id != signature._key_id:
            raise VerifyError('incompatible key identifiers')
        if not signature._trusted_comment.startswith(TRUSTED_COMMENT_PREFIX):
            raise VerifyError('unexpected format for the trusted comment')
        pk = ed25519.Ed25519PublicKey.from_public_bytes(
            self._keynum_pk.public_key)
        try:
            pk.verify(
                signature._signature,
                read_data(data, signature._is_prehashed()),
            )
            pk.verify(
                signature._global_signature,
                signature._signature + signature.trusted_comment.encode(),
            )
        except InvalidSignature as err:
            raise VerifyError(err)

    def verify_file(
        self,
        path: Union[str, os.PathLike],
        signature: Optional[Signature] = None,
    ):
        if signature is None:
            signature = Signature.from_file(f'{path}.{SIG_EXT}')
        with open(path, 'rb') as f:
            self.verify(f, signature)

    def to_base64(self) -> bytes:
        return base64.standard_b64encode(
            self._signature_algorithm.value +
            bytes(self._keynum_pk)
        )

    def __bytes__(self) -> bytes:
        return b'\n'.join((
            (
                f'{UNTRUSTED_COMMENT_PREFIX}minisign public key '
                f'{self._keynum_pk.key_id.hex().upper()}'
                if self._untrusted_comment is None else
                self._untrusted_comment
            ).encode(),
            self.to_base64(),
        ))


@dataclass(frozen=True, repr=False)
class KeynumSK:
    key_id: bytearray
    secret_key: bytearray
    public_key: bytearray
    checksum: bytearray

    @classmethod
    def from_bytes(cls, data: Union[bytes, Reader]) -> KeynumSK:
        assert len(data) == KEYNUM_SK_LEN
        if isinstance(data, bytes):
            data = Reader(data)
        return cls(
            key_id=bytearray(data.read(KEY_ID_LEN)),
            secret_key=bytearray(data.read(KEY_LEN)),
            public_key=bytearray(data.read(KEY_LEN)),
            checksum=bytearray(data.read(CHECKSUM_LEN)),
        )

    def xor(self, key: bytes):
        assert len(key) == KEYNUM_SK_LEN
        buf = Reader(key)
        for (l, size) in (
            (self.key_id, KEY_ID_LEN),
            (self.secret_key, KEY_LEN),
            (self.public_key, KEY_LEN),
            (self.checksum, CHECKSUM_LEN),
        ):
            for idx, (v1, v2) in enumerate(zip(l[:], buf.read(size))):
                l[idx] = v1 ^ v2

    def __bytes__(self) -> bytes:
        return (
            bytes(self.key_id) +
            bytes(self.secret_key) +
            bytes(self.public_key) +
            bytes(self.checksum)
        )


@dataclass(frozen=True, repr=False)
class SecretKey:
    _untrusted_comment: str
    _signature_algorithm: SignatureAlgorithm
    _kdf_algorithm: KDFAlgorithm
    _cksum_algorithm: CksumAlgorithm
    _kdf_salt: bytes
    _kdf_opslimit: int
    _kdf_memlimit: int
    _keynum_sk: KeynumSK

    @classmethod
    def from_bytes(cls, data: bytes) -> SecretKey:
        lines = data.splitlines()
        if len(lines) < 2:
            raise ParseError('incomplete encoded secret key')
        buf = Reader(base64.standard_b64decode(lines[1]))
        return cls(
            _untrusted_comment=lines[0].decode(),
            _signature_algorithm=SignatureAlgorithm(buf.read(ALG_LEN)),
            _kdf_algorithm=KDFAlgorithm(buf.read(ALG_LEN)),
            _cksum_algorithm=CksumAlgorithm(buf.read(ALG_LEN)),
            _kdf_salt=buf.read(SALT_LEN),
            _kdf_opslimit=int.from_bytes(buf.read(KDF_PARAM_LEN), BYTE_ORDER),
            _kdf_memlimit=int.from_bytes(buf.read(KDF_PARAM_LEN), BYTE_ORDER),
            _keynum_sk=KeynumSK.from_bytes(buf),
        )

    @classmethod
    def from_file(
        cls,
        path: Optional[Union[str, os.PathLike]] = None,
    ) -> SecretKey:
        if path is None:
            path = Path(DEFAULT_SK_PATH).expanduser().resolve(strict=True)
        with open(path, 'rb') as f:
            return cls.from_bytes(f.read())

    @property
    def untrusted_comment(self) -> str:
        return self._untrusted_comment

    def set_untrusted_comment(self, value: str):
        check_comment(value)
        self.__dict__['_untrusted_comment'] = value

    def get_public_key(self) -> PublicKey:
        return PublicKey.from_secret_key(self)

    def decrypt(self, password: str):
        self._crypt(password)
        if self._calc_checksum() != bytes(self._keynum_sk.checksum):
            raise Error('wrong password for that key')

    def encrypt(self, password: str):
        self._crypt(password)

    def _crypt(self, password: str):
        if self._kdf_memlimit > MEMLIMIT_MAX:
            raise Error('memlimit too high')
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
            p = min(0x3fffffff, (opslimit // 4) // (1 << n_log2)) // r
        if n_log2 > N_LOG2_MAX:
            raise Error('n_log2 too high')
        self._keynum_sk.xor(scrypt.Scrypt(
            salt=self._kdf_salt,
            length=KEYNUM_SK_LEN,
            n=1 << n_log2,
            r=r,
            p=p,
        ).derive(password.encode()))

    def sign(
        self,
        data: Union[bytes, BinaryIO],
        *,
        prehash: bool = True,
        untrusted_comment: Optional[str] = None,
        trusted_comment: Optional[str] = None,
    ) -> Signature:
        untrusted_comment = (
            f'{UNTRUSTED_COMMENT_PREFIX}minisign signature '
            f'{self._keynum_sk.key_id.hex().upper()}'
            if untrusted_comment is None else
            untrusted_comment
        )
        check_comment(untrusted_comment)
        trusted_comment = (
            f'timestamp:{int(time.time())}'
            if trusted_comment is None else
            trusted_comment
        )
        check_comment(trusted_comment)
        pk = ed25519.Ed25519PrivateKey.from_private_bytes(
            self._keynum_sk.secret_key)
        sig_sig = pk.sign(read_data(data, prehash))
        return Signature(
            _untrusted_comment=untrusted_comment,
            _signature_algorithm=(
                SignatureAlgorithm.PREHASHED_ED_DSA
                if prehash else
                SignatureAlgorithm.PURE_ED_DSA
            ),
            _key_id=self._keynum_sk.key_id,
            _signature=sig_sig,
            _trusted_comment=f'{TRUSTED_COMMENT_PREFIX}{trusted_comment}',
            _global_signature=pk.sign(sig_sig + trusted_comment.encode()),
        )

    def sign_file(
        self,
        path: Union[str, os.PathLike],
        *,
        prehash: bool = False,
        untrusted_comment: Optional[str] = None,
        trusted_comment: Optional[str] = None,
        drop_signature: bool = False,
    ) -> Signature:
        with open(path, 'rb') as f:
            sig = self.sign(
                f,
                prehash=prehash,
                untrusted_comment=untrusted_comment,
                trusted_comment=trusted_comment,
            )
        if drop_signature:
            with open(f'{path}.{SIG_EXT}', 'wb') as f1:
                f1.write(bytes(sig))
                f1.write(b'\n')
        return sig

    def _calc_checksum(self) -> bytes:
        hasher = hashlib.blake2b(digest_size=CHECKSUM_LEN)
        hasher.update(self._signature_algorithm.value)
        hasher.update(self._keynum_sk.key_id)
        hasher.update(self._keynum_sk.secret_key)
        hasher.update(self._keynum_sk.public_key)
        return hasher.digest()

    def _update_checksum(self):
        self._keynum_sk.checksum[0:] = self._calc_checksum()

    def __bytes__(self) -> bytes:
        return b'\n'.join((
            self._untrusted_comment.encode(),
            base64.standard_b64encode(
                self._signature_algorithm.value +
                self._kdf_algorithm.value +
                self._cksum_algorithm.value +
                self._kdf_salt +
                self._kdf_opslimit.to_bytes(KDF_PARAM_LEN, BYTE_ORDER) +
                self._kdf_memlimit.to_bytes(KDF_PARAM_LEN, BYTE_ORDER) +
                bytes(self._keynum_sk)
            ),
        ))


@dataclass(frozen=True, repr=False)
class KeyPair:
    secret_key: SecretKey
    public_key: PublicKey

    @classmethod
    def generate(cls) -> KeyPair:
        private_key = ed25519.Ed25519PrivateKey.generate()
        key_id = secrets.token_bytes(KEY_ID_LEN)
        sk = SecretKey(
            _untrusted_comment=f'{UNTRUSTED_COMMENT_PREFIX}'
                               f'minisign secret key '
                               f'{key_id.hex().upper()}',
            _signature_algorithm=SignatureAlgorithm.PURE_ED_DSA,
            _kdf_algorithm=KDFAlgorithm.SCRYPT,
            _cksum_algorithm=CksumAlgorithm.BLAKE2b,
            _kdf_salt=secrets.token_bytes(SALT_LEN),
            _kdf_opslimit=OPSLIMIT,
            _kdf_memlimit=MEMLIMIT,
            _keynum_sk=KeynumSK(
                key_id=bytearray(key_id),
                secret_key=bytearray(private_key.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption(),
                )),
                public_key=bytearray(private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )),
                checksum=bytearray(CHECKSUM_LEN),
            ),
        )
        sk._update_checksum()
        return cls(secret_key=sk, public_key=PublicKey.from_secret_key(sk))
