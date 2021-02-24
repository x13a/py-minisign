"""
https://jedisct1.github.io/minisign
"""

from __future__ import annotations

import base64
import enum
import hashlib
import os
import io
import secrets
import time
from dataclasses import dataclass
from typing import (
    BinaryIO,
    Optional,
    Union,
)

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.kdf import scrypt

from .helpers import (
    Reader,
    get_data,
)

ALG_LEN = 2
KDF_PARAM_LEN = 8
KEY_ID_LEN = 8
KEY_LEN = 32
SALT_LEN = 32
CHECKSUM_LEN = 32
SIG_LEN = 64

KEYNUM_PK_LEN = 40
KEYNUM_SK_LEN = 104

UNTRUSTED_COMMENT_PREFIX = 'untrusted comment: '
TRUSTED_COMMENT_PREFIX = 'trusted comment: '
TRUSTED_COMMENT_PREFIX_LEN = len(TRUSTED_COMMENT_PREFIX)


class Error(ValueError):
    pass


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
            raise Error('incomplete encoded signature')
        glob_sig = base64.standard_b64decode(lines[3])
        if len(glob_sig) != SIG_LEN:
            raise Error('invalid encoded signature')
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

    @property
    def trusted_comment(self) -> str:
        return self._trusted_comment[TRUSTED_COMMENT_PREFIX_LEN:]

    def __bytes__(self) -> bytes:
        buf = io.BytesIO()
        buf.write(self._untrusted_comment.encode() + b'\n')
        buf.write(base64.standard_b64encode(
            self._signature_algorithm.value +
            self._key_id +
            self._signature
        ) + b'\n')
        buf.write(self._trusted_comment.encode() + b'\n')
        buf.write(base64.standard_b64encode(self._global_signature))
        return buf.getvalue()

    def _is_prehashed(self) -> bool:
        return self._signature_algorithm == SignatureAlgorithm.PREHASHED_ED_DSA


@dataclass(frozen=True)
class KeynumPK:
    _key_id: bytes
    _public_key: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> KeynumPK:
        assert len(data) == KEYNUM_PK_LEN
        buf = Reader(data)
        return cls(
            _key_id=buf.read(KEY_ID_LEN),
            _public_key=buf.read(KEY_LEN),
        )


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
            _keynum_pk=KeynumPK.from_bytes(buf.read(KEYNUM_PK_LEN)),
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> PublicKey:
        lines = data.splitlines()
        if len(lines) < 2:
            raise Error('incomplete encoded public key')
        pk = cls.from_base64(lines[1])
        pk.__dict__['_untrusted_comment'] = lines[0].decode()
        return pk

    @classmethod
    def from_file(cls, path: Union[str, os.PathLike]) -> PublicKey:
        with open(path, 'rb') as f:
            return cls.from_bytes(f.read())

    @property
    def untrusted_comment(self) -> Optional[str]:
        return self._untrusted_comment

    def verify(self, data: Union[bytes, BinaryIO], signature: Signature):
        if self._keynum_pk._key_id != signature._key_id:
            raise Error('incompatible key identifiers')
        if not signature._trusted_comment.startswith(TRUSTED_COMMENT_PREFIX):
            raise Error('unexpected format for the trusted comment')
        data = get_data(data, signature._is_prehashed())
        pk = ed25519.Ed25519PublicKey.from_public_bytes(
            self._keynum_pk._public_key)
        pk.verify(signature._signature, data)
        pk.verify(
            signature._global_signature,
            signature._signature + signature.trusted_comment.encode(),
        )

    def verify_file(self, path: Union[str, os.PathLike], signature: Signature):
        with open(path, 'rb') as f:
            self.verify(f, signature)

    def to_base64(self) -> bytes:
        return base64.standard_b64encode(
            self._signature_algorithm.value +
            self._keynum_pk._key_id +
            self._keynum_pk._public_key
        )

    def __bytes__(self) -> bytes:
        buf = io.BytesIO()
        buf.write((
            f'{UNTRUSTED_COMMENT_PREFIX}minisign public key '
            f'{self._keynum_pk._key_id.hex().upper()}'
            if self._untrusted_comment is None else
            self._untrusted_comment
        ).encode() + b'\n')
        buf.write(self.to_base64())
        return buf.getvalue()


@dataclass(frozen=True, repr=False)
class KeynumSK:
    _key_id: bytearray
    _secret_key: bytearray
    _public_key: bytearray
    _checksum: bytearray

    @classmethod
    def from_bytes(cls, data: bytes) -> KeynumSK:
        buf = Reader(data)
        return cls(
            _key_id=bytearray(buf.read(KEY_ID_LEN)),
            _secret_key=bytearray(buf.read(KEY_LEN)),
            _public_key=bytearray(buf.read(KEY_LEN)),
            _checksum=bytearray(buf.read(CHECKSUM_LEN)),
        )

    def xor(self, key: bytes):
        assert len(key) == KEYNUM_SK_LEN
        buf = Reader(key)
        for idx, (v1, v2) in enumerate(zip(
            self._key_id[:],
            buf.read(KEY_ID_LEN),
        )):
            self._key_id[idx] = v1 ^ v2
        for idx, (v1, v2) in enumerate(zip(
            self._secret_key[:],
            buf.read(KEY_LEN),
        )):
            self._secret_key[idx] = v1 ^ v2
        for idx, (v1, v2) in enumerate(zip(
            self._public_key[:],
            buf.read(KEY_LEN),
        )):
            self._public_key[idx] = v1 ^ v2
        for idx, (v1, v2) in enumerate(zip(
            self._checksum[:],
            buf.read(CHECKSUM_LEN),
        )):
            self._checksum[idx] = v1 ^ v2


@dataclass(frozen=True, repr=False)
class SecretKey:
    _untrusted_comment: str
    _signature_algorithm: SignatureAlgorithm
    _kdf_algorithm: KDFAlgorithm
    _cksum_algorithm: CksumAlgorithm
    _kdf_salt: bytes
    _kdf_opslimit: bytes
    _kdf_memlimit: bytes
    _keynum_sk: KeynumSK

    @classmethod
    def from_bytes(cls, data: bytes) -> SecretKey:
        lines = data.splitlines()
        if len(lines) < 2:
            raise Error('incomplete encoded secret key')
        buf = Reader(base64.standard_b64decode(lines[1]))
        return cls(
            _untrusted_comment=lines[0].decode(),
            _signature_algorithm=SignatureAlgorithm(buf.read(ALG_LEN)),
            _kdf_algorithm=KDFAlgorithm(buf.read(ALG_LEN)),
            _cksum_algorithm=CksumAlgorithm(buf.read(ALG_LEN)),
            _kdf_salt=buf.read(SALT_LEN),
            _kdf_opslimit=buf.read(KDF_PARAM_LEN),
            _kdf_memlimit=buf.read(KDF_PARAM_LEN),
            _keynum_sk=KeynumSK.from_bytes(buf.read(KEYNUM_SK_LEN)),
        )

    @classmethod
    def from_file(cls, path: Union[os.PathLike, str]) -> SecretKey:
        with open(path, 'rb') as f:
            return cls.from_bytes(f.read())

    @property
    def untrusted_comment(self) -> str:
        return self._untrusted_comment

    def decrypt(self, password: str):
        self._crypt(password)
        if self._calc_checksum() != bytes(self._keynum_sk._checksum):
            raise Error('wrong password for that key')

    def encrypt(self, password: str):
        self._keynum_sk._checksum[0:] = self._calc_checksum()
        self._crypt(password)

    def _crypt(self, password: str):
        memlimit = int.from_bytes(self._kdf_memlimit, 'little')
        if memlimit > 1_073_741_824:
            raise Error('memlimit too high')
        opslimit = max(32768, int.from_bytes(self._kdf_opslimit, 'little'))
        n_log2 = 1
        r = 8
        p = 0
        if opslimit < memlimit // 32:
            maxn = opslimit // (r * 4)
            p = 1
        else:
            maxn = memlimit // (r * 128)
        while n_log2 < 63:
            if 1 << n_log2 > maxn // 2:
                break
            n_log2 += 1
        if not p:
            p = min(0x3fffffff, (opslimit // 4) // (1 << n_log2)) // r
        if n_log2 > 20:
            raise Error('n_log2 too high')
        self._keynum_sk.xor(scrypt.Scrypt(
            salt=self._kdf_salt,
            length=104,
            n=1 << n_log2,
            r=r,
            p=p,
        ).derive(password.encode()))

    def sign(
        self,
        data: Union[bytes, BinaryIO],
        prehash: bool = False,
        untrusted_comment: Optional[str] = None,
        trusted_comment: Optional[str] = None,
    ) -> bytes:
        data = get_data(data, prehash)
        untrusted_comment = (
            f'{UNTRUSTED_COMMENT_PREFIX}signature from minisign secret key'
            if untrusted_comment is None else
            untrusted_comment
        )
        trusted_comment = (
            f'timestamp:{int(time.time())}'
            if trusted_comment is None else
            trusted_comment
        )
        if '\n' in untrusted_comment or '\n' in trusted_comment:
            raise Error('comment contains new line char')
        pk = ed25519.Ed25519PrivateKey.from_private_bytes(
            self._keynum_sk._secret_key)
        sig_sig = pk.sign(data)
        return bytes(Signature(
            _untrusted_comment=untrusted_comment,
            _signature_algorithm=(
                SignatureAlgorithm.PREHASHED_ED_DSA
                if prehash else
                SignatureAlgorithm.PURE_ED_DSA
            ),
            _key_id=self._keynum_sk._key_id,
            _signature=sig_sig,
            _trusted_comment=f'{TRUSTED_COMMENT_PREFIX}{trusted_comment}',
            _global_signature=pk.sign(sig_sig + trusted_comment.encode()),
        ))

    def sign_file(
        self,
        path: Union[str, os.PathLike],
        prehash: bool = False,
        untrusted_comment: Optional[str] = None,
        trusted_comment: Optional[str] = None,
    ) -> bytes:
        with open(path, 'rb') as f:
            return self.sign(f, prehash, untrusted_comment, trusted_comment)

    def _calc_checksum(self) -> bytes:
        hasher = hashlib.blake2b(digest_size=CHECKSUM_LEN)
        hasher.update(self._signature_algorithm.value)
        hasher.update(self._keynum_sk._key_id)
        hasher.update(self._keynum_sk._secret_key)
        hasher.update(self._keynum_sk._public_key)
        return hasher.digest()

    def __bytes__(self) -> bytes:
        buf = io.BytesIO()
        buf.write(self._untrusted_comment.encode() + b'\n')
        buf.write(base64.standard_b64encode(
            self._signature_algorithm.value +
            self._kdf_algorithm.value +
            self._cksum_algorithm.value +
            self._kdf_salt +
            self._kdf_opslimit +
            self._kdf_memlimit +
            bytes(self._keynum_sk._key_id) +
            bytes(self._keynum_sk._secret_key) +
            bytes(self._keynum_sk._public_key) +
            bytes(self._keynum_sk._checksum)
        ))
        return buf.getvalue()


@dataclass(frozen=True, repr=False)
class KeyPair:
    secret_key: SecretKey
    public_key: PublicKey

    @classmethod
    def generate(cls) -> KeyPair:
        sk = ed25519.Ed25519PrivateKey.generate()
        key_id = secrets.token_bytes(KEY_ID_LEN)
        public_key = sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return cls(
            secret_key=SecretKey(
                _untrusted_comment=f'{UNTRUSTED_COMMENT_PREFIX}'
                                   f'minisign secret key',
                _signature_algorithm=SignatureAlgorithm.PURE_ED_DSA,
                _kdf_algorithm=KDFAlgorithm.SCRYPT,
                _cksum_algorithm=CksumAlgorithm.BLAKE2b,
                _kdf_salt=secrets.token_bytes(SALT_LEN),
                _kdf_opslimit=(1_048_576).to_bytes(
                    KDF_PARAM_LEN,
                    byteorder='little',
                ),
                _kdf_memlimit=(33_554_432).to_bytes(
                    KDF_PARAM_LEN,
                    byteorder='little',
                ),
                _keynum_sk=KeynumSK(
                    _key_id=bytearray(key_id),
                    _secret_key=bytearray(sk.private_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PrivateFormat.Raw,
                        encryption_algorithm=serialization.NoEncryption(),
                    )),
                    _public_key=bytearray(public_key),
                    _checksum=bytearray(),
                ),
            ),
            public_key=PublicKey(
                _untrusted_comment=None,
                _signature_algorithm=SignatureAlgorithm.PURE_ED_DSA,
                _keynum_pk=KeynumPK(
                    _key_id=key_id,
                    _public_key=public_key,
                ),
            ),
        )
