"""
https://jedisct1.github.io/minisign
"""

import secrets
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from typing_extensions import Self

from .algo import (
    CksumAlgorithm,
    KDFAlgorithm,
    SignatureAlgorithm,
)
from .const import (
    CHECKSUM_LEN,
    KEY_ID_LEN,
    SALT_LEN,
)
from .public_key import PublicKey
from .secret_key import KeynumSK, SecretKey


@dataclass(frozen=True, slots=True, repr=False)
class KeyPair:
    secret_key: SecretKey
    public_key: PublicKey

    @classmethod
    def generate(cls) -> Self:
        private_key = ed25519.Ed25519PrivateKey.generate()
        key_id = secrets.token_bytes(KEY_ID_LEN)
        sk = SecretKey(
            _untrusted_comment=None,
            _signature_algorithm=SignatureAlgorithm.PURE_ED_DSA,
            _kdf_algorithm=KDFAlgorithm.NONE,
            _cksum_algorithm=CksumAlgorithm.BLAKE2b,
            _kdf_salt=bytes(SALT_LEN),
            _kdf_opslimit=0,
            _kdf_memlimit=0,
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
