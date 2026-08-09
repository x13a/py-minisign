import base64
import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519
from typing_extensions import Self

from .algo import SignatureAlgorithm
from .const import (
    ALG_LEN,
    KEY_ID_LEN,
    KEY_LEN,
    KEYNUM_PK_LEN,
    PUBLIC_KEY_LEN,
    SIG_EXT,
    UNTRUSTED_COMMENT_PREFIX,
    PathLike,
)
from .exceptions import ParseError, VerifyError
from .helpers import (
    BytesReaderProto,
    Reader,
    check_comment,
    decode_base64,
    decode_comment,
    read_data,
    split_lines,
)
from .signature import Signature

if TYPE_CHECKING:
    from .secret_key import SecretKey


@dataclass(slots=True, kw_only=True, frozen=True)
class KeynumPK:
    key_id: bytes
    public_key: bytes

    @classmethod
    def from_bytes(cls, data: bytes | Reader) -> Self:
        if len(data) != KEYNUM_PK_LEN:
            raise ParseError("invalid public key length")
        if isinstance(data, bytes):
            data = Reader(data)
        return cls(key_id=data.read(KEY_ID_LEN), public_key=data.read(KEY_LEN))

    def __bytes__(self) -> bytes:
        return self.key_id + self.public_key


@dataclass(slots=True, kw_only=True, unsafe_hash=True)
class PublicKey:
    _untrusted_comment: str | None = field(compare=False)
    _signature_algorithm: SignatureAlgorithm
    _keynum_pk: KeynumPK

    @classmethod
    def from_base64(cls, s: str | bytes) -> Self:
        buf = Reader(decode_base64(s, PUBLIC_KEY_LEN))
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
    def from_bytes(cls, data: bytes) -> Self:
        lines = split_lines(data, 2)
        pk = cls.from_base64(lines[1])
        pk.untrusted_comment = decode_comment(lines[0], UNTRUSTED_COMMENT_PREFIX)
        return pk

    @classmethod
    def from_file(cls, path: PathLike) -> Self:
        with open(path, "rb") as f:
            return cls.from_bytes(f.read())

    @classmethod
    def from_secret_key(cls, secret_key: "SecretKey") -> Self:
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

    @untrusted_comment.setter
    def untrusted_comment(self, value: str | None) -> None:
        if value is not None:
            check_comment(value)
        self._untrusted_comment = value

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
            raise VerifyError("signature verification failed") from err

    def verify_file(
        self,
        path: PathLike,
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
