import base64
from dataclasses import dataclass, field

from typing_extensions import Self

from .algo import SignatureAlgorithm
from .const import (
    ALG_LEN,
    KEY_ID_LEN,
    LINE_1_LEN,
    SIG_LEN,
    TRUSTED_COMMENT_PREFIX,
    UNTRUSTED_COMMENT_PREFIX,
    PathLike,
)
from .exceptions import ParseError
from .helpers import (
    Reader,
    check_comment,
    decode_base64,
    decode_comment,
    split_lines,
)


@dataclass(slots=True, kw_only=True, unsafe_hash=True)
class Signature:
    _untrusted_comment: str = field(compare=False)
    _signature_algorithm: SignatureAlgorithm
    _key_id: bytes
    _signature: bytes
    _trusted_comment: str
    _global_signature: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        lines = split_lines(data, 4)
        glob_sig = decode_base64(lines[3], SIG_LEN)
        buf = Reader(decode_base64(lines[1], LINE_1_LEN))
        try:
            signature_algorithm = SignatureAlgorithm(buf.read(ALG_LEN))
        except ValueError as err:
            raise ParseError("unsupported signature algorithm") from err
        return cls(
            _untrusted_comment=decode_comment(lines[0], UNTRUSTED_COMMENT_PREFIX),
            _signature_algorithm=signature_algorithm,
            _key_id=buf.read(KEY_ID_LEN),
            _signature=buf.read(SIG_LEN),
            _trusted_comment=decode_comment(lines[2], TRUSTED_COMMENT_PREFIX),
            _global_signature=glob_sig,
        )

    @classmethod
    def from_file(cls, path: PathLike) -> Self:
        with open(path, "rb") as f:
            return cls.from_bytes(f.read())

    @property
    def untrusted_comment(self) -> str:
        return self._untrusted_comment

    @untrusted_comment.setter
    def untrusted_comment(self, value: str) -> None:
        check_comment(value)
        self._untrusted_comment = value

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
