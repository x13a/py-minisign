import base64
import binascii
import hashlib
from typing import Protocol, runtime_checkable

from .exceptions import ParseError


@runtime_checkable
class BytesReaderProto(Protocol):
    def read(self, size: int = -1, /) -> bytes: ...


class Reader:
    def __init__(self, data: bytes) -> None:
        self._buf = data
        self._pos = 0

    def __len__(self) -> int:
        return len(self._buf) - self._pos

    def read(self, size: int) -> bytes:
        pos = self._pos + size
        data = self._buf[self._pos : pos]
        if len(data) != size:
            raise ParseError("read size mismatch")
        self._pos = pos
        return data


def read_data(data: bytes | BytesReaderProto, prehash: bool) -> bytes:
    if prehash:
        if isinstance(data, BytesReaderProto):
            hasher = hashlib.blake2b()
            while chunk := data.read(1 << 13):
                hasher.update(chunk)
            data = hasher.digest()
        else:
            data = hashlib.blake2b(data).digest()
    elif isinstance(data, BytesReaderProto):
        data = data.read()
    return data


def check_comment(s: str) -> None:
    if any(c in ("\r", "\n") for c in s):
        raise ParseError("comment contains a line break")
    if any(c != "\t" and not " " <= c < "\x7f" for c in s):
        raise ParseError("comment contains an unprintable character")


def decode_base64(data: str | bytes, expected_len: int) -> bytes:
    try:
        decoded = base64.b64decode(data, validate=True)
    except (ValueError, binascii.Error) as err:
        raise ParseError("invalid base64 encoding") from err
    if len(decoded) != expected_len:
        raise ParseError("invalid encoded length")
    return decoded


def decode_comment(data: bytes, prefix: str) -> str:
    try:
        comment = data.decode()
    except UnicodeDecodeError as err:
        raise ParseError("invalid comment encoding") from err
    if not comment.startswith(prefix):
        raise ParseError("invalid comment prefix")
    return comment[len(prefix) :]


def split_lines(data: bytes, expected_len: int) -> list[bytes]:
    lines = data.splitlines()
    if len(lines) != expected_len:
        raise ParseError("invalid number of lines")
    return lines
