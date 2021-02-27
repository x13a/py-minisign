import hashlib
import io
from typing import (
    BinaryIO,
    Union,
)

from .exceptions import (
    Error,
    ParseError,
)


class Reader:
    def __init__(self, data: bytes):
        self._buf = data
        self._pos = 0

    def __len__(self) -> int:
        return len(self._buf) - self._pos

    def read(self, size: int) -> bytes:
        pos = self._pos + size
        data = self._buf[self._pos:pos]
        if len(data) != size:
            raise ParseError('read size mismatch')
        self._pos = pos
        return data


def read_data(data: Union[bytes, BinaryIO], prehash: bool) -> bytes:
    if prehash:
        if isinstance(data, io.BufferedIOBase):
            hasher = hashlib.blake2b()
            while chunk := data.read(1 << 13):
                hasher.update(chunk)
            data = hasher.digest()
        else:
            data = hashlib.blake2b(data).digest()
    elif isinstance(data, io.BufferedIOBase):
        data = data.read()
    return data


def check_comment(s: str):
    if '\n' in s:
        raise Error('comment contains new line char')
