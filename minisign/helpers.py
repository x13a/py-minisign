from __future__ import annotations

import hashlib
from typing import (
    Protocol,
    runtime_checkable,
)

from .exceptions import (
    Error,
    ParseError,
)


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
    if "\n" in s:
        raise Error("comment contains new line char")
