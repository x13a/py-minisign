import hashlib
import io
from typing import (
    BinaryIO,
    Union,
)


class Reader:
    def __init__(self, data: bytes):
        self._buf = data
        self._pos = 0

    def read(self, size: int) -> bytes:
        pos = self._pos + size
        res = self._buf[self._pos:pos]
        if len(res) != size:
            raise ValueError('read size mismatch')
        self._pos = pos
        return res


def get_data(data: Union[bytes, BinaryIO], prehash: bool) -> bytes:
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
