from typing import TYPE_CHECKING, NamedTuple

from cryptography.hazmat.primitives.kdf import scrypt

from .const import KEYNUM_SK_LEN
from .exceptions import Error

if TYPE_CHECKING:
    from .secret_key import KeynumSK

OPSLIMIT = 1_048_576
MEMLIMIT = 33_554_432
OPSLIMIT_MAX = (1 << 64) - 1
MEMLIMIT_MAX = 1_073_741_824
N_LOG2_MAX = 20


class ScryptParams(NamedTuple):
    N: int
    r: int
    p: int


def scrypt_params_from_limits(opslimit: int, memlimit: int) -> ScryptParams:
    if not 0 <= opslimit <= OPSLIMIT_MAX:
        raise Error("invalid opslimit")
    if not 0 <= memlimit <= MEMLIMIT_MAX:
        raise Error("invalid memlimit")
    opslimit = max(32768, opslimit)
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
        p = min(0x3FFFFFFF, (opslimit // 4) // (1 << n_log2)) // r
    if n_log2 > N_LOG2_MAX:
        raise Error("n_log2 too high")
    return ScryptParams(
        N=1 << n_log2,
        r=r,
        p=p,
    )


def xor_crypt(
    *,
    keynum_sk: "KeynumSK",
    password: str,
    salt: bytes,
    opslimit: int,
    memlimit: int,
) -> None:
    params = scrypt_params_from_limits(opslimit, memlimit)
    stream = bytearray(
        scrypt.Scrypt(
            salt=salt,
            length=KEYNUM_SK_LEN,
            n=params.N,
            r=params.r,
            p=params.p,
        ).derive(password.encode())
    )
    try:
        keynum_sk.xor(stream)
    finally:
        stream[:] = bytes(len(stream))
