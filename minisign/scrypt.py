from typing import NamedTuple

from .exceptions import Error

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
    if memlimit > MEMLIMIT_MAX:
        raise Error("memlimit too high")
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
