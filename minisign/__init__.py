"""
Minisign
"""

from .const import TRUSTED_COMMENT_MAX_LEN
from .exceptions import (
    Error,
    ParseError,
    VerifyError,
)
from .minisign import KeyPair
from .public_key import PublicKey
from .scrypt import (
    MEMLIMIT,
    MEMLIMIT_MAX,
    OPSLIMIT,
    OPSLIMIT_MAX,
)
from .secret_key import SecretKey
from .signature import Signature

__all__ = [
    "MEMLIMIT",
    "MEMLIMIT_MAX",
    "OPSLIMIT",
    "OPSLIMIT_MAX",
    "TRUSTED_COMMENT_MAX_LEN",
    "Error",
    "KeyPair",
    "ParseError",
    "PublicKey",
    "SecretKey",
    "Signature",
    "VerifyError",
]
