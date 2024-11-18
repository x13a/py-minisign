"""
Minisign
"""

__version__ = '0.12.0'

from .exceptions import (
    Error,
    ParseError,
    VerifyError,
)
from .minisign import (
    KeyPair,
    PublicKey,
    SecretKey,
    Signature,
)
