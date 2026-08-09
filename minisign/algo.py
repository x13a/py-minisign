import enum


@enum.unique
class SignatureAlgorithm(bytes, enum.Enum):
    PURE_ED_DSA = b"Ed"
    PREHASHED_ED_DSA = b"ED"


@enum.unique
class KDFAlgorithm(bytes, enum.Enum):
    NONE = b"\0\0"
    SCRYPT = b"Sc"


@enum.unique
class CksumAlgorithm(bytes, enum.Enum):
    BLAKE2b = b"B2"
