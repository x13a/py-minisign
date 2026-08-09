import pytest

from minisign import (
    Error,
    KeyPair,
    SecretKey,
)
from minisign.scrypt import (
    MEMLIMIT_MAX,
    OPSLIMIT_MAX,
    ScryptParams,
    scrypt_params_from_limits,
)


@pytest.mark.parametrize(
    "opslimit, memlimit, expected",
    (
        (32_768, 16_777_216, ScryptParams(N=1_024, r=8, p=1)),
        (524_288, 16_777_216, ScryptParams(N=16_384, r=8, p=1)),
        (1_048_576, 33_554_432, ScryptParams(N=32_768, r=8, p=1)),
        (33_554_432, 1_073_741_824, ScryptParams(N=1_048_576, r=8, p=1)),
        (65_536, 1_048_576, ScryptParams(N=1_024, r=8, p=2)),
    ),
)
def test_scrypt_params_from_limits(
    opslimit: int,
    memlimit: int,
    expected: ScryptParams,
):
    assert scrypt_params_from_limits(opslimit, memlimit) == expected


def test_secret_key_custom_scrypt_params_roundtrip():
    key_pair = KeyPair.generate()
    secret_key = key_pair.secret_key

    secret_key.encrypt(
        "strong password",
        opslimit=65_536,
        memlimit=1_048_576,
    )

    stored = SecretKey.from_bytes(bytes(secret_key))
    assert stored._kdf_opslimit == 65_536
    assert stored._kdf_memlimit == 1_048_576
    assert stored.is_encrypted()

    stored.decrypt("strong password")
    assert not stored.is_encrypted()
    assert stored.get_public_key() == key_pair.public_key


@pytest.mark.parametrize(
    "limits, message",
    (
        ({"opslimit": -1}, "invalid opslimit"),
        ({"opslimit": OPSLIMIT_MAX + 1}, "invalid opslimit"),
        ({"memlimit": -1}, "invalid memlimit"),
        ({"memlimit": MEMLIMIT_MAX + 1}, "invalid memlimit"),
    ),
)
def test_secret_key_rejects_invalid_scrypt_limits_without_modification(
    limits: dict[str, int],
    message: str,
):
    secret_key = KeyPair.generate().secret_key
    encoded = bytes(secret_key)

    with pytest.raises(Error, match=message):
        secret_key.encrypt("strong password", **limits)

    assert bytes(secret_key) == encoded
