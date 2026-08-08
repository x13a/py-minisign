import base64
import copy
import io
import secrets
from pathlib import Path

import pytest

from minisign.minisign import (
    KEYNUM_SK_LEN,
    TRUSTED_COMMENT_MAX_LEN,
    Error,
    KDFAlgorithm,
    KeyPair,
    ParseError,
    PublicKey,
    SecretKey,
    Signature,
    VerifyError,
)


def test_public_key_conv():
    pk = KeyPair.generate().public_key
    assert pk == PublicKey.from_bytes(bytes(pk))


def test_public_key_rejects_prehash_algorithm():
    encoded = bytearray(base64.b64decode(KeyPair.generate().public_key.to_base64()))
    encoded[:2] = b"ED"
    with pytest.raises(ParseError, match="invalid signature algorithm"):
        PublicKey.from_base64(base64.b64encode(encoded))


def test_secret_key_conv():
    sk = KeyPair.generate().secret_key
    assert sk == SecretKey.from_bytes(bytes(sk))


def test_secret_key_rejects_prehash_algorithm():
    encoded = bytearray(base64.b64decode(KeyPair.generate().secret_key.to_base64()))
    encoded[:2] = b"ED"
    with pytest.raises(ParseError, match="invalid signature algorithm"):
        SecretKey.from_base64(base64.b64encode(encoded))


def test_signature_conv():
    sig = KeyPair.generate().secret_key.sign(b"data")
    assert sig == Signature.from_bytes(bytes(sig))


def test_sign_prefixed_trusted_comment():
    kp = KeyPair.generate()
    sig = kp.secret_key.sign(
        b"data",
        trusted_comment="trusted comment: release",
    )
    kp.public_key.verify(b"data", Signature.from_bytes(bytes(sig)))


def test_untrusted_comment_setters():
    key_pair = KeyPair.generate()
    values = (
        key_pair.secret_key.sign(b"data"),
        key_pair.public_key,
        key_pair.secret_key,
    )

    for value in values:
        value.untrusted_comment = "release"
        assert value.untrusted_comment == "release"
        assert bytes(value).splitlines()[0] == b"untrusted comment: release"


def test_key_untrusted_comment_setters_accept_none():
    key_pair = KeyPair.generate()

    for key in (key_pair.public_key, key_pair.secret_key):
        key.untrusted_comment = "release"
        key.untrusted_comment = None
        assert key.untrusted_comment is None


@pytest.mark.parametrize("invalid", ("line 1\nline 2", "bad\x01comment"))
def test_untrusted_comment_setters_are_atomic(invalid: str):
    key_pair = KeyPair.generate()
    values = (
        key_pair.secret_key.sign(b"data"),
        key_pair.public_key,
        key_pair.secret_key,
    )

    for value in values:
        value.untrusted_comment = "original"
        with pytest.raises(ParseError):
            value.untrusted_comment = invalid
        assert value.untrusted_comment == "original"


def test_signature_authentication_boundaries():
    key_pair = KeyPair.generate()
    signature = key_pair.secret_key.sign(
        b"data",
        untrusted_comment="original",
        trusted_comment="release",
    )
    encoded = bytes(signature)

    changed_untrusted = Signature.from_bytes(
        encoded.replace(
            b"untrusted comment: original",
            b"untrusted comment: changed",
        )
    )
    key_pair.public_key.verify(b"data", changed_untrusted)

    changed_trusted = Signature.from_bytes(
        encoded.replace(
            b"trusted comment: release",
            b"trusted comment: changed",
        )
    )
    with pytest.raises(VerifyError):
        key_pair.public_key.verify(b"data", changed_trusted)

    lines = encoded.splitlines()
    global_signature = bytearray(base64.b64decode(lines[3]))
    global_signature[-1] ^= 1
    lines[3] = base64.b64encode(global_signature)
    with pytest.raises(VerifyError):
        key_pair.public_key.verify(b"data", Signature.from_bytes(b"\n".join(lines)))

    with pytest.raises(VerifyError, match="incompatible key identifiers"):
        KeyPair.generate().public_key.verify(b"data", signature)


def test_signature_rejects_modified_data():
    key_pair = KeyPair.generate()
    signature = key_pair.secret_key.sign(b"data")
    with pytest.raises(VerifyError):
        key_pair.public_key.verify(b"changed", signature)


def test_keynum_sk_xor():
    kn = KeyPair.generate().secret_key._keynum_sk
    kn_origin = copy.deepcopy(kn)
    key = secrets.token_bytes(KEYNUM_SK_LEN)
    kn.xor(key)
    assert kn_origin != kn
    kn.xor(key)
    assert kn_origin == kn


def test_secret_key_crypt():
    sk = KeyPair.generate().secret_key
    kn_origin = copy.deepcopy(sk._keynum_sk)
    password = "strong_password"
    sk.encrypt(password)
    assert sk._kdf_algorithm == KDFAlgorithm.SCRYPT
    sk.decrypt(password)
    assert kn_origin == sk._keynum_sk


def test_key_pair_kdf_selection():
    kp_kdf_none = KeyPair.generate()
    assert kp_kdf_none.secret_key._kdf_algorithm == KDFAlgorithm.NONE
    assert SecretKey.from_bytes(bytes(kp_kdf_none.secret_key)) == kp_kdf_none.secret_key
    passwd = "strong_password"
    kp_kdf_script = KeyPair.generate(kdf_algorithm=KDFAlgorithm.SCRYPT)
    kp_kdf_script.secret_key.encrypt(passwd)
    assert kp_kdf_script.secret_key._kdf_algorithm == KDFAlgorithm.SCRYPT
    assert kp_kdf_script.secret_key.is_encrypted()
    with pytest.raises(Error, match="decrypt it before signing"):
        kp_kdf_script.secret_key.sign(b"data")
    stored = SecretKey.from_bytes(bytes(kp_kdf_script.secret_key))
    stored.decrypt(passwd)
    assert not stored.is_encrypted()
    assert stored.get_public_key().to_base64() == kp_kdf_script.public_key.to_base64()


def test_encrypted_key_operations_safe():
    passwd = "strong_password"
    sk = KeyPair.generate(kdf_algorithm=KDFAlgorithm.SCRYPT).secret_key
    sk.encrypt(passwd)
    encrypted = bytes(sk)
    with pytest.raises(Error, match="already encrypted"):
        sk.encrypt(passwd)
    assert bytes(sk) == encrypted
    with pytest.raises(Error, match="wrong password"):
        sk.decrypt("wrong_password")
    assert bytes(sk) == encrypted
    assert sk.is_encrypted()


def test_wipe_secret_key():
    sk = KeyPair.generate().secret_key
    sk.wipe()
    assert sk.is_wiped
    assert not any(bytes(sk._keynum_sk))
    sk.wipe()
    for operation in (
        sk.get_public_key,
        lambda: PublicKey.from_secret_key(sk),
        sk.is_encrypted,
        lambda: sk.encrypt("password"),
        lambda: sk.decrypt("password"),
        lambda: sk.sign(b"data"),
        sk.to_base64,
        lambda: bytes(sk),
    ):
        with pytest.raises(Error, match="has been wiped"):
            operation()


def test_secret_key_context_manager_wipes_on_exit():
    secret_key = KeyPair.generate().secret_key

    with secret_key as entered:
        assert entered is secret_key
        assert not secret_key.is_wiped

    assert secret_key.is_wiped
    assert not any(bytes(secret_key._keynum_sk))


def test_secret_key_context_manager_wipes_on_exception():
    secret_key = KeyPair.generate().secret_key

    with pytest.raises(RuntimeError, match="signing failed"), secret_key:
        raise RuntimeError("signing failed")

    assert secret_key.is_wiped
    assert not any(bytes(secret_key._keynum_sk))


def test_parsers_reject_invalid_structure():
    key_pair = KeyPair.generate()
    signature = key_pair.secret_key.sign(b"data")
    invalid_signature_base64 = bytes(signature).splitlines()
    invalid_signature_base64[1] = b"!"
    invalid_signature_length = bytes(signature).splitlines()
    invalid_signature_length[1] = base64.b64encode(b"Ed")
    invalid_global_signature_length = bytes(signature).splitlines()
    invalid_global_signature_length[3] = base64.b64encode(b"short")
    invalid_trusted_prefix = bytes(signature).splitlines()
    invalid_trusted_prefix[2] = b"comment: " + signature.trusted_comment.encode()

    for operation in (
        lambda: PublicKey.from_base64(b"!"),
        lambda: SecretKey.from_base64(b"!"),
        lambda: PublicKey.from_base64(base64.b64encode(b"Ed")),
        lambda: SecretKey.from_base64(base64.b64encode(b"Ed")),
        lambda: Signature.from_bytes(b"\n".join(invalid_signature_base64)),
        lambda: Signature.from_bytes(b"\n".join(invalid_signature_length)),
        lambda: Signature.from_bytes(b"\n".join(invalid_global_signature_length)),
        lambda: PublicKey.from_bytes(bytes(key_pair.public_key) + b"\nextra"),
        lambda: SecretKey.from_bytes(bytes(key_pair.secret_key) + b"\nextra"),
        lambda: Signature.from_bytes(bytes(signature) + b"\nextra"),
        lambda: PublicKey.from_bytes(
            bytes(key_pair.public_key).replace(b"untrusted comment: ", b"comment: ")
        ),
        lambda: SecretKey.from_bytes(
            bytes(key_pair.secret_key).replace(b"untrusted comment: ", b"comment: ")
        ),
        lambda: Signature.from_bytes(b"\n".join(invalid_trusted_prefix)),
    ):
        with pytest.raises(ParseError):
            operation()


def test_parsers_reject_unsupported_algorithms():
    key_pair = KeyPair.generate()

    public_key = bytearray(base64.b64decode(key_pair.public_key.to_base64()))
    public_key[:2] = b"??"
    with pytest.raises(ParseError, match="unsupported signature algorithm"):
        PublicKey.from_base64(base64.b64encode(public_key))

    for offset in (2, 4):
        secret_key = bytearray(base64.b64decode(key_pair.secret_key.to_base64()))
        secret_key[offset : offset + 2] = b"??"
        with pytest.raises(ParseError, match="unsupported key algorithm"):
            SecretKey.from_base64(base64.b64encode(secret_key))

    signature_lines = bytes(key_pair.secret_key.sign(b"data")).splitlines()
    signature = bytearray(base64.b64decode(signature_lines[1]))
    signature[:2] = b"??"
    signature_lines[1] = base64.b64encode(signature)
    with pytest.raises(ParseError, match="unsupported signature algorithm"):
        Signature.from_bytes(b"\n".join(signature_lines))


def test_file_api(tmp_path: Path):
    key_pair = KeyPair.generate()
    secret_key_path = tmp_path / "minisign.key"
    public_key_path = tmp_path / "minisign.pub"
    message_path = tmp_path / "payload.bin"
    secret_key_path.write_bytes(bytes(key_pair.secret_key))
    public_key_path.write_bytes(bytes(key_pair.public_key))
    message_path.write_bytes(b"important data" * 1000)

    secret_key = SecretKey.from_file(secret_key_path)
    public_key = PublicKey.from_file(public_key_path)
    signature = secret_key.sign_file(
        message_path,
        prehash=True,
        drop_signature=True,
    )
    signature_path = tmp_path / "payload.bin.minisig"

    assert Signature.from_file(signature_path) == signature
    assert "file:payload.bin" in signature.trusted_comment
    assert "hashed" in signature.trusted_comment
    public_key.verify_file(message_path, signature)
    public_key.verify_file(message_path)


def test_trusted_comment_length_boundary():
    secret_key = KeyPair.generate().secret_key
    secret_key.sign(b"data", trusted_comment="a" * TRUSTED_COMMENT_MAX_LEN)
    with pytest.raises(ParseError, match="trusted comment too long"):
        secret_key.sign(b"data", trusted_comment="a" * (TRUSTED_COMMENT_MAX_LEN + 1))


def test_sign_verify():
    kp = KeyPair.generate()
    data = b"very important data" * 1000
    kp.public_key.verify(data, kp.secret_key.sign(data, prehash=False))
    kp.public_key.verify(data, kp.secret_key.sign(data, prehash=True))
    kp.public_key.verify(
        io.BytesIO(data),
        kp.secret_key.sign(io.BytesIO(data), prehash=True),
    )
