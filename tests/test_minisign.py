import copy
import io
import secrets

import pytest

from minisign.minisign import (
    KEYNUM_SK_LEN,
    Error,
    KDFAlgorithm,
    KeyPair,
    PublicKey,
    SecretKey,
    Signature,
)


def test_verify_pure():
    sig = Signature.from_bytes(
        b"untrusted comment: signature from minisign secret key\n"
        b"RWQf6LRCGA9i59SLOFxz6NxvASXDJeRtuZykwQepbDEGt87ig1BNpWaVWuNrm73YiIiJbq71Wi+dP9eKL8OC351vwIasSSbXxwA=\n"
        b"trusted comment: timestamp:1555779966\tfile:test\n"
        b"QtKMXWyYcwdpZAlPF7tE2ENJkRd1ujvKjlj1m9RtHTBnZPa5WKU5uWRs5GoP5M/VqE81QFuMKI5k/SfNQUaOAA=="
    )
    assert (
        sig.untrusted_comment == "untrusted comment: signature from minisign secret key"
    )
    assert sig.trusted_comment == "timestamp:1555779966\tfile:test"
    PublicKey.from_base64(
        "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3"
    ).verify(b"test", sig)


def test_verify_prehashed():
    sig = Signature.from_bytes(
        b"untrusted comment: signature from minisign secret key\n"
        b"RUQf6LRCGA9i559r3g7V1qNyJDApGip8MfqcadIgT9CuhV3EMhHoN1mGTkUidF/z7SrlQgXdy8ofjb7bNJJylDOocrCo8KLzZwo=\n"
        b"trusted comment: timestamp:1556193335\tfile:test\n"
        b"y/rUw2y8/hOUYjZU71eHp/Wo1KZ40fGy2VJEDl34XMJM+TX48Ss/17u3IvIfbVR1FkZZSNCisQbuQY+bHwhEBg=="
    )
    assert (
        sig.untrusted_comment == "untrusted comment: signature from minisign secret key"
    )
    assert sig.trusted_comment == "timestamp:1556193335\tfile:test"
    PublicKey.from_base64(
        "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3"
    ).verify(b"test", sig)


def test_public_key_conv():
    pk = KeyPair.generate().public_key
    assert pk == PublicKey.from_bytes(bytes(pk))


def test_secret_key_conv():
    sk = KeyPair.generate().secret_key
    assert sk == SecretKey.from_bytes(bytes(sk))


def test_unencrypted_secret_key():
    sk = SecretKey.from_bytes(
        b"untrusted comment: minisign encrypted secret key\n"
        b"RWQAAEIyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOItWpGuGQbG4C9WXaxEYLgZ2xxuqfbuZmDgAhQ8Unot8t7SyxZ0nVh0gESesJ6Ay57fGFJ9T1ajVmanT7MFMCCDbPZ8uqDcSAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    )
    pk = PublicKey.from_bytes(
        b"untrusted comment: minisign public key B141866BA4568B38\n"
        b"RWQ4i1aka4ZBsR0gESesJ6Ay57fGFJ9T1ajVmanT7MFMCCDbPZ8uqDcS"
    )
    assert sk.get_public_key().to_base64() == pk.to_base64()
    v = b"data"
    pk.verify(v, sk.sign(v))


def test_signature_conv():
    sig = KeyPair.generate().secret_key.sign(b"data")
    assert sig == Signature.from_bytes(bytes(sig))


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
    unencrypted = KeyPair.generate()
    assert unencrypted.secret_key._kdf_algorithm == KDFAlgorithm.NONE
    assert SecretKey.from_bytes(bytes(unencrypted.secret_key)) == unencrypted.secret_key
    passwd = "strong_password"
    encrypted = KeyPair.generate(
        kdf_algorithm=KDFAlgorithm.SCRYPT,
        password=passwd,
    )
    assert encrypted.secret_key._kdf_algorithm == KDFAlgorithm.SCRYPT
    assert encrypted.secret_key.is_encrypted()
    with pytest.raises(Error, match="decrypt it before signing"):
        encrypted.secret_key.sign(b"data")
    stored = SecretKey.from_bytes(bytes(encrypted.secret_key))
    stored.decrypt(passwd)
    assert not stored.is_encrypted()
    assert stored.get_public_key().to_base64() == encrypted.public_key.to_base64()


def test_encrypted_key_operations_are_safe():
    passwd = "strong_password"
    sk = KeyPair.generate(
        kdf_algorithm=KDFAlgorithm.SCRYPT,
        password=passwd,
    ).secret_key
    encrypted = bytes(sk)
    with pytest.raises(Error, match="already encrypted"):
        sk.encrypt(passwd)
    assert bytes(sk) == encrypted
    with pytest.raises(Error, match="wrong password"):
        sk.decrypt("wrong_password")
    assert bytes(sk) == encrypted
    assert sk.is_encrypted()


def test_sign_verify():
    kp = KeyPair.generate()
    data = b"very important data"
    kp.public_key.verify(data, kp.secret_key.sign(data))
    kp.public_key.verify(data, kp.secret_key.sign(data, prehash=True))
    kp.public_key.verify(
        io.BytesIO(data),
        kp.secret_key.sign(io.BytesIO(data), prehash=True),
    )
