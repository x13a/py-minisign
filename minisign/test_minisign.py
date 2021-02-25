import copy
import io
import secrets
import unittest

from .minisign import (
    KEYNUM_SK_LEN,
    KeyPair,
    PublicKey,
    SecretKey,
    Signature,
)


class MinisignTestCase(unittest.TestCase):

    def test_verify_pure(self):
        sig = Signature.from_bytes(
            b'untrusted comment: signature from minisign secret key\n'
            b'RWQf6LRCGA9i59SLOFxz6NxvASXDJeRtuZykwQepbDEGt87ig1BNpWaVWuNrm73YiIiJbq71Wi+dP9eKL8OC351vwIasSSbXxwA=\n'
            b'trusted comment: timestamp:1555779966\tfile:test\n'
            b'QtKMXWyYcwdpZAlPF7tE2ENJkRd1ujvKjlj1m9RtHTBnZPa5WKU5uWRs5GoP5M/VqE81QFuMKI5k/SfNQUaOAA=='
        )
        self.assertEqual(
            sig.untrusted_comment,
            'untrusted comment: signature from minisign secret key',
        )
        self.assertEqual(
            sig.trusted_comment,
            'timestamp:1555779966\tfile:test',
        )
        PublicKey.from_base64(
            'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
        ).verify(b'test', sig)

    def test_verify_prehashed(self):
        sig = Signature.from_bytes(
            b'untrusted comment: signature from minisign secret key\n'
            b'RUQf6LRCGA9i559r3g7V1qNyJDApGip8MfqcadIgT9CuhV3EMhHoN1mGTkUidF/z7SrlQgXdy8ofjb7bNJJylDOocrCo8KLzZwo=\n'
            b'trusted comment: timestamp:1556193335\tfile:test\n'
            b'y/rUw2y8/hOUYjZU71eHp/Wo1KZ40fGy2VJEDl34XMJM+TX48Ss/17u3IvIfbVR1FkZZSNCisQbuQY+bHwhEBg=='
        )
        self.assertEqual(
            sig.untrusted_comment,
            'untrusted comment: signature from minisign secret key',
        )
        self.assertEqual(
            sig.trusted_comment,
            'timestamp:1556193335\tfile:test',
        )
        PublicKey.from_base64(
            'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
        ).verify(b'test', sig)

    def test_public_key_conv(self):
        pk = KeyPair.generate().public_key
        self.assertEqual(pk, PublicKey.from_bytes(bytes(pk)))

    def test_secret_key_conv(self):
        sk = KeyPair.generate().secret_key
        self.assertEqual(sk, SecretKey.from_bytes(bytes(sk)))

    def test_signature_conv(self):
        sig = KeyPair.generate().secret_key.sign(b'data')
        self.assertEqual(sig, Signature.from_bytes(bytes(sig)))

    def test_keynum_sk_xor(self):
        kn = KeyPair.generate().secret_key._keynum_sk
        kn_origin = copy.deepcopy(kn)
        key = secrets.token_bytes(KEYNUM_SK_LEN)
        kn.xor(key)
        self.assertNotEqual(kn_origin, kn)
        kn.xor(key)
        self.assertEqual(kn_origin, kn)

    def test_secret_key_crypt(self):
        sk = KeyPair.generate().secret_key
        kn_origin = copy.deepcopy(sk._keynum_sk)
        password = 'strong_password'
        sk.encrypt(password)
        self.assertNotEqual(kn_origin, sk._keynum_sk)
        sk.decrypt(password)
        self.assertEqual(kn_origin, sk._keynum_sk)

    def test_sign_verify(self):
        kp = KeyPair.generate()
        data = b'very important data'
        kp.public_key.verify(data, kp.secret_key.sign(data))
        kp.public_key.verify(data, kp.secret_key.sign(data, prehash=True))
        kp.public_key.verify(
            io.BytesIO(data),
            kp.secret_key.sign(io.BytesIO(data), prehash=True),
        )
