import unittest

from .minisign import (
    PublicKey,
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
