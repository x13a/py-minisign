py-minisign
===========

Missing python `minisign <https://github.com/jedisct1/minisign>`_ library.

Library
-------

.. code:: python

    import os
    import minisign

    # verify

    pk = minisign.PublicKey.from_base64(
        'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3')
    sig = minisign.Signature.from_bytes(
        b'untrusted comment: signature from minisign secret key\n'
        b'RWQf6LRCGA9i59SLOFxz6NxvASXDJeRtuZykwQepbDEGt87ig1BNpWaVWuNrm73YiIiJbq71Wi+dP9eKL8OC351vwIasSSbXxwA=\n'
        b'trusted comment: timestamp:1555779966\tfile:test\n'
        b'QtKMXWyYcwdpZAlPF7tE2ENJkRd1ujvKjlj1m9RtHTBnZPa5WKU5uWRs5GoP5M/VqE81QFuMKI5k/SfNQUaOAA=='
    )
    pk.verify(b'test', sig)

    # sign

    sk = minisign.SecretKey.from_file('/path/to/secret.key')
    sk.decrypt('strong_password')
    sig = sk.sign(b'very important data')

    # generate key pair

    key_pair = minisign.KeyPair.generate()
    sk = key_pair.secret_key
    pk = key_pair.public_key

    # save key

    sk.encrypt('strong_password')
    with open(os.open('/path/to/secret.key', os.O_CREAT | os.O_WRONLY, 0o600), 'wb') as f:
        f.write(bytes(sk))
