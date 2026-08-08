py-minisign
===========

A Python implementation of the `Minisign <https://jedisct1.github.io/minisign/>`_
signature system.

Installation
------------

With `uv <https://docs.astral.sh/uv/>`_:

.. code:: shell

    uv add py-minisign

With pip:

.. code:: shell

    python3 -m pip install py-minisign

Verify a signature
------------------

.. code:: python

    import minisign

    public_key = minisign.PublicKey.from_base64(
        "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3"
    )
    signature = minisign.Signature.from_bytes(
        b"untrusted comment: signature from minisign secret key\n"
        b"RWQf6LRCGA9i59SLOFxz6NxvASXDJeRtuZykwQepbDEGt87ig1BNpWaVWuNrm73YiIiJbq71Wi+dP9eKL8OC351vwIasSSbXxwA=\n"
        b"trusted comment: timestamp:1555779966\tfile:test\n"
        b"QtKMXWyYcwdpZAlPF7tE2ENJkRd1ujvKjlj1m9RtHTBnZPa5WKU5uWRs5GoP5M/VqE81QFuMKI5k/SfNQUaOAA=="
    )

    public_key.verify(b"test", signature)

``verify()`` raises ``VerifyError`` if the signature is invalid.

Sign data
---------

Secret keys loaded from disk are usually encrypted. Decrypt the key before
signing and wipe its mutable secret buffers when it is no longer needed:

.. code:: python

    import minisign

    secret_key = minisign.SecretKey.from_file("/path/to/minisign.key")
    try:
        secret_key.decrypt("strong password")
        signature = secret_key.sign(
            b"very important data",
            trusted_comment="release 1.0",
        )
    finally:
        secret_key.wipe()

    print(bytes(signature).decode())

The default signing mode uses a BLAKE2b prehash. Pass ``prehash=False`` when a
legacy ``Ed`` signature is required.

Generate and store a key pair
-----------------------------

``KeyPair.generate()`` creates an unencrypted key using ``KDF_NONE``. Calling
``encrypt()`` upgrades it to scrypt and encrypts the secret key before it is
serialized:

.. code:: python

    import os

    import minisign

    key_pair = minisign.KeyPair.generate()
    secret_key = key_pair.secret_key

    try:
        secret_key.encrypt("strong password")

        with open(
            os.open(
                "/path/to/minisign.key",
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                0o600,
            ),
            "wb",
        ) as file:
            file.write(bytes(secret_key) + b"\n")

        with open("/path/to/minisign.pub", "wb") as file:
            file.write(bytes(key_pair.public_key) + b"\n")
    finally:
        secret_key.wipe()

The KDF can also be selected explicitly at generation time. A key generated
with ``SCRYPT`` still needs an ``encrypt()`` call before it is encrypted:

.. code:: python

    key_pair = minisign.KeyPair.generate(
        kdf_algorithm=minisign.KDFAlgorithm.SCRYPT,
    )
    key_pair.secret_key.encrypt("strong password")

Use ``KDF_NONE`` only when an unencrypted secret key is intentionally required:

.. code:: python

    key_pair = minisign.KeyPair.generate(
        kdf_algorithm=minisign.KDFAlgorithm.NONE,
    )
    encoded_secret_key = bytes(key_pair.secret_key)

Sign and verify files
---------------------

.. code:: python

    import minisign

    secret_key = minisign.SecretKey.from_file("/path/to/minisign.key")
    public_key = minisign.PublicKey.from_file("/path/to/minisign.pub")

    try:
        secret_key.decrypt("strong password")
        secret_key.sign_file(
            "archive.tar.gz",
            prehash=True,
            drop_signature=True,
        )
    finally:
        secret_key.wipe()

    # Reads archive.tar.gz.minisig automatically.
    public_key.verify_file("archive.tar.gz")

Comments
--------

Comment properties contain only their values. They do not include the
``untrusted comment:`` or ``trusted comment:`` prefixes; serialization adds
these prefixes automatically.

Untrusted comments are not authenticated and may be changed without
invalidating a signature. Trusted comments are covered by the global signature.

Memory wiping
-------------

``SecretKey.wipe()`` overwrites the mutable secret-key buffers and prevents the
key object from being used again.

Development
-----------

Install the project and development dependencies:

.. code:: shell

    uv sync --group dev

Run the test suite and static checks:

.. code:: shell

    uv run pytest
    uvx ruff format
    uvx ruff check
    uvx ty check

Build the source distribution and wheel:

.. code:: shell

    uv build
