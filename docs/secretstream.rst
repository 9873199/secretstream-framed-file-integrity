Secret Stream File Container
============================

.. currentmodule:: nacl.secretstream

The :mod:`nacl.secretstream` module adds a versioned binary container and
file-object oriented framing on top of the low level
``crypto_secretstream_xchacha20poly1305`` bindings. It does not implement any
cryptographic primitive of its own: every frame is sealed and opened by
libsodium.

A container starts with a fixed magic and version byte, followed by the
libsodium stream header, followed by any number of length prefixed encrypted
frames and exactly one final frame. Each frame is a 4 byte big-endian length
(authentication tag included) followed by the secretstream ciphertext.

The caller supplied ``context``, the container header, the zero based frame
sequence number and the declared frame length are all encoded as explicit,
length prefixed, big-endian additional data (AD) and authenticated with
every frame. No dictionary serialization or platform byte order is used.
Consequently frames cannot be moved between files encrypted under the same
key with a different context, nor reordered or replayed within a file.

Encrypting a stream
-------------------

:class:`SecretStreamWriter` frames plaintext from bounded short reads. An
empty input still produces a single, unique FINAL frame (uniqueness comes
from the fresh random header libsodium generates for every stream).

.. testcode::

    import io

    import nacl.secretstream
    import nacl.utils

    key = nacl.utils.random(
        nacl.bindings.crypto_secretstream_xchacha20poly1305_KEYBYTES
    )

    source = io.BytesIO(b"backup contents")
    encrypted = io.BytesIO()

    # Convenience wrapper around SecretStreamWriter.
    nacl.secretstream.encrypt_stream(
        source, encrypted, key, context=b"daily-backup"
    )

Incremental reading
-------------------

:class:`SecretStreamReader` yields one authenticated plaintext chunk per
frame. A yielded chunk has individually passed authentication, but that does
**not** prove the whole file is valid: the FINAL frame could still be
missing or not be the last frame. Whole-file validity is only established
once iteration (or :meth:`SecretStreamReader.readall`) completes, which also
confirms that the source is at EOF.

.. testcode::

    reader = nacl.secretstream.SecretStreamReader(
        io.BytesIO(encrypted.getvalue()), key, context=b"daily-backup"
    )
    assert reader.readall() == b"backup contents"

Strict, all-or-nothing decryption
---------------------------------

:func:`decrypt_stream` never writes plaintext to the real destination until
the FINAL frame and EOF have both been confirmed. The plaintext is buffered
in a seekable scratch stream provided by the caller; on any container
failure the destination receives zero writes and the scratch stream is
scrubbed. The source, destination and scratch streams are never closed.

.. testcode::

    destination = io.BytesIO()
    scratch = io.BytesIO()
    nacl.secretstream.decrypt_stream(
        io.BytesIO(encrypted.getvalue()),
        destination,
        key,
        context=b"daily-backup",
        scratch=scratch,
    )
    assert destination.getvalue() == b"backup contents"
    # The scratch stream is seeked back and truncated on success too.
    assert scratch.getvalue() == b""

Ordinary output streams provide no atomic rollback: if a scratch write or
the final copy fails (for example because a disk is full), the underlying
:exc:`OSError` is propagated and the destination may already hold partial
plaintext.

Container errors
----------------

Every container level failure derives from :class:`ContainerError`, itself a
:class:`nacl.exceptions.CryptoError`:

* :class:`ContainerFormatError`: bad magic or version, truncated header or
  frame, or a declared frame length outside the negotiated bounds. Lengths
  are checked before the frame body is read.
* :class:`FrameAuthenticationError`: libsodium rejected a frame, covering a
  wrong key or context, corruption, reordering, replay and frames spliced
  from another container.
* :class:`FinalFrameError`: the FINAL frame is missing, repeated, not the
  last frame, or trailing data follows it.
* :class:`ContainerStateError`: a writer was reused after its FINAL frame.

Reference
---------

.. class:: SecretStreamWriter(stream, key, context, max_frame_length)

    Incremental container writer. The underlying stream is never closed.
    ``context`` defaults to ``b""`` and ``max_frame_length`` defaults to
    :data:`DEFAULT_MAX_FRAME_LENGTH`.

    :param stream: a writable binary stream receiving the container.
    :param bytes key: the secretstream key.
    :param bytes context: caller defined bytes authenticated into every
        frame; readers must pass the identical value.
    :param int max_frame_length: maximum ciphertext length of a frame,
        ABYTES included, strictly greater than ABYTES and not exceeding
        :data:`CONTAINER_MAX_FRAME_LENGTH`.

    .. method:: write(data)

        Buffer plaintext and emit full MESSAGE frames, honoring bounded
        short reads. Returns the number of plaintext bytes accepted.

    .. method:: rekey()

        Flush any buffered plaintext in a frame carrying libsodium's
        ``TAG_REKEY`` tag; readers follow the rekey automatically.

    .. method:: finish()

        Emit the unique FINAL frame (possibly empty) and finalize the
        container. Idempotent.

    .. attribute:: chunk_size

        Maximum plaintext bytes carried by a non-final frame.

.. class:: SecretStreamReader(stream, key, context, max_frame_length)

    Incremental container reader over any readable binary stream, including
    non-seekable ones. The underlying stream is never closed. ``context``
    defaults to ``b""`` and ``max_frame_length`` defaults to
    :data:`DEFAULT_MAX_FRAME_LENGTH`.

    .. method:: read_frame()

        Validate the declared length, read one complete frame and return a
        ``(plaintext, tag)`` tuple, or raise a :class:`ContainerError`
        subclass.

    .. method:: readall()

        Consume every frame and return the full plaintext; returns only
        after the FINAL frame and EOF have both been confirmed.

    .. method:: verify_eof()

        Raise :class:`FinalFrameError` if any byte remains after the FINAL
        frame.

    .. attribute:: final_seen

        Whether the unique FINAL frame has been pulled.

.. function:: encrypt_stream(source, target, key, context, max_frame_length)

    Encrypt ``source`` into ``target`` with bounded short reads. Returns the
    number of plaintext bytes read. ``context`` defaults to ``b""`` and
    ``max_frame_length`` defaults to :data:`DEFAULT_MAX_FRAME_LENGTH`.

.. function:: decrypt_stream(source, target, key, context, scratch, \
                             max_frame_length)

    Strictly decrypt ``source`` into ``target``, buffering plaintext in the
    caller provided, seekable ``scratch`` stream until the FINAL frame and
    EOF are confirmed. Returns the number of plaintext bytes copied.
    ``context`` and ``max_frame_length`` use the same defaults as
    :func:`encrypt_stream`; ``scratch`` is keyword-only.
