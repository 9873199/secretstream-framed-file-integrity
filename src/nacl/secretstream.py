# Copyright 2026 Donald Stufft and individual contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
Versioned, file-object oriented container built on top of libsodium's
``crypto_secretstream_xchacha20poly1305``.

This module adds framing and whole-container integrity rules on top of the
low level secretstream bindings. It does not implement any cryptographic
primitive of its own: every frame is sealed and opened by libsodium.

Container layout (version 1)
----------------------------

A container is the concatenation of::

    magic    (6 bytes): b"NACLSS"
    version  (1 byte):  b"\\x01"
    header   (24 bytes): the libsodium secretstream header
    frame*   : zero or more MESSAGE/REKEY/PUSH frames followed by exactly
               one FINAL frame

Each frame is::

    length     (4 bytes, unsigned big-endian): length of the following
               ciphertext *including* the secretstream ABYTES overhead
    ciphertext (``length`` bytes): the output of secretstream ``push``

The length prefix is always 4 bytes network byte order; integers are never
encoded using platform byte order and no structured serializer (dict, JSON,
pickle, ...) is involved anywhere in the format.

An empty plaintext input still produces exactly one frame, the FINAL frame,
whose plaintext is the empty byte string. Two encryptions of the empty input
under the same key are distinct because libsodium generates a fresh random
header for every stream.

Additional data (AD) bound into every frame
--------------------------------------------

For every frame, both writer and reader pass the following unambiguously
length-prefixed byte string as the secretstream additional data::

    b"nacl.secretstream/1"                         # domain separator
    b"h" + u32be(len(container_header)) + container_header
    b"c" + u32be(len(context)) + context
    b"s" + u64be(sequence_number)
    b"l" + u32be(declared_frame_length)

where ``container_header`` is the exact ``magic + version + header`` byte
sequence stored in the file, ``context`` is the caller supplied byte string,
``sequence_number`` is the zero-based frame counter and
``declared_frame_length`` is the length advertised by the frame being read
or written. All multi-byte integers are big-endian.

Because the container header, the context, the frame sequence number and the
declared frame length are all authenticated, frames cannot be moved between
files (even files encrypted under the same key, including with a different
context), reordered, replayed or silently resized without secretstream
rejecting them when the frame is pulled.

Two reading semantics
---------------------

* :class:`SecretStreamReader` is an *incremental* reader. Each plaintext chunk
  it yields has been individually authenticated by libsodium before it is
  handed out, but chunks having been yielded does **not** prove that the
  whole file is valid: the FINAL frame may still be missing or not be the
  last frame, and trailing data may follow it. Whole-file validity is only
  established once iteration completes, which requires the FINAL frame to
  have been seen exactly once and the source stream to be at EOF.
* :func:`decrypt_stream` is the *strict* entry point. It keeps the
  plaintext in a caller provided seekable scratch stream and never writes
  anything to the real destination until the FINAL frame and EOF have both
  been confirmed.
"""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING, BinaryIO, Iterator

import nacl.bindings as _b
from nacl import exceptions as exc

if TYPE_CHECKING:
    from typing_extensions import Self

#: Fixed magic prefix of every container.
MAGIC: bytes = b"NACLSS"
#: Only container format version understood by this module.
VERSION: bytes = b"\x01"
#: Size of the fixed container header (magic, version, libsodium header).
CONTAINER_HEADER_SIZE: int = (
    len(MAGIC)
    + len(VERSION)
    + _b.crypto_secretstream_xchacha20poly1305_HEADERBYTES
)
#: Size of the length prefix in front of every frame.
LENGTH_PREFIX_SIZE: int = 4

#: Largest frame length (ciphertext length, ABYTES included) that the 4 byte
#: length prefix can encode, intersected with the libsodium message limit.
CONTAINER_MAX_FRAME_LENGTH: int = min(
    _b.crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX
    + _b.crypto_secretstream_xchacha20poly1305_ABYTES,
    0xFFFFFFFF,
)
#: Default upper bound on a frame length (64 KiB plaintext + ABYTES).
DEFAULT_MAX_FRAME_LENGTH: int = (
    64 * 1024 + _b.crypto_secretstream_xchacha20poly1305_ABYTES
)

# Chunk size used when copying the verified scratch stream to the target.
_COPY_CHUNK_SIZE: int = 64 * 1024

_AD_DOMAIN: bytes = b"nacl.secretstream/1"


class ContainerError(exc.CryptoError):
    """Base class for every container level failure."""


class ContainerFormatError(ContainerError):
    """
    The byte stream does not conform to the container layout (bad magic or
    version, truncated header or frame, frame length outside the negotiated
    bounds).
    """


class FrameAuthenticationError(ContainerError):
    """
    A frame failed libsodium authentication. This covers a wrong key or
    context, a corrupted or modified frame, reordered frames and frames
    spliced from a different container.
    """


class FinalFrameError(ContainerError):
    """
    The rules around the FINAL frame were violated: it is missing, appears
    more than once, is not the last frame, or trailing data follows it.
    """


class ContainerStateError(ContainerError):
    """
    The container object was used after its stream had already been
    finalized.
    """


def _check_context(context: object) -> bytes:
    if not isinstance(context, bytes):
        raise exc.TypeError("context must be a bytes object")
    return context


def _check_max_frame_length(max_frame_length: object) -> int:
    if isinstance(max_frame_length, bool) or not isinstance(
        max_frame_length, int
    ):
        raise exc.TypeError("max_frame_length must be an int")
    if max_frame_length <= _b.crypto_secretstream_xchacha20poly1305_ABYTES:
        raise exc.ValueError(
            "max_frame_length must be greater than "
            f"{_b.crypto_secretstream_xchacha20poly1305_ABYTES} (ABYTES): "
            "the declared length includes the authentication tag and every "
            "non-final frame must be able to carry at least one plaintext "
            "byte",
        )
    if max_frame_length > CONTAINER_MAX_FRAME_LENGTH:
        raise exc.ValueError(
            f"max_frame_length must not exceed {CONTAINER_MAX_FRAME_LENGTH}",
        )
    return max_frame_length


def _build_ad(
    container_header: bytes,
    context: bytes,
    sequence: int,
    declared_length: int,
) -> bytes:
    return b"".join(
        (
            _AD_DOMAIN,
            b"h",
            struct.pack(">I", len(container_header)),
            container_header,
            b"c",
            struct.pack(">I", len(context)),
            context,
            b"s",
            struct.pack(">Q", sequence),
            b"l",
            struct.pack(">I", declared_length),
        )
    )


def _read_exact(stream: BinaryIO, size: int, what: str) -> bytes:
    """Read exactly ``size`` bytes or raise :class:`ContainerFormatError`."""
    chunks: list[bytes] = []
    remaining = size
    while remaining > 0:
        chunk = stream.read(remaining)
        if not isinstance(chunk, bytes):
            raise exc.TypeError(
                f"{what} expected bytes from stream.read(), got "
                f"{type(chunk).__name__}",
            )
        if len(chunk) == 0:
            got = size - remaining
            raise ContainerFormatError(
                f"truncated {what}: expected {size} bytes, got {got}",
            )
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


class SecretStreamWriter:
    """
    Incremental writer for a versioned secretstream container.

    The writer owns the secretstream state and framing; the underlying
    output stream is owned by the caller and is never closed by this class.

    :param stream: a writable binary stream receiving the container.
    :param key: a ``crypto_secretstream_xchacha20poly1305`` key,
        :data:`nacl.bindings.crypto_secretstream_xchacha20poly1305_KEYBYTES`
        long.
    :param context: optional caller defined bytes authenticated into every
        frame. Readers must pass the identical value.
    :param max_frame_length: maximum ciphertext length of a single frame,
        ABYTES included. Must be an int between
        :data:`nacl.bindings.crypto_secretstream_xchacha20poly1305_ABYTES`
        and :data:`CONTAINER_MAX_FRAME_LENGTH`.
    """

    def __init__(
        self,
        stream: BinaryIO,
        key: bytes,
        context: bytes = b"",
        max_frame_length: int = DEFAULT_MAX_FRAME_LENGTH,
    ) -> None:
        if not hasattr(stream, "write"):
            raise exc.TypeError("stream must be a writable binary stream")
        context = _check_context(context)
        max_frame_length = _check_max_frame_length(max_frame_length)

        self._stream = stream
        self._context = context
        self._max_frame_length = max_frame_length
        # Plaintext bytes that fit in one MESSAGE frame.
        self._chunk_size = (
            max_frame_length - _b.crypto_secretstream_xchacha20poly1305_ABYTES
        )

        state = _b.crypto_secretstream_xchacha20poly1305_state()
        sodium_header = _b.crypto_secretstream_xchacha20poly1305_init_push(
            state, key
        )
        self._state = state
        self._container_header = MAGIC + VERSION + sodium_header
        stream.write(self._container_header)

        self._buffer = bytearray()
        self._sequence = 0
        self._bytes_written = 0
        self._frames_written = 0
        self._finished = False

    @property
    def max_frame_length(self) -> int:
        """Configured upper bound of a frame length (ABYTES included)."""
        return self._max_frame_length

    @property
    def chunk_size(self) -> int:
        """Maximum plaintext bytes carried by a non-final frame."""
        return self._chunk_size

    @property
    def frames_written(self) -> int:
        """Number of frames emitted so far, FINAL included."""
        return self._frames_written

    @property
    def bytes_written(self) -> int:
        """Number of plaintext bytes handed to the writer."""
        return self._bytes_written

    @property
    def finished(self) -> bool:
        """Whether :meth:`finish` already wrote the FINAL frame."""
        return self._finished

    def _push_frame(self, plaintext: bytes, tag: int) -> None:
        ad = _build_ad(
            self._container_header,
            self._context,
            self._sequence,
            len(plaintext) + _b.crypto_secretstream_xchacha20poly1305_ABYTES,
        )
        ciphertext = _b.crypto_secretstream_xchacha20poly1305_push(
            self._state, plaintext, ad, tag
        )
        self._stream.write(struct.pack(">I", len(ciphertext)))
        self._stream.write(ciphertext)
        self._sequence += 1
        self._frames_written += 1

    def write(self, data: bytes) -> int:
        """
        Buffer ``data`` and emit as many full MESSAGE frames as possible.

        Short writes are handled naturally: frames are only emitted when a
        full chunk of plaintext is available, the remainder stays buffered
        until the next call or :meth:`finish`. Returns the number of
        plaintext bytes accepted.
        """
        if self._finished:
            raise ContainerStateError(
                "cannot write after the FINAL frame has been emitted",
            )
        if not isinstance(data, bytes):
            raise exc.TypeError("data must be a bytes object")
        view = memoryview(data)
        self._buffer.extend(view)
        self._bytes_written += len(view)
        while len(self._buffer) >= self._chunk_size:
            chunk = bytes(self._buffer[: self._chunk_size])
            del self._buffer[: self._chunk_size]
            self._push_frame(
                chunk,
                _b.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE,
            )
        return len(view)

    def rekey(self) -> None:
        """
        Force a secretstream rekey at the next frame boundary.

        Any buffered plaintext is first sealed into its own frame and the
        frame is pushed with libsodium's ``TAG_REKEY`` tag, so the rekey
        boundary always falls between two complete frames. Because the tag
        travels inside the authenticated frame, readers follow the rekey
        automatically; no out-of-band state synchronization is needed.
        """
        if self._finished:
            raise ContainerStateError(
                "cannot rekey after the FINAL frame has been emitted",
            )
        chunk = bytes(self._buffer)
        self._buffer.clear()
        self._push_frame(
            chunk,
            _b.crypto_secretstream_xchacha20poly1305_TAG_REKEY,
        )

    def finish(self) -> None:
        """
        Emit the unique FINAL frame and mark the container complete.

        The FINAL frame carries whatever buffered plaintext remains, which
        may be zero bytes. In particular an empty input produces a single
        empty FINAL frame. Idempotent: calling it again is a no-op.
        """
        if self._finished:
            return
        self._push_frame(
            bytes(self._buffer),
            _b.crypto_secretstream_xchacha20poly1305_TAG_FINAL,
        )
        self._buffer.clear()
        self._finished = True

    def close(self) -> None:
        """
        Ensure the FINAL frame was written. The underlying stream is *not*
        closed: its lifecycle remains the caller's responsibility.
        """
        self.finish()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        # If the ``with`` block raised, do not attach a FINAL frame: that
        # would turn an aborted, partial stream into an authenticated one.
        if exc_type is None:
            self.finish()


class SecretStreamReader:
    """
    Incremental reader for a versioned secretstream container.

    Iterating over the reader yields authenticated plaintext chunks, one per
    container frame (the FINAL frame's plaintext included). A yielded chunk
    has individually passed libsodium authentication, but the whole file is
    only proven valid once iteration completes: exhaustion additionally
    requires the FINAL frame to have been seen exactly once and confirms that
    the source stream is at EOF. Use :meth:`readall` or
    :func:`decrypt_stream` for a whole-file guarantee.

    The underlying input stream is owned by the caller and is never closed.

    :param stream: a readable binary stream positioned at the start of the
        container. It does not need to be seekable.
    :param key: the secretstream key used to encrypt the container.
    :param context: the same bytes that were given to the writer.
    :param max_frame_length: maximum accepted frame length, ABYTES included.
        Declared lengths are checked against this bound *before* any
        allocation or read of the frame body.
    """

    def __init__(
        self,
        stream: BinaryIO,
        key: bytes,
        context: bytes = b"",
        max_frame_length: int = DEFAULT_MAX_FRAME_LENGTH,
    ) -> None:
        if not hasattr(stream, "read"):
            raise exc.TypeError("stream must be a readable binary stream")
        context = _check_context(context)
        max_frame_length = _check_max_frame_length(max_frame_length)

        self._stream = stream
        self._context = context
        self._max_frame_length = max_frame_length

        header = _read_exact(stream, CONTAINER_HEADER_SIZE, "container header")
        magic_size = len(MAGIC)
        if header[:magic_size] != MAGIC:
            raise ContainerFormatError("bad container magic")
        if header[magic_size : magic_size + len(VERSION)] != VERSION:
            raise ContainerFormatError("unsupported container version")
        sodium_header = header[magic_size + len(VERSION) :]
        self._container_header = header

        self._state = _b.crypto_secretstream_xchacha20poly1305_state()
        # A wrong key is not detected here; the first authenticated pull
        # below fails instead.
        _b.crypto_secretstream_xchacha20poly1305_init_pull(
            self._state, sodium_header, key
        )

        self._sequence = 0
        self._final_seen = False
        self._frames_read = 0

    @property
    def max_frame_length(self) -> int:
        """Configured upper bound of an accepted frame length."""
        return self._max_frame_length

    @property
    def frames_read(self) -> int:
        """Number of frames successfully pulled so far, FINAL included."""
        return self._frames_read

    @property
    def final_seen(self) -> bool:
        """Whether the unique FINAL frame has been pulled."""
        return self._final_seen

    def read_frame(self) -> tuple[bytes, int]:
        """
        Pull one complete frame and return ``(plaintext, tag)``.

        The declared length is fully validated before the frame body is
        read, so a hostile length field can only trigger reads up to the
        configured ``max_frame_length``. Authentication failures, including
        reordered or cross-container frames, raise
        :class:`FrameAuthenticationError`; a clean EOF before any FINAL
        frame raises :class:`FinalFrameError`.
        """
        if self._final_seen:
            raise FinalFrameError(
                "a frame follows the FINAL frame; FINAL must be last",
            )

        # Read the prefix one byte at a time first, so a clean EOF is
        # distinguishable from a prefix cut off mid-stream. _read_exact
        # below keeps this correct for sources that return short reads.
        first = self._stream.read(1)
        if not isinstance(first, bytes):
            raise exc.TypeError(
                "expected bytes from stream.read(), got "
                f"{type(first).__name__}",
            )
        if len(first) == 0:
            # Clean EOF: the container ended without a FINAL frame.
            raise FinalFrameError(
                "container ended before the FINAL frame",
            )
        prefix = first + _read_exact(
            self._stream, LENGTH_PREFIX_SIZE - 1, "frame length prefix"
        )
        declared_length: int = int.from_bytes(
            prefix, byteorder="big", signed=False
        )
        if declared_length < _b.crypto_secretstream_xchacha20poly1305_ABYTES:
            raise ContainerFormatError(
                "declared frame length "
                f"{declared_length} is below ABYTES "
                f"({_b.crypto_secretstream_xchacha20poly1305_ABYTES})",
            )
        if declared_length > self._max_frame_length:
            raise ContainerFormatError(
                f"declared frame length {declared_length} exceeds the "
                f"configured maximum {self._max_frame_length}",
            )

        ciphertext = _read_exact(self._stream, declared_length, "frame body")
        ad = _build_ad(
            self._container_header,
            self._context,
            self._sequence,
            declared_length,
        )
        try:
            plaintext, tag = _b.crypto_secretstream_xchacha20poly1305_pull(
                self._state, ciphertext, ad
            )
        except exc.RuntimeError as e:
            raise FrameAuthenticationError(
                "secretstream rejected the frame (wrong key or context, "
                "corruption, reordering or a frame from another container)",
            ) from e

        if tag not in (
            _b.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE,
            _b.crypto_secretstream_xchacha20poly1305_TAG_PUSH,
            _b.crypto_secretstream_xchacha20poly1305_TAG_REKEY,
            _b.crypto_secretstream_xchacha20poly1305_TAG_FINAL,
        ):
            raise ContainerFormatError(f"unknown secretstream tag {tag}")

        self._sequence += 1
        self._frames_read += 1
        if tag == _b.crypto_secretstream_xchacha20poly1305_TAG_FINAL:
            self._final_seen = True
        return plaintext, tag

    def verify_eof(self) -> None:
        """
        Confirm no bytes remain in the source after the FINAL frame.

        Raises :class:`FinalFrameError` on trailing data. Only meaningful
        after :attr:`final_seen` is true.
        """
        trailing = self._stream.read(1)
        if trailing:
            raise FinalFrameError(
                "trailing data after the FINAL frame",
            )

    def __iter__(self) -> Iterator[bytes]:
        return self

    def __next__(self) -> bytes:
        if self._final_seen:
            # The FINAL frame was already yielded on the previous call;
            # exhaustion requires EOF to be confirmed.
            self.verify_eof()
            raise StopIteration
        plaintext, _tag = self.read_frame()
        return plaintext

    def readall(self) -> bytes:
        """
        Consume every frame and return the full plaintext.

        This returns only after the FINAL frame has been seen exactly once
        and EOF has been confirmed, so a successful return proves the whole
        container is valid.
        """
        return b"".join(self)


def _scrub_scratch(scratch: BinaryIO) -> None:
    scratch.seek(0)
    scratch.truncate(0)


def encrypt_stream(
    source: BinaryIO,
    target: BinaryIO,
    key: bytes,
    context: bytes = b"",
    max_frame_length: int = DEFAULT_MAX_FRAME_LENGTH,
) -> int:
    """
    Encrypt ``source`` into ``target`` using bounded short reads.

    The source only needs to be readable (it may be a non-seekable pipe);
    each read requests at most the writer's plaintext chunk size and short
    reads are simply retried on the next loop. The target is never closed.

    :return: the number of plaintext bytes read from the source.
    """
    if not hasattr(source, "read"):
        raise exc.TypeError("source must be a readable binary stream")
    if not hasattr(target, "write"):
        raise exc.TypeError("target must be a writable binary stream")
    writer = SecretStreamWriter(target, key, context, max_frame_length)
    total = 0
    while True:
        chunk = source.read(writer.chunk_size)
        if not isinstance(chunk, bytes):
            raise exc.TypeError(
                "expected bytes from source.read(), got "
                f"{type(chunk).__name__}",
            )
        if len(chunk) == 0:
            break
        writer.write(chunk)
        total += len(chunk)
    writer.finish()
    return total


def decrypt_stream(
    source: BinaryIO,
    target: BinaryIO,
    key: bytes,
    context: bytes = b"",
    *,
    scratch: BinaryIO,
    max_frame_length: int = DEFAULT_MAX_FRAME_LENGTH,
) -> int:
    """
    Strictly decrypt a container and commit the plaintext to ``target``.

    The plaintext is first written to the caller provided, seekable
    ``scratch`` stream. Nothing at all is written to ``target`` until every
    frame has been authenticated, the FINAL frame has been seen exactly
    once and EOF on the source has been confirmed. On any container failure
    the target therefore receives zero writes from this function and the
    scratch stream is scrubbed (seeked back and truncated) before the
    exception propagates.

    ``source``, ``target`` and ``scratch`` are never closed by this
    function; their lifecycle is the caller's responsibility. The source
    does not need to be seekable, the scratch stream does.

    Ordinary output streams provide no atomic rollback: if a scratch write
    fails, or if the final copy into ``target`` fails after verification
    (for example because the destination disk is full), the underlying
    :exc:`OSError` is propagated as-is and ``target`` may already hold
    partial plaintext. The zero-write guarantee only covers failures
    detected while the container itself is being verified.

    :return: the number of plaintext bytes copied to ``target``.
    """
    if not hasattr(source, "read"):
        raise exc.TypeError("source must be a readable binary stream")
    if not hasattr(target, "write"):
        raise exc.TypeError("target must be a writable binary stream")
    for attr in ("read", "write", "seek", "tell", "truncate"):
        if not hasattr(scratch, attr):
            raise exc.TypeError(
                "scratch must be a seekable, truncatable binary stream "
                f"(missing {attr})",
            )

    reader = SecretStreamReader(source, key, context, max_frame_length)
    total = 0
    try:
        for chunk in reader:
            scratch.write(chunk)
            total += len(chunk)
        # Iterating to completion has pulled the FINAL frame and confirmed
        # EOF on the source.
        if not reader.final_seen:
            raise FinalFrameError(
                "container ended before the FINAL frame",
            )
    except BaseException:
        _scrub_scratch(scratch)
        raise

    # Container fully verified: only now may the target be touched.
    try:
        scratch.seek(0)
        while True:
            chunk = scratch.read(_COPY_CHUNK_SIZE)
            if not chunk:
                break
            target.write(chunk)
    except BaseException:
        _scrub_scratch(scratch)
        raise
    _scrub_scratch(scratch)
    return total
