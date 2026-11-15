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

from __future__ import annotations

import inspect
import io
import struct
from typing import BinaryIO, cast

import pytest
from hypothesis import given
from hypothesis import strategies as st

import nacl.secretstream as ss
from nacl.bindings import (
    crypto_secretstream_xchacha20poly1305_ABYTES as ABYTES,
)
from nacl.bindings import (
    crypto_secretstream_xchacha20poly1305_HEADERBYTES,
    crypto_secretstream_xchacha20poly1305_init_pull,
    crypto_secretstream_xchacha20poly1305_keygen,
    crypto_secretstream_xchacha20poly1305_pull,
    crypto_secretstream_xchacha20poly1305_state,
    crypto_secretstream_xchacha20poly1305_TAG_FINAL,
    crypto_secretstream_xchacha20poly1305_TAG_MESSAGE,
)
from nacl.exceptions import CryptoError
from nacl.exceptions import TypeError as NaclTypeError
from nacl.exceptions import ValueError as NaclValueError

# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


class ShortReader:
    """Readable, non-seekable stream that always returns short reads."""

    def __init__(self, data: bytes, max_return: int = 1) -> None:
        self._buf = io.BytesIO(data)
        self.max_return = max_return
        self.read_sizes: list[int] = []

    def read(self, size: int = -1) -> bytes:
        self.read_sizes.append(size)
        if size is None or size < 0:
            return self._buf.read()
        return self._buf.read(min(size, self.max_return))


class NonSeekableWriter:
    def __init__(self) -> None:
        self.parts: list[bytes] = []
        self.closed = False

    def write(self, data: bytes) -> int:
        self.parts.append(bytes(data))
        return len(data)

    def close(self) -> None:  # must never be called by the library
        self.closed = True


class CloseTrackingBytesIO(io.BytesIO):
    def __init__(self, initial: bytes = b"") -> None:
        super().__init__(initial)
        self.close_count = 0

    def close(self) -> None:
        self.close_count += 1


class FailingScratch:
    """Seekable scratch whose write fails after ``succeed_writes`` writes."""

    def __init__(self, succeed_writes: int = 0) -> None:
        self.succeed_writes = succeed_writes
        self.writes = 0
        self.truncated = False

    def write(self, data: bytes) -> int:
        self.writes += 1
        if self.writes > self.succeed_writes:
            raise OSError("scratch disk full")
        return len(data)

    def seek(self, offset: int, whence: int = 0) -> int:
        return 0

    def tell(self) -> int:
        return 0

    def truncate(self, size: int | None = None) -> int:
        self.truncated = True
        return 0

    def read(self, size: int = -1) -> bytes:
        return b""


class FailingTarget:
    def __init__(self, fail_after: int) -> None:
        self.fail_after = fail_after
        self.written: list[bytes] = []

    def write(self, data: bytes) -> int:
        if len(self.written) >= self.fail_after:
            raise OSError("target disk full")
        self.written.append(bytes(data))
        return len(data)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_container(
    payload: bytes,
    key: bytes,
    context: bytes = b"",
    max_frame_length: int = ss.DEFAULT_MAX_FRAME_LENGTH,
) -> bytes:
    out = io.BytesIO()
    n = ss.encrypt_stream(
        io.BytesIO(payload), out, key, context, max_frame_length
    )
    assert n == len(payload)
    return out.getvalue()


def parse_frames(blob: bytes) -> list[tuple[int, bytes]]:
    """Split a container into (declared_length, ciphertext) frames."""
    assert blob[: len(ss.MAGIC)] == ss.MAGIC
    assert blob[len(ss.MAGIC) : len(ss.MAGIC) + 1] == ss.VERSION
    pos = ss.CONTAINER_HEADER_SIZE
    frames: list[tuple[int, bytes]] = []
    while pos < len(blob):
        (declared,) = struct.unpack(">I", blob[pos : pos + 4])
        pos += 4
        body = blob[pos : pos + declared]
        assert len(body) == declared
        pos += declared
        frames.append((declared, body))
    assert pos == len(blob)
    return frames


def rebuild(frames: list[tuple[int, bytes]]) -> bytes:
    out = bytearray()
    for declared, body in frames:
        out += struct.pack(">I", declared)
        out += body
    return bytes(out)


def splice(blob: bytes, frames: list[tuple[int, bytes]]) -> bytes:
    return blob[: ss.CONTAINER_HEADER_SIZE] + rebuild(frames)


@pytest.fixture
def key() -> bytes:
    return crypto_secretstream_xchacha20poly1305_keygen()


# ---------------------------------------------------------------------------
# Container layout
# ---------------------------------------------------------------------------


def test_container_header_layout(key: bytes) -> None:
    blob = make_container(b"", key)
    assert blob[:6] == b"NACLSS"
    assert blob[6:7] == b"\x01"
    assert ss.MAGIC == b"NACLSS"
    assert ss.VERSION == b"\x01"
    assert (
        ss.CONTAINER_HEADER_SIZE
        == 6 + 1 + crypto_secretstream_xchacha20poly1305_HEADERBYTES
    )
    # 31 byte header, one length prefix and one ABYTES sized FINAL frame.
    assert len(blob) == (ss.CONTAINER_HEADER_SIZE + 4 + ABYTES)


def test_empty_input_has_unique_empty_final(key: bytes) -> None:
    blob = make_container(b"", key, context=b"ctx")
    frames = parse_frames(blob)
    assert len(frames) == 1
    declared, body = frames[0]
    assert declared == ABYTES

    state = crypto_secretstream_xchacha20poly1305_state()
    sodium_header = blob[
        7 : 7 + crypto_secretstream_xchacha20poly1305_HEADERBYTES
    ]
    crypto_secretstream_xchacha20poly1305_init_pull(state, sodium_header, key)
    ad = ss._build_ad(blob[: ss.CONTAINER_HEADER_SIZE], b"ctx", 0, ABYTES)
    plaintext, tag = crypto_secretstream_xchacha20poly1305_pull(
        state, body, ad
    )
    assert plaintext == b""
    assert tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL


def test_two_empty_containers_have_distinct_headers(key: bytes) -> None:
    first = make_container(b"", key)
    second = make_container(b"", key)
    assert first != second
    # Only the random libsodium header differs; framing is identical.
    assert first[:7] == second[:7]
    assert (
        first[7 : ss.CONTAINER_HEADER_SIZE]
        != second[7 : ss.CONTAINER_HEADER_SIZE]
    )


def test_chunking_boundaries(key: bytes) -> None:
    max_len = ABYTES + 3  # at most 3 plaintext bytes per frame
    # payload smaller than one chunk: only the FINAL frame
    small = make_container(b"ab", key, max_frame_length=max_len)
    assert len(parse_frames(small)) == 1

    # payload exactly one chunk: one MESSAGE frame plus the FINAL frame
    exact = make_container(b"abc", key, max_frame_length=max_len)
    frames = parse_frames(exact)
    assert len(frames) == 2
    assert frames[0][0] == max_len
    assert frames[1][0] == ABYTES  # empty FINAL

    # payload spanning several chunks
    many = make_container(b"abcdefgh", key, max_frame_length=max_len)
    frames = parse_frames(many)
    assert len(frames) == 3  # MESSAGE abc, MESSAGE def, FINAL gh
    assert frames[-1][0] == ABYTES + 2


def test_short_reads_are_bounded_and_respected(key: bytes) -> None:
    payload = bytes(range(251))
    source = ShortReader(payload, max_return=2)
    out = io.BytesIO()
    writer = ss.SecretStreamWriter(out, key, b"", max_frame_length=ABYTES + 7)
    # encrypt_stream-style loop, driven manually against the short reader
    total = 0
    while True:
        chunk = source.read(writer.chunk_size)
        if not chunk:
            break
        writer.write(chunk)
        total += len(chunk)
    writer.finish()
    assert total == len(payload)
    # the reader must never ask for more than the negotiated chunk size
    assert all(size <= writer.chunk_size for size in source.read_sizes)

    dec = io.BytesIO()
    ss.decrypt_stream(
        io.BytesIO(out.getvalue()), dec, key, scratch=io.BytesIO()
    )
    assert dec.getvalue() == payload


def test_encrypt_stream_accepts_nonseekable_source(key: bytes) -> None:
    payload = b"x" * 100
    source = ShortReader(payload, max_return=5)
    target = NonSeekableWriter()
    n = ss.encrypt_stream(
        cast(BinaryIO, source),
        cast(BinaryIO, target),
        key,
        b"ns",
        max_frame_length=ABYTES + 9,
    )
    assert n == len(payload)
    assert not target.closed

    blob = b"".join(target.parts)
    dec = CloseTrackingBytesIO()
    ss.decrypt_stream(
        cast(BinaryIO, ShortReader(blob)),
        dec,
        key,
        b"ns",
        scratch=io.BytesIO(),
        max_frame_length=ABYTES + 9,
    )
    assert dec.getvalue() == payload
    assert dec.close_count == 0


# ---------------------------------------------------------------------------
# Constructor validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad", [bytearray(b"x"), None, 1024, "ctx"])
def test_context_must_be_bytes(key: bytes, bad: object) -> None:
    with pytest.raises(NaclTypeError):
        ss.SecretStreamWriter(io.BytesIO(), key, bad)  # type: ignore[arg-type]
    with pytest.raises(NaclTypeError):
        ss.SecretStreamReader(io.BytesIO(b"x" * 40), key, bad)  # type: ignore[arg-type]


def test_max_frame_length_bounds(key: bytes) -> None:
    # must be an int, and bool must not sneak through
    with pytest.raises(NaclTypeError):
        ss.SecretStreamWriter(io.BytesIO(), key, max_frame_length=True)
    with pytest.raises(NaclTypeError):
        ss.SecretStreamWriter(io.BytesIO(), key, max_frame_length=1024.0)  # type: ignore[arg-type]

    # ABYTES itself leaves no room for plaintext in a MESSAGE frame
    with pytest.raises(NaclValueError):
        ss.SecretStreamWriter(io.BytesIO(), key, max_frame_length=ABYTES)
    with pytest.raises(NaclValueError):
        ss.SecretStreamWriter(io.BytesIO(), key, max_frame_length=ABYTES - 1)

    with pytest.raises(NaclValueError):
        ss.SecretStreamWriter(
            io.BytesIO(),
            key,
            max_frame_length=ss.CONTAINER_MAX_FRAME_LENGTH + 1,
        )

    # the smallest legal value works
    w = ss.SecretStreamWriter(io.BytesIO(), key, max_frame_length=ABYTES + 1)
    assert w.chunk_size == 1


def test_max_frame_length_tracks_library_limit(
    key: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ss, "CONTAINER_MAX_FRAME_LENGTH", 100)
    with pytest.raises(NaclValueError):
        ss.SecretStreamWriter(io.BytesIO(), key, max_frame_length=101)
    w = ss.SecretStreamWriter(io.BytesIO(), key, max_frame_length=100)
    assert w.max_frame_length == 100


def test_default_frame_length_within_safe_range() -> None:
    assert ss.DEFAULT_MAX_FRAME_LENGTH <= ss.CONTAINER_MAX_FRAME_LENGTH
    assert ss.DEFAULT_MAX_FRAME_LENGTH == 64 * 1024 + ABYTES


# ---------------------------------------------------------------------------
# AD binding: context, header, sequence, declared length
# ---------------------------------------------------------------------------


def test_wrong_context_is_rejected(key: bytes) -> None:
    blob = make_container(b"secret" * 10, key, context=b"context-A")
    with pytest.raises(ss.FrameAuthenticationError):
        ss.SecretStreamReader(
            io.BytesIO(blob), key, context=b"context-B"
        ).readall()
    # the empty context is a context like any other
    with pytest.raises(ss.FrameAuthenticationError):
        ss.SecretStreamReader(io.BytesIO(blob), key).readall()


def test_contexts_with_structured_bytes_remain_distinct(key: bytes) -> None:
    # contexts deliberately containing the AD field markers and integer
    # looking bytes; the length prefixes keep the encoding unambiguous
    contexts = [b"", b"h", b"c", b"h\x00\x00\x00\x05hello", b"hh", b"h\x00"]
    blobs = [make_container(b"data", key, context=c) for c in contexts]
    for i, blob in enumerate(blobs):
        for j, context in enumerate(contexts):
            reader = ss.SecretStreamReader(io.BytesIO(blob), key, context)
            if i == j:
                assert reader.readall() == b"data"
            else:
                with pytest.raises(ss.FrameAuthenticationError):
                    reader.readall()


def test_frames_cannot_cross_files_with_different_context(key: bytes) -> None:
    blob_a = make_container(b"same plaintext", key, context=b"A")
    blob_b = make_container(b"same plaintext", key, context=b"B")
    frames_b = parse_frames(blob_b)
    tampered = splice(blob_a, frames_b)
    with pytest.raises(ss.FrameAuthenticationError):
        ss.SecretStreamReader(
            io.BytesIO(tampered), key, context=b"A"
        ).readall()


def test_frames_cannot_cross_files_with_same_context(key: bytes) -> None:
    # identical key *and* context: the container header in the AD still
    # binds frames to their own stream
    blob_a = make_container(b"same plaintext", key, context=b"ctx")
    blob_b = make_container(b"same plaintext", key, context=b"ctx")
    frames_b = parse_frames(blob_b)
    tampered = splice(blob_a, frames_b)
    with pytest.raises(ss.FrameAuthenticationError):
        ss.SecretStreamReader(
            io.BytesIO(tampered), key, context=b"ctx"
        ).readall()


def test_frame_reorder_is_rejected(key: bytes) -> None:
    blob = make_container(
        b"0123456789abcdef", key, max_frame_length=ABYTES + 2
    )
    frames = parse_frames(blob)
    assert len(frames) >= 3
    frames[0], frames[1] = frames[1], frames[0]
    tampered = splice(blob, frames)
    with pytest.raises(ss.FrameAuthenticationError):
        ss.SecretStreamReader(
            io.BytesIO(tampered), key, max_frame_length=ABYTES + 2
        ).readall()


def test_frame_replay_is_rejected(key: bytes) -> None:
    blob = make_container(b"0123456789", key, max_frame_length=ABYTES + 2)
    frames = parse_frames(blob)
    # replay the first MESSAGE frame a second time
    tampered = splice(blob, [frames[0], frames[0]] + frames[1:])
    with pytest.raises(ss.FrameAuthenticationError):
        ss.SecretStreamReader(
            io.BytesIO(tampered), key, max_frame_length=ABYTES + 2
        ).readall()


def test_declared_length_is_authenticated(key: bytes) -> None:
    # generous frame cap so a tampered length stays an allocatable frame
    # and the failure must come from the AD mismatch, not the length check
    max_len = ABYTES + 100
    # two frames: a full MESSAGE frame and a non-full FINAL frame
    blob = bytearray(make_container(b"a" * 150, key, max_frame_length=max_len))
    frames = parse_frames(bytes(blob))
    assert len(frames) == 2
    # append one spare byte the lying FINAL frame can swallow
    blob += b"\x00"
    # lie about the FINAL frame length, keeping the same frame body
    final_pos = ss.CONTAINER_HEADER_SIZE + 4 + frames[0][0]
    original = frames[1][0]
    assert original < max_len
    struct.pack_into(">I", blob, final_pos, original + 1)
    with pytest.raises(ss.FrameAuthenticationError):
        ss.SecretStreamReader(
            io.BytesIO(bytes(blob)), key, max_frame_length=max_len
        ).readall()


def test_wrong_key_is_authentication_failure(key: bytes) -> None:
    blob = make_container(b"abcd", key)
    other = crypto_secretstream_xchacha20poly1305_keygen()
    with pytest.raises(ss.FrameAuthenticationError):
        ss.SecretStreamReader(io.BytesIO(blob), other).readall()


def test_ciphertext_mutation_is_rejected(key: bytes) -> None:
    blob = bytearray(
        make_container(b"abcdefgh", key, max_frame_length=ABYTES + 2)
    )
    # flip a byte inside the first frame body
    pos = ss.CONTAINER_HEADER_SIZE + 4 + 3
    blob[pos] ^= 0x01
    with pytest.raises(ss.FrameAuthenticationError):
        ss.SecretStreamReader(
            io.BytesIO(bytes(blob)), key, max_frame_length=ABYTES + 2
        ).readall()


# ---------------------------------------------------------------------------
# Reader framing and FINAL rules
# ---------------------------------------------------------------------------


def test_bad_magic_and_version(key: bytes) -> None:
    blob = bytearray(make_container(b"abcd", key))
    blob[0] ^= 0x01
    with pytest.raises(ss.ContainerFormatError):
        ss.SecretStreamReader(io.BytesIO(bytes(blob)), key)
    blob = bytearray(make_container(b"abcd", key))
    blob[6] = 0x02
    with pytest.raises(ss.ContainerFormatError):
        ss.SecretStreamReader(io.BytesIO(bytes(blob)), key)


def test_empty_file_is_format_error(key: bytes) -> None:
    with pytest.raises(ss.ContainerFormatError):
        ss.SecretStreamReader(io.BytesIO(b""), key)


def test_declared_length_checked_before_body_read(key: bytes) -> None:
    blob = make_container(b"abcd", key, max_frame_length=ABYTES + 4)

    class PrefixProbe:
        def __init__(self, data: bytes) -> None:
            self._io = io.BytesIO(data)
            self.calls: list[int] = []

        def read(self, size: int = -1) -> bytes:
            self.calls.append(size)
            return self._io.read(size)

    for evil in (0, ABYTES - 1, ABYTES + 5):
        evil_blob = bytearray(blob)
        struct.pack_into(">I", evil_blob, ss.CONTAINER_HEADER_SIZE, evil)
        probe = PrefixProbe(bytes(evil_blob))
        reader = ss.SecretStreamReader(
            cast(BinaryIO, probe),
            key,
            max_frame_length=ABYTES + 4,
        )
        with pytest.raises(ss.ContainerFormatError):
            reader.read_frame()
        # the header is read in one call, then only the one-byte probe and
        # the remaining three prefix bytes; the frame body must never be
        # read before the length is validated
        assert probe.calls[0] == ss.CONTAINER_HEADER_SIZE
        assert probe.calls[1:] == [1, ss.LENGTH_PREFIX_SIZE - 1]


def test_truncated_length_prefix(key: bytes) -> None:
    blob = make_container(b"abcd", key)
    cut = ss.CONTAINER_HEADER_SIZE + 2
    with pytest.raises(ss.ContainerFormatError):
        ss.SecretStreamReader(io.BytesIO(blob[:cut]), key).read_frame()


def test_truncated_frame_body(key: bytes) -> None:
    blob = make_container(b"abcd", key)
    with pytest.raises(ss.ContainerFormatError):
        ss.SecretStreamReader(io.BytesIO(blob[:-1]), key).readall()


def test_missing_final_frame(key: bytes) -> None:
    max_len = ABYTES + 2
    blob = make_container(b"0123456789", key, max_frame_length=max_len)
    frames = parse_frames(blob)
    # drop the FINAL frame, keeping every MESSAGE frame
    without_final = splice(blob, frames[:-1])
    reader = ss.SecretStreamReader(
        io.BytesIO(without_final), key, max_frame_length=max_len
    )
    with pytest.raises(ss.FinalFrameError):
        reader.readall()
    assert not reader.final_seen


def test_trailing_data_after_final(key: bytes) -> None:
    blob = make_container(b"abcd", key)
    reader = ss.SecretStreamReader(io.BytesIO(blob + b"\x00"), key)
    chunks: list[bytes] = []
    with pytest.raises(ss.FinalFrameError):
        chunks.extend(reader)
    assert b"".join(chunks) == b"abcd"
    assert reader.final_seen


def test_duplicate_final_frame(key: bytes) -> None:
    blob = make_container(b"abcd", key)
    frames = parse_frames(blob)
    duplicated = splice(blob, frames + [frames[-1]])
    reader = ss.SecretStreamReader(io.BytesIO(duplicated), key)
    with pytest.raises(ss.FinalFrameError):
        reader.readall()
    # direct frame access after FINAL is rejected the same way
    with pytest.raises(ss.FinalFrameError):
        reader.read_frame()


def test_truncation_at_every_byte_position(key: bytes) -> None:
    # small container so every prefix length is cheap to exercise
    max_len = ABYTES + 1
    blob = make_container(
        b"abcde", key, context=b"ctx", max_frame_length=max_len
    )
    assert len(blob) < 200
    for cut in range(len(blob)):
        target = io.BytesIO()
        scratch = io.BytesIO()
        with pytest.raises(ss.ContainerError):
            ss.decrypt_stream(
                io.BytesIO(blob[:cut]),
                target,
                key,
                b"ctx",
                scratch=scratch,
                max_frame_length=max_len,
            )
        # strict entry point: target untouched, scratch scrubbed
        assert target.getvalue() == b""
        assert scratch.getvalue() == b""
    # and the untouched full container succeeds
    ok = io.BytesIO()
    ss.decrypt_stream(
        io.BytesIO(blob),
        ok,
        key,
        b"ctx",
        scratch=io.BytesIO(),
        max_frame_length=max_len,
    )
    assert ok.getvalue() == b"abcde"


def test_yielded_chunks_do_not_prove_whole_file(key: bytes) -> None:
    max_len = ABYTES + 2
    blob = make_container(b"0123456789", key, max_frame_length=max_len)
    frames = parse_frames(blob)
    truncated = splice(blob, frames[:-1])  # FINAL removed
    reader = ss.SecretStreamReader(
        io.BytesIO(truncated), key, max_frame_length=max_len
    )
    yielded = b""
    with pytest.raises(ss.FinalFrameError):
        for chunk in reader:
            yielded += chunk
    # real plaintext chunks were produced, but the file was not valid
    assert yielded == b"0123456789"
    assert not reader.final_seen


def test_all_container_errors_are_crypto_errors(key: bytes) -> None:
    for exc_cls in (
        ss.ContainerFormatError,
        ss.FrameAuthenticationError,
        ss.FinalFrameError,
        ss.ContainerStateError,
    ):
        assert issubclass(exc_cls, ss.ContainerError)
        assert issubclass(exc_cls, CryptoError)


# ---------------------------------------------------------------------------
# Strict decryption entry point
# ---------------------------------------------------------------------------


def test_decrypt_stream_zero_target_writes_and_scrubbed_scratch(
    key: bytes,
) -> None:
    blob = make_container(
        b"0123456789", key, b"ctx", max_frame_length=ABYTES + 2
    )
    target = io.BytesIO()
    scratch = io.BytesIO(b"stale contents")
    with pytest.raises(ss.ContainerError):
        ss.decrypt_stream(
            io.BytesIO(blob + b"\x00"),
            target,
            key,
            b"ctx",
            scratch=scratch,
            max_frame_length=ABYTES + 2,
        )
    assert target.getvalue() == b""
    assert scratch.getvalue() == b""


def test_decrypt_stream_does_not_close_any_stream(key: bytes) -> None:
    blob = make_container(b"payload", key)
    source = CloseTrackingBytesIO(blob)
    target = CloseTrackingBytesIO()
    scratch = CloseTrackingBytesIO()
    ss.decrypt_stream(source, target, key, scratch=scratch)
    assert source.close_count == 0
    assert target.close_count == 0
    assert scratch.close_count == 0
    assert target.getvalue() == b"payload"
    assert scratch.getvalue() == b""

    # same guarantee on failure
    source2 = CloseTrackingBytesIO(blob + b"\x00")
    target2 = CloseTrackingBytesIO()
    scratch2 = CloseTrackingBytesIO()
    with pytest.raises(ss.ContainerError):
        ss.decrypt_stream(source2, target2, key, scratch=scratch2)
    assert source2.close_count == 0
    assert target2.close_count == 0
    assert scratch2.close_count == 0


def test_scratch_must_be_seekable(key: bytes) -> None:
    class Bare:
        def read(self, size: int = -1) -> bytes:
            return b""

        def write(self, data: bytes) -> int:
            return 0

    with pytest.raises(NaclTypeError):
        ss.decrypt_stream(
            io.BytesIO(b""),
            io.BytesIO(),
            key,
            scratch=Bare(),  # type: ignore[arg-type]
        )


def test_scratch_write_failure_propagates_and_target_stays_empty(
    key: bytes,
) -> None:
    blob = make_container(b"abcdef", key, max_frame_length=ABYTES + 2)
    target = io.BytesIO()
    with pytest.raises(OSError):
        ss.decrypt_stream(
            io.BytesIO(blob),
            target,
            key,
            scratch=cast(BinaryIO, FailingScratch(succeed_writes=1)),
            max_frame_length=ABYTES + 2,
        )
    assert target.getvalue() == b""


def test_final_copy_failure_is_honest(
    key: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    blob = make_container(b"abcdefghij", key, max_frame_length=ABYTES + 2)
    scratch = io.BytesIO()
    target = FailingTarget(fail_after=1)
    # shrink the copy buffer so the final copy spans several target writes
    monkeypatch.setattr(ss, "_COPY_CHUNK_SIZE", 2)
    # verification succeeds; the subsequent copy fails with the real OSError
    with pytest.raises(OSError):
        ss.decrypt_stream(
            io.BytesIO(blob),
            target,  # type: ignore[arg-type]
            key,
            scratch=scratch,
            max_frame_length=ABYTES + 2,
        )
    # no atomic rollback is promised: partial plaintext may already be there
    assert len(target.written) == 1
    # scratch was still scrubbed
    assert scratch.getvalue() == b""


# ---------------------------------------------------------------------------
# Writer semantics
# ---------------------------------------------------------------------------


def test_writer_finish_is_idempotent(key: bytes) -> None:
    out = io.BytesIO()
    w = ss.SecretStreamWriter(out, key)
    w.write(b"abc")
    w.finish()
    size_after_first = out.tell()
    w.finish()
    w.close()
    assert out.tell() == size_after_first
    assert w.finished
    assert (
        ss.SecretStreamReader(io.BytesIO(out.getvalue()), key).readall()
        == b"abc"
    )


def test_writer_rejects_use_after_final(key: bytes) -> None:
    out = io.BytesIO()
    w = ss.SecretStreamWriter(out, key)
    w.finish()
    with pytest.raises(ss.ContainerStateError):
        w.write(b"x")
    with pytest.raises(ss.ContainerStateError):
        w.rekey()


def test_writer_context_manager(key: bytes) -> None:
    out = io.BytesIO()
    with ss.SecretStreamWriter(out, key, b"c") as w:
        w.write(b"hello")
    blob = out.getvalue()
    assert (
        ss.SecretStreamReader(io.BytesIO(blob), key, b"c").readall()
        == b"hello"
    )

    # an exception in the block must not produce an authenticated FINAL
    # frame
    out2 = io.BytesIO()
    with pytest.raises(RuntimeError), ss.SecretStreamWriter(out2, key) as w:
        w.write(b"partial")
        raise RuntimeError("boom")
    with pytest.raises(ss.ContainerError):
        ss.SecretStreamReader(io.BytesIO(out2.getvalue()), key).readall()


def test_explicit_rekey_roundtrip_and_tags(key: bytes) -> None:
    out = io.BytesIO()
    w = ss.SecretStreamWriter(out, key, b"rk", max_frame_length=ABYTES + 4)
    w.write(b"abcd")  # one full MESSAGE frame
    w.rekey()
    w.write(b"ef")
    w.finish()

    reader = ss.SecretStreamReader(
        io.BytesIO(out.getvalue()), key, b"rk", max_frame_length=ABYTES + 4
    )
    plaintext, tag = reader.read_frame()
    assert plaintext == b"abcd"
    assert tag == crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
    # the buffer was already flushed, so rekey() emits an empty REKEY frame
    from nacl.bindings import (
        crypto_secretstream_xchacha20poly1305_TAG_REKEY,
    )

    plaintext, tag = reader.read_frame()
    assert plaintext == b""
    assert tag == crypto_secretstream_xchacha20poly1305_TAG_REKEY
    # the last buffered chunk is carried by the FINAL frame
    plaintext, tag = reader.read_frame()
    assert plaintext == b"ef"
    assert tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL
    reader.verify_eof()


def test_rekey_with_empty_buffer(key: bytes) -> None:
    out = io.BytesIO()
    with ss.SecretStreamWriter(out, key, max_frame_length=ABYTES + 4) as w:
        w.rekey()
        w.write(b"x")
    assert (
        ss.SecretStreamReader(io.BytesIO(out.getvalue()), key).readall()
        == b"x"
    )


def test_rekey_flushes_partial_buffer_with_rekey_tag(key: bytes) -> None:
    from nacl.bindings import (
        crypto_secretstream_xchacha20poly1305_TAG_REKEY,
    )

    out = io.BytesIO()
    with ss.SecretStreamWriter(out, key, max_frame_length=ABYTES + 4) as w:
        w.write(b"ab")  # partial chunk: stays buffered
        w.rekey()  # must flush "ab" inside the REKEY frame
        w.write(b"c")
    reader = ss.SecretStreamReader(
        io.BytesIO(out.getvalue()), key, max_frame_length=ABYTES + 4
    )
    plaintext, tag = reader.read_frame()
    assert plaintext == b"ab"
    assert tag == crypto_secretstream_xchacha20poly1305_TAG_REKEY
    plaintext, tag = reader.read_frame()
    assert plaintext == b"c"
    assert tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL
    reader.verify_eof()


def test_writer_counters(key: bytes) -> None:
    out = io.BytesIO()
    w = ss.SecretStreamWriter(out, key, max_frame_length=ABYTES + 2)
    w.write(b"abcde")
    assert w.bytes_written == 5
    w.finish()
    # 2+2+1 bytes -> two MESSAGE frames and one FINAL frame
    assert w.frames_written == 3
    assert (
        ss.SecretStreamReader(
            io.BytesIO(out.getvalue()), key, max_frame_length=ABYTES + 2
        ).readall()
        == b"abcde"
    )


# ---------------------------------------------------------------------------
# Property based round trips
# ---------------------------------------------------------------------------


@given(
    payload=st.binary(max_size=400),
    context=st.binary(max_size=20),
    chunk_overhead=st.integers(min_value=1, max_value=37),
)
def test_roundtrip_hypothesis(
    payload: bytes, context: bytes, chunk_overhead: int
) -> None:
    key = crypto_secretstream_xchacha20poly1305_keygen()
    max_len = ABYTES + chunk_overhead
    blob = make_container(payload, key, context, max_len)
    reader = ss.SecretStreamReader(
        io.BytesIO(blob), key, context, max_frame_length=max_len
    )
    assert reader.readall() == payload
    assert reader.final_seen

    target = io.BytesIO()
    scratch = io.BytesIO()
    written = ss.decrypt_stream(
        io.BytesIO(blob),
        target,
        key,
        context,
        scratch=scratch,
        max_frame_length=max_len,
    )
    assert written == len(payload)
    assert target.getvalue() == payload
    assert scratch.getvalue() == b""


# ---------------------------------------------------------------------------
# Hygiene: no logging (which could leak key/plaintext), no network, no
# platform dependent integer encoding.
# ---------------------------------------------------------------------------


def test_module_never_logs_secrets() -> None:
    source = inspect.getsource(ss)
    assert "import logging" not in source
    assert "logging." not in source
    # all integer serialization is explicit big-endian; never native or
    # little-endian encoding
    assert 'struct.pack(">I"' in source
    assert 'struct.pack(">Q"' in source
    assert "int.from_bytes(" in source
    assert 'byteorder="big"' in source
    assert 'struct.pack("=' not in source
    assert 'struct.pack("<' not in source
    assert 'byteorder="little"' not in source
    # no structured serializers or networking primitives are imported
    for forbidden in (
        "import json",
        "import pickle",
        "import marshal",
        "import socket",
        "import urllib",
        "from http",
    ):
        assert forbidden not in source
