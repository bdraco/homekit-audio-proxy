"""Tests for the SRTP encryption context."""

from __future__ import annotations

import base64
import os
import struct

from homekit_audio_proxy._srtp import SRTPContext


def _make_rtp_packet(
    seq: int = 1,
    timestamp: int = 960,
    ssrc: int = 0x12345678,
    payload: bytes = b"\x00" * 20,
) -> bytes:
    """Build a minimal RTP packet."""
    # V=2, P=0, X=0, CC=0, M=0, PT=111
    header = struct.pack(
        "!BBHII",
        0x80,  # V=2, no padding, no extension, CC=0
        111,  # marker=0, payload type=111
        seq,
        timestamp,
        ssrc,
    )
    return header + payload


def _make_key_b64() -> str:
    """Generate a random 30-byte SRTP master key+salt as base64."""
    return base64.b64encode(os.urandom(30)).decode()


def test_encrypt_produces_valid_srtp_packet():
    """Encrypted packet should be header + encrypted payload + 10-byte auth tag."""
    key_b64 = _make_key_b64()
    ctx = SRTPContext(key_b64)
    rtp = _make_rtp_packet(payload=b"\xab" * 20)

    srtp = ctx.encrypt(rtp)

    # SRTP = 12-byte header + 20-byte encrypted payload + 10-byte auth tag
    assert len(srtp) == 12 + 20 + 10


def test_encrypt_preserves_header():
    """SRTP header should be identical to the original RTP header."""
    key_b64 = _make_key_b64()
    ctx = SRTPContext(key_b64)
    rtp = _make_rtp_packet()

    srtp = ctx.encrypt(rtp)

    assert srtp[:12] == rtp[:12]


def test_encrypt_changes_payload():
    """Encrypted payload must differ from plaintext."""
    key_b64 = _make_key_b64()
    ctx = SRTPContext(key_b64)
    payload = b"\x01\x02\x03\x04\x05\x06\x07\x08" * 4
    rtp = _make_rtp_packet(payload=payload)

    srtp = ctx.encrypt(rtp)

    encrypted_payload = srtp[12:-10]
    assert encrypted_payload != payload


def test_sequential_packets_produce_different_output():
    """Two packets with different sequence numbers should produce different SRTP."""
    key_b64 = _make_key_b64()
    ctx = SRTPContext(key_b64)
    payload = b"\xaa" * 20

    srtp1 = ctx.encrypt(_make_rtp_packet(seq=1, payload=payload))
    srtp2 = ctx.encrypt(_make_rtp_packet(seq=2, payload=payload))

    assert srtp1 != srtp2


def test_roc_increments_on_sequence_wraparound():
    """ROC should increment when sequence number wraps around."""
    key_b64 = _make_key_b64()
    ctx = SRTPContext(key_b64)

    # Start near the end of the sequence space
    ctx.encrypt(_make_rtp_packet(seq=0xFFFE))
    ctx.encrypt(_make_rtp_packet(seq=0xFFFF))
    assert ctx._roc == 0

    # Wraparound
    ctx.encrypt(_make_rtp_packet(seq=0x0000))
    assert ctx._roc == 1


def test_encrypt_with_csrc():
    """Packets with CSRC entries should be handled correctly."""
    key_b64 = _make_key_b64()
    ctx = SRTPContext(key_b64)

    # V=2, P=0, X=0, CC=2
    header = struct.pack(
        "!BBHII",
        0x82,  # CC=2
        111,
        1,
        960,
        0x12345678,
    )
    # Two CSRC entries
    csrc = struct.pack("!II", 0xAAAAAAAA, 0xBBBBBBBB)
    payload = b"\x00" * 10
    rtp = header + csrc + payload

    srtp = ctx.encrypt(rtp)

    # 12 base header + 8 CSRC + 10 payload + 10 auth tag
    assert len(srtp) == 12 + 8 + 10 + 10
    # Header + CSRC preserved
    assert srtp[:20] == rtp[:20]


def test_encrypt_with_extension():
    """Packets with RTP header extension should be handled correctly."""
    key_b64 = _make_key_b64()
    ctx = SRTPContext(key_b64)

    # V=2, P=0, X=1, CC=0
    header = struct.pack(
        "!BBHII",
        0x90,  # X=1 (extension bit)
        111,
        1,
        960,
        0x12345678,
    )
    # Extension header: profile-specific ID + length in 32-bit words
    ext = struct.pack("!HH", 0xBEDE, 1)  # 1 word of extension data
    ext_data = b"\x00" * 4
    payload = b"\xff" * 10
    rtp = header + ext + ext_data + payload

    srtp = ctx.encrypt(rtp)

    # 12 base + 4 ext header + 4 ext data + 10 payload + 10 auth tag
    assert len(srtp) == 12 + 4 + 4 + 10 + 10
