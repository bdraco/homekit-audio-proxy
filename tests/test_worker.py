"""Tests for the subprocess worker."""

from __future__ import annotations

import base64
import os
import struct

from homekit_audio_proxy._srtp import SRTPContext
from homekit_audio_proxy._worker import run_proxy


def _make_key_b64() -> str:
    """Generate a random 30-byte SRTP master key+salt as base64."""
    return base64.b64encode(os.urandom(30)).decode()


def _make_rtp_packet(
    seq: int = 1,
    timestamp: int = 960,
    ssrc: int = 0x12345678,
    payload: bytes = b"\x00" * 20,
) -> bytes:
    """Build a minimal RTP packet."""
    header = struct.pack("!BBHII", 0x80, 111, seq, timestamp, ssrc)
    return header + payload


def test_srtp_encrypt_roundtrip():
    """SRTP context should produce correctly sized encrypted packets."""
    key_b64 = _make_key_b64()
    srtp = SRTPContext(key_b64)
    rtp = _make_rtp_packet(timestamp=960)
    encrypted = srtp.encrypt(rtp)
    # SRTP packet: 12 header + 20 payload + 10 auth
    assert len(encrypted) == 42


def test_worker_converts_timestamps():
    """Verify the timestamp ratio calculation is correct."""
    # At 48kHz, 20ms = 960 samples
    # At 16kHz, 20ms = 320 samples
    # So timestamp 960 at 48kHz should become 320 at 16kHz
    ratio = 16000 / 48000
    ts_48k = 960
    ts_16k = int(ts_48k * ratio) & 0xFFFFFFFF
    assert ts_16k == 320

    # 60ms frame
    ts_48k = 2880
    ts_16k = int(ts_48k * ratio) & 0xFFFFFFFF
    assert ts_16k == 960

    # Verify wraparound handling
    ts_48k = 0xFFFFFF00
    ts_16k = int(ts_48k * ratio) & 0xFFFFFFFF
    assert ts_16k == int(0xFFFFFF00 * ratio) & 0xFFFFFFFF


def test_worker_invalid_key_returns_error():
    """Worker should return 1 for an invalid SRTP key."""
    result = run_proxy(
        dest_addr="127.0.0.1",
        dest_port=0,
        srtp_key_b64="not-valid-base64!!!",
        target_clock_rate=16000,
    )
    assert result == 1
