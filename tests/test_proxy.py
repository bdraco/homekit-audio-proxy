"""Tests for the async AudioProxy class."""

from __future__ import annotations

import asyncio
import base64
import os
import socket
import struct

import pytest

from homekit_audio_proxy import AudioProxy
from homekit_audio_proxy.proxy import AudioProxy as _AudioProxy


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


@pytest.mark.asyncio
async def test_proxy_start_stop():
    """Proxy should start, report a port, and stop cleanly."""
    tmp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tmp.bind(("127.0.0.1", 0))
    dest_port = tmp.getsockname()[1]
    tmp.close()

    proxy = AudioProxy(
        dest_addr="127.0.0.1",
        dest_port=dest_port,
        srtp_key_b64=_make_key_b64(),
        target_clock_rate=16000,
    )
    await proxy.async_start()

    assert proxy.local_port > 0

    await proxy.async_stop()


@pytest.mark.asyncio
async def test_proxy_forwards_and_encrypts():
    """Proxy should forward RTP as SRTP with converted timestamps."""
    tmp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tmp.bind(("127.0.0.1", 0))
    dest_port = tmp.getsockname()[1]
    tmp.close()

    key_b64 = _make_key_b64()
    proxy = AudioProxy(
        dest_addr="127.0.0.1",
        dest_port=dest_port,
        srtp_key_b64=key_b64,
        target_clock_rate=16000,
    )
    await proxy.async_start()
    assert proxy.local_port > 0

    try:
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        rtp = _make_rtp_packet(seq=1, timestamp=960)
        sender.sendto(rtp, ("127.0.0.1", proxy.local_port))
        sender.close()

        await asyncio.sleep(0.1)

        assert proxy._process is not None
        assert proxy._process.returncode is None
    finally:
        await proxy.async_stop()


@pytest.mark.asyncio
async def test_proxy_start_with_invalid_key(caplog: pytest.LogCaptureFixture):
    """Proxy should handle subprocess failure on start gracefully."""
    proxy = AudioProxy(
        dest_addr="127.0.0.1",
        dest_port=0,
        srtp_key_b64="not-valid-base64!!!",
        target_clock_rate=16000,
    )
    await proxy.async_start()

    assert proxy.local_port == 0
    assert "Audio proxy subprocess failed to start" in caplog.text

    await proxy.async_stop()


@pytest.mark.asyncio
async def test_log_stderr_forwards_lines(caplog: pytest.LogCaptureFixture):
    """_log_stderr should forward subprocess stderr lines to logger."""
    reader = asyncio.StreamReader()
    reader.feed_data(b"some warning message\n")
    reader.feed_eof()

    with caplog.at_level("WARNING"):
        await _AudioProxy._log_stderr(reader)

    assert "Audio proxy: some warning message" in caplog.text


@pytest.mark.asyncio
async def test_log_stderr_empty_stream():
    """_log_stderr should return immediately on empty stream."""
    reader = asyncio.StreamReader()
    reader.feed_eof()

    await _AudioProxy._log_stderr(reader)


@pytest.mark.asyncio
async def test_proxy_stop_is_idempotent():
    """Calling async_stop multiple times should not raise."""
    proxy = AudioProxy(
        dest_addr="127.0.0.1",
        dest_port=0,
        srtp_key_b64=_make_key_b64(),
        target_clock_rate=16000,
    )
    await proxy.async_stop()
    await proxy.async_stop()
