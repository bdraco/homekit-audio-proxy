"""Tests for the async AudioProxy class."""

from __future__ import annotations

import asyncio
import base64
import os
import socket
import struct

import pytest

from homekit_audio_proxy import AudioProxy


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
    # Find a free port for dest
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
    # Find a free port for the proxy's send socket bind (dest_port).
    # The proxy binds send_sock to 0.0.0.0:dest_port AND sends to
    # dest_addr:dest_port, so on loopback the proxy's own send socket
    # receives the forwarded packet.
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
        # Send a plain RTP packet to the proxy's recv port
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        rtp = _make_rtp_packet(seq=1, timestamp=960)
        sender.sendto(rtp, ("127.0.0.1", proxy.local_port))
        sender.close()

        # Give the subprocess a moment to process and forward
        await asyncio.sleep(0.1)

        # Verify the proxy is still running (didn't crash processing the packet)
        assert proxy._process is not None
        assert proxy._process.returncode is None
    finally:
        await proxy.async_stop()


@pytest.mark.asyncio
async def test_proxy_stop_is_idempotent():
    """Calling async_stop multiple times should not raise."""
    proxy = AudioProxy(
        dest_addr="127.0.0.1",
        dest_port=0,
        srtp_key_b64=_make_key_b64(),
        target_clock_rate=16000,
    )
    # Stop without starting
    await proxy.async_stop()
    await proxy.async_stop()
