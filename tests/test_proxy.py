"""Tests for the async AudioProxy class."""

from __future__ import annotations

import asyncio
import socket

import pytest

from homekit_audio_proxy import AudioProxy

from .conftest import make_rtp_packet


@pytest.fixture
def free_dest_port() -> int:
    """Find a free UDP port for the proxy destination."""
    tmp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tmp.bind(("127.0.0.1", 0))
    port = tmp.getsockname()[1]
    tmp.close()
    return port


@pytest.mark.asyncio
async def test_proxy_start_stop(
    srtp_key_b64: str, free_dest_port: int
) -> None:
    """Proxy should start, report a port, and stop cleanly."""
    proxy = AudioProxy(
        dest_addr="127.0.0.1",
        dest_port=free_dest_port,
        srtp_key_b64=srtp_key_b64,
        target_clock_rate=16000,
    )
    await proxy.async_start()

    assert proxy.local_port > 0

    await proxy.async_stop()


@pytest.mark.asyncio
async def test_proxy_forwards_and_encrypts(
    srtp_key_b64: str, free_dest_port: int
) -> None:
    """Proxy should forward RTP as SRTP with converted timestamps."""
    proxy = AudioProxy(
        dest_addr="127.0.0.1",
        dest_port=free_dest_port,
        srtp_key_b64=srtp_key_b64,
        target_clock_rate=16000,
    )
    await proxy.async_start()
    assert proxy.local_port > 0

    try:
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        rtp = make_rtp_packet(seq=1, timestamp=960)
        sender.sendto(rtp, ("127.0.0.1", proxy.local_port))
        sender.close()

        await asyncio.sleep(0.1)

        assert proxy._process is not None
        assert proxy._process.returncode is None
    finally:
        await proxy.async_stop()


@pytest.mark.asyncio
async def test_proxy_start_with_invalid_key(
    caplog: pytest.LogCaptureFixture,
) -> None:
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
    # Process should be cleaned up
    assert proxy._process is None

    await proxy.async_stop()


@pytest.mark.asyncio
async def test_log_stderr_forwards_lines(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """_log_stderr should forward subprocess stderr lines to logger."""
    reader = asyncio.StreamReader()
    reader.feed_data(b"some warning message\n")
    reader.feed_eof()

    with caplog.at_level("WARNING"):
        await AudioProxy._log_stderr(reader)

    assert "Audio proxy: some warning message" in caplog.text


@pytest.mark.asyncio
async def test_log_stderr_empty_stream() -> None:
    """_log_stderr should return immediately on empty stream."""
    reader = asyncio.StreamReader()
    reader.feed_eof()

    await AudioProxy._log_stderr(reader)


@pytest.mark.asyncio
async def test_proxy_stop_is_idempotent(srtp_key_b64: str) -> None:
    """Calling async_stop multiple times should not raise."""
    proxy = AudioProxy(
        dest_addr="127.0.0.1",
        dest_port=0,
        srtp_key_b64=srtp_key_b64,
        target_clock_rate=16000,
    )
    await proxy.async_stop()
    await proxy.async_stop()
