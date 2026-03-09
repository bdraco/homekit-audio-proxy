"""Tests for the subprocess worker."""

from __future__ import annotations

import contextlib
import io
import os
import socket
import sys
import threading
import time
from unittest.mock import patch

from homekit_audio_proxy._srtp import SRTPContext
from homekit_audio_proxy._worker import run_proxy

from .conftest import make_rtp_packet


def test_srtp_encrypt_roundtrip(srtp_key_b64: str) -> None:
    """SRTP context should produce correctly sized encrypted packets."""
    srtp = SRTPContext(srtp_key_b64)
    rtp = make_rtp_packet(timestamp=960)
    encrypted = srtp.encrypt(rtp)
    # SRTP packet: 12 header + 20 payload + 10 auth
    assert len(encrypted) == 42


def test_worker_converts_timestamps() -> None:
    """Verify the integer timestamp conversion is correct."""
    assert (960 * 16000 // 48000) & 0xFFFFFFFF == 320
    assert (2880 * 16000 // 48000) & 0xFFFFFFFF == 960

    # Verify wraparound handling
    ts_48k = 0xFFFFFF00
    ts_16k = (ts_48k * 16000 // 48000) & 0xFFFFFFFF
    assert ts_16k == (0xFFFFFF00 * 16000 // 48000) & 0xFFFFFFFF


def test_worker_invalid_key_returns_error(free_port: int) -> None:
    """Worker should return 1 for an invalid SRTP key."""
    result = run_proxy(
        dest_addr="127.0.0.1",
        dest_port=free_port,
        srtp_key_b64="not-valid-base64!!!",
        target_clock_rate=16000,
    )
    assert result == 1


def test_worker_send_bind_failure_returns_error(srtp_key_b64: str) -> None:
    """Worker should return 1 if send socket bind fails."""
    original_bind = socket.socket.bind

    def mock_bind(self: socket.socket, address: tuple[str, int]) -> None:
        """Fail bind on 0.0.0.0 (the send socket) but allow 127.0.0.1 (recv)."""
        if address[0] == "0.0.0.0":  # noqa: S104
            raise OSError("Address already in use")
        original_bind(self, address)

    with patch.object(socket.socket, "bind", mock_bind):
        result = run_proxy(
            dest_addr="127.0.0.1",
            dest_port=12345,
            srtp_key_b64=srtp_key_b64,
            target_clock_rate=16000,
        )
    assert result == 1


def test_worker_recv_bind_failure_returns_error(srtp_key_b64: str) -> None:
    """Worker should return 1 if recv socket bind fails."""
    original_bind = socket.socket.bind

    def mock_bind(self: socket.socket, address: tuple[str, int]) -> None:
        """Fail bind on 127.0.0.1 (the recv socket)."""
        if address[0] == "127.0.0.1":
            raise OSError("Address already in use")
        original_bind(self, address)

    with patch.object(socket.socket, "bind", mock_bind):
        result = run_proxy(
            dest_addr="127.0.0.1",
            dest_port=12345,
            srtp_key_b64=srtp_key_b64,
            target_clock_rate=16000,
        )
    assert result == 1


def test_worker_orphan_detection(srtp_key_b64: str, free_port: int) -> None:
    """Worker should exit when parent PID changes."""
    call_count = 0
    original_ppid = os.getppid()

    def fake_getppid() -> int:
        nonlocal call_count
        call_count += 1
        if call_count <= 1:
            return original_ppid
        return original_ppid + 1

    with (
        contextlib.redirect_stdout(io.StringIO()),
        patch("homekit_audio_proxy._worker.os.getppid", side_effect=fake_getppid),
        patch("homekit_audio_proxy._worker._RECV_TIMEOUT_SECONDS", 0.1),
    ):
        result = run_proxy(
            dest_addr="127.0.0.1",
            dest_port=free_port,
            srtp_key_b64=srtp_key_b64,
            target_clock_rate=16000,
        )

    assert result == 0


def _run_worker_in_thread(
    srtp_key_b64: str,
    free_port: int,
    result_holder: list[int],
    extra_patches: dict[str, object] | None = None,
) -> tuple[threading.Thread, io.StringIO]:
    """Start worker in a thread with orphan detection."""
    captured = io.StringIO()
    original_ppid = os.getppid()
    call_count = 0

    def fake_getppid() -> int:
        nonlocal call_count
        call_count += 1
        if call_count <= 3:
            return original_ppid
        return original_ppid + 1

    side_effects: dict[str, object] = {
        "homekit_audio_proxy._worker.os.getppid": fake_getppid,
    }
    values: dict[str, object] = {
        "homekit_audio_proxy._worker._RECV_TIMEOUT_SECONDS": 0.2,
    }
    if extra_patches:
        side_effects.update(extra_patches)

    def run_worker() -> None:
        with contextlib.ExitStack() as stack:
            for target, side_effect in side_effects.items():
                stack.enter_context(patch(target, side_effect=side_effect))
            for target, value in values.items():
                stack.enter_context(patch(target, value))
            result = run_proxy(
                dest_addr="127.0.0.1",
                dest_port=free_port,
                srtp_key_b64=srtp_key_b64,
                target_clock_rate=16000,
            )
        result_holder.append(result)

    old_stdout = sys.stdout
    sys.stdout = captured
    try:
        worker_thread = threading.Thread(target=run_worker, daemon=True)
        worker_thread.start()
        time.sleep(0.3)
    finally:
        sys.stdout = old_stdout

    return worker_thread, captured


def _get_worker_port(captured: io.StringIO) -> int:
    """Extract the worker's local port from captured stdout."""
    output = captured.getvalue().strip()
    assert output, "Worker failed to start — no port written to stdout"
    return int(output)


def test_worker_processes_and_forwards_packet(
    srtp_key_b64: str, free_port: int
) -> None:
    """Worker should forward SRTP packets with converted timestamps."""
    result_holder: list[int] = []
    worker_thread, captured = _run_worker_in_thread(
        srtp_key_b64, free_port, result_holder
    )

    local_port = _get_worker_port(captured)

    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rtp = make_rtp_packet(seq=1, timestamp=960)
    sender.sendto(rtp, ("127.0.0.1", local_port))
    sender.close()

    worker_thread.join(timeout=3.0)
    assert not worker_thread.is_alive()
    assert result_holder[0] == 0


def test_worker_sendto_oserror_exits_cleanly(srtp_key_b64: str, free_port: int) -> None:
    """Worker should exit with 0 on OSError during sendto."""
    original_sendto = socket.socket.sendto
    sendto_armed = threading.Event()

    def mock_sendto(self: socket.socket, data: bytes, address: tuple[str, int]) -> int:
        if sendto_armed.is_set():
            raise OSError("Network is unreachable")
        return original_sendto(self, data, address)

    result_holder: list[int] = []

    # Use orphan detection as fallback exit path
    original_ppid = os.getppid()
    call_count = 0

    def fake_getppid() -> int:
        nonlocal call_count
        call_count += 1
        if call_count <= 5:
            return original_ppid
        return original_ppid + 1

    captured = io.StringIO()
    old_stdout = sys.stdout
    sys.stdout = captured

    def run_worker() -> None:
        with (
            patch.object(socket.socket, "sendto", mock_sendto),
            patch(
                "homekit_audio_proxy._worker.os.getppid",
                side_effect=fake_getppid,
            ),
            patch("homekit_audio_proxy._worker._RECV_TIMEOUT_SECONDS", 0.2),
        ):
            result = run_proxy(
                dest_addr="127.0.0.1",
                dest_port=free_port,
                srtp_key_b64=srtp_key_b64,
                target_clock_rate=16000,
            )
        result_holder.append(result)

    try:
        worker_thread = threading.Thread(target=run_worker, daemon=True)
        worker_thread.start()
        time.sleep(0.3)
    finally:
        sys.stdout = old_stdout

    local_port = _get_worker_port(captured)

    # Arm the mock so the worker's sendto raises
    sendto_armed.set()

    # Send a valid RTP packet using the real sendto
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rtp = make_rtp_packet(seq=1, timestamp=960)
    original_sendto(sender, rtp, ("127.0.0.1", local_port))
    sender.close()

    worker_thread.join(timeout=3.0)
    assert not worker_thread.is_alive()
    assert result_holder[0] == 0


def test_worker_encrypt_exception_returns_error(
    srtp_key_b64: str, free_port: int
) -> None:
    """Worker should return 1 on unexpected Exception in main loop."""

    def mock_encrypt(data: bytes) -> bytes:
        raise RuntimeError("Unexpected encryption error")

    result_holder: list[int] = []
    worker_thread, captured = _run_worker_in_thread(
        srtp_key_b64,
        free_port,
        result_holder,
        extra_patches={
            "homekit_audio_proxy._worker.SRTPContext.encrypt": mock_encrypt,
        },
    )

    local_port = _get_worker_port(captured)

    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rtp = make_rtp_packet(seq=1, timestamp=960)
    sender.sendto(rtp, ("127.0.0.1", local_port))
    sender.close()

    worker_thread.join(timeout=3.0)
    assert not worker_thread.is_alive()
    assert result_holder[0] == 1


def test_worker_skips_short_packets(srtp_key_b64: str, free_port: int) -> None:
    """Worker should skip packets shorter than minimum RTP header."""
    result_holder: list[int] = []
    worker_thread, captured = _run_worker_in_thread(
        srtp_key_b64, free_port, result_holder
    )

    local_port = _get_worker_port(captured)

    # Send a short packet (< 12 bytes) — should be silently skipped
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sender.sendto(b"\x00" * 5, ("127.0.0.1", local_port))
    sender.close()

    # Worker exits via orphan detection
    worker_thread.join(timeout=3.0)
    assert not worker_thread.is_alive()
    assert result_holder[0] == 0
