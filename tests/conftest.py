"""Shared test fixtures and helpers."""

from __future__ import annotations

import base64
import os
import socket
import struct

import pytest


@pytest.fixture
def srtp_key_b64() -> str:
    """Generate a random 30-byte SRTP master key+salt as base64."""
    return base64.b64encode(os.urandom(30)).decode()


@pytest.fixture
def free_port() -> int:
    """Find a free UDP port."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def make_rtp_packet(
    seq: int = 1,
    timestamp: int = 960,
    ssrc: int = 0x12345678,
    payload: bytes = b"\x00" * 20,
) -> bytes:
    """Build a minimal RTP packet."""
    header = struct.pack("!BBHII", 0x80, 111, seq, timestamp, ssrc)
    return header + payload
