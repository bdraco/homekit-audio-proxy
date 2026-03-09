"""
HomeKit audio RTP proxy.

FFmpeg's RTP muxer uses a 48000 Hz clock rate for Opus (per RFC 7587),
but Apple's HomeKit implementation expects the RTP timestamps to use
the negotiated sample rate (e.g., 16000 Hz). This library provides a
subprocess-based proxy that receives plain RTP from FFmpeg, converts
the timestamps, encrypts with SRTP, and forwards to the HomeKit client.
"""

__version__ = "1.0.0"

from .proxy import AudioProxy

__all__ = ["AudioProxy"]
