"""Entry point for ``python -m homekit_audio_proxy``."""

from __future__ import annotations

import sys

from ._worker import run_proxy

# SRTP key is passed via stdin to avoid exposing it in process args
_srtp_key = sys.stdin.readline().strip()
sys.exit(
    run_proxy(
        dest_addr=sys.argv[1],
        dest_port=int(sys.argv[2]),
        srtp_key_b64=_srtp_key,
        target_clock_rate=int(sys.argv[3]),
    )
)
