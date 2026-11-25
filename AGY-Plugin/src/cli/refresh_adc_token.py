#!/usr/bin/env python3
"""ACL-locked helper CLI for background ADC token refresh and certifi lookup."""

from __future__ import annotations

from collections.abc import Sequence
import functools
import os
import sys

try:
    import certifi
except ImportError:
    certifi = None  # type: ignore[assignment]

try:
    from google import auth as google_auth
    from google.auth.transport import requests as google_auth_requests
except ImportError:
    google_auth = None  # type: ignore[assignment]
    google_auth_requests = None  # type: ignore[assignment]

DEFAULT_REFRESH_TIMEOUT_SECONDS = 15.0


def print_certifi_path() -> int:
    """Prints certifi.where() to stdout and returns 0."""
    if certifi is None:
        raise RuntimeError("certifi is not installed in this Python environment")
    sys.stdout.write(certifi.where() + "\n")
    sys.stdout.flush()
    return 0


def refresh_token_to_file(
    cred_config_path: str,
    target_token_path: str,
    timeout_seconds: float = DEFAULT_REFRESH_TIMEOUT_SECONDS,
) -> int:
    """Exchanges external_account or ADC credentials and atomically writes the bearer token."""
    if google_auth is None or google_auth_requests is None:
        raise RuntimeError("google-auth and requests are required to refresh ADC credentials")

    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = cred_config_path
    creds, _ = google_auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
    bounded_request = functools.partial(google_auth_requests.Request(), timeout=timeout_seconds)
    creds.refresh(bounded_request)
    token_val = (creds.token or "").strip()
    if not token_val:
        raise RuntimeError("google-auth returned an empty access token")

    parent_dir = os.path.dirname(os.path.abspath(target_token_path))
    if parent_dir:
        os.makedirs(parent_dir, exist_ok=True)
    tmp_path = f"{target_token_path}.tmp.{os.getpid()}"
    try:
        with open(tmp_path, "w", encoding="utf-8") as token_fh:
            token_fh.write(token_val)
        os.replace(tmp_path, target_token_path)
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass
    return 0


def main(argv: Sequence[str]) -> int:
    """Parses CLI arguments and runs certifi lookup or atomic ADC token refresh."""
    if len(argv) == 2 and argv[1] == "--print-certifi":
        return print_certifi_path()
    if len(argv) not in (3, 4):
        sys.stderr.write(
            "Usage: refresh_adc_token.py (--print-certifi | "
            "<cred_config_path> <target_token_path> [timeout_seconds])\n"
        )
        return 2
    timeout_sec = float(argv[3]) if len(argv) == 4 else DEFAULT_REFRESH_TIMEOUT_SECONDS
    return refresh_token_to_file(argv[1], argv[2], timeout_seconds=timeout_sec)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
