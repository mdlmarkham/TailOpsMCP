#!/usr/bin/env python3
"""Simple CLI to mint HMAC tokens for SystemManager (fallback auth).

Generates tokens of the form: base64url(json_claims).hex_signature
where signature = HMAC-SHA256(shared_secret, base64url(json_claims)).

Usage:
  python scripts/mint_token.py --agent llm-agent-1 --scopes monitor,deploy --expiry 2025-12-31T00:00:00

You can set `SYSTEMMANAGER_SHARED_SECRET` in the environment or pass `--secret`.
"""
import argparse
import base64
import datetime
import hmac
import hashlib
import json
import os
from typing import List


def base64url_no_pad(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def make_hmac_token(claims: dict, secret: bytes) -> str:
    payload = json.dumps(claims, separators=(",",":")).encode()
    payload_b64 = base64url_no_pad(payload)
    sig = hmac.new(secret, payload_b64.encode(), hashlib.sha256).hexdigest()
    return f"{payload_b64}.{sig}"


def parse_scopes(s: str) -> List[str]:
    return [x.strip() for x in s.split(",") if x.strip()]


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--agent", required=True)
    p.add_argument("--scopes", required=True, help="Comma separated scopes")
    p.add_argument("--expiry", default=None, help="ISO8601 expiry, e.g. 2025-12-31T00:00:00")
    p.add_argument("--secret", default=None, help="Shared secret (or set SYSTEMMANAGER_SHARED_SECRET env var)")

    args = p.parse_args()

    secret = args.secret or os.getenv("SYSTEMMANAGER_SHARED_SECRET")
    if not secret:
        raise SystemExit("No secret provided; set --secret or SYSTEMMANAGER_SHARED_SECRET")

    claims = {
        "agent": args.agent,
        "scopes": parse_scopes(args.scopes),
    }
    if args.expiry:
        # Validate ISO format
        try:
            datetime.datetime.fromisoformat(args.expiry)
            claims["expiry"] = args.expiry
        except Exception as e:
            raise SystemExit(f"Invalid expiry: {e}")

    token = make_hmac_token(claims, secret.encode())
    print(token)


if __name__ == "__main__":
    main()
