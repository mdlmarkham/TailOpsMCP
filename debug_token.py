#!/usr/bin/env python3
"""Debug script to inspect the token being sent to the server."""

import base64
import json
import sys

def inspect_token(token: str):
    """Inspect a token to see its format."""
    print(f"Token length: {len(token)}")
    print(f"Token preview: {token[:50]}...")
    print()
    
    # Try to decode as JWT
    try:
        parts = token.split('.')
        if len(parts) == 3:
            print("✅ Token has 3 parts (JWT format)")
            
            # Decode header
            header_padded = parts[0] + '=' * (4 - len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_padded))
            print(f"Header: {json.dumps(header, indent=2)}")
            
            # Decode payload
            payload_padded = parts[1] + '=' * (4 - len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_padded))
            print(f"Payload: {json.dumps(payload, indent=2)}")
            
            return True
        else:
            print(f"❌ Token has {len(parts)} parts, not 3 (not standard JWT)")
    except Exception as e:
        print(f"❌ Failed to decode as JWT: {e}")
    
    # Try as opaque token
    print("\nTrying to interpret as opaque/non-JWT token...")
    print(f"Raw bytes (first 50): {token[:50].encode()}")
    
    return False

if __name__ == "__main__":
    if len(sys.argv) > 1:
        token = sys.argv[1]
    else:
        print("Paste the token from the Authorization header:")
        token = input().strip()
        if token.lower().startswith("bearer "):
            token = token.split(None, 1)[1]
    
    inspect_token(token)
