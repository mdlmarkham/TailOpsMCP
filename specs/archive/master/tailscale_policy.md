# Tailscale Services: Policy snippet & token schema

This document provides:

- A minimal Tailscale Service & ACL snippet you can paste into your tailnet policy.
- A simple token-scope schema and examples (HMAC and JWT) for the MCP server fallback.

---

## 1) Example Tailscale Service definition (Admin Console)

In the Tailscale Admin Console, create a Service (e.g., `svc:mcp-api`) that points
to the MCP server on the host machine (for example mapping `tcp:443` → `127.0.0.1:8443`).

This will give you a stable MagicDNS name such as `mcp-api.<your-tailnet>.ts.net`.

## 2) Minimal tailnet ACL snippet (policy) - allow only LLM agent devices

Add the following to your tailnet ACLs in the Admin → Access controls → Tags / ACLs.

```json
{
  "ACLs": [
    {
      "Action": "accept",
      "Users": ["*"],
      "Ports": ["tag:llm-agent,svc:mcp-api:443"]
    }
  ],
  "TagOwners": {
    "tag:mcp": ["group:admins@example.com"],
    "tag:llm-agent": ["group:llm-team@example.com"]
  }
}
```

Notes:
- Replace `group:...` entries with your users/groups. Use tags to limit which devices can access `svc:mcp-api`.
- You can auto-approve host advertisements for `tag:mcp` to ease automation.

## 3) Example token schema (fallback auth)

Tokens are optional when Tailscale enforces strict network ACLs. If you enable an application
token verifier, use tokens with scopes so you can finely control which tools an agent may call.

Example token JSON (claims):

```json
{
  "agent": "llm-agent-1",
  "scopes": ["monitor", "deploy"],
  "host_tags": ["homelab"],
  "expiry": "2025-12-31T00:00:00"
}
```

Two token formats supported by `src/auth/token_auth.py`:

- HMAC shared-secret token (simple):
  - Format: `base64url(json_claims).hex_signature`
  - Signature = HMAC-SHA256(shared_secret, base64url(json_claims))
  - Configure the server with `SYSTEMMANAGER_SHARED_SECRET`.

- JWT (recommended if you already run a token issuer):
  - Configure the server with `SYSTEMMANAGER_JWT_SECRET` (HS256 shared key) or adapt to use public keys.

## 4) Generating an HMAC token (example)

Python snippet to create an HMAC token:

```python
import base64, json, hmac, hashlib

claims = {
  "agent": "llm-agent-1",
  "scopes": ["monitor", "deploy"],
  "host_tags": ["homelab"],
  "expiry": "2025-12-31T00:00:00"
}
payload = json.dumps(claims,separators=(",",":")).encode()
payload_b64 = base64.urlsafe_b64encode(payload).rstrip(b"=").decode()
secret = b"your-shared-secret-here"
sig = hmac.new(secret,payload_b64.encode(),hashlib.sha256).hexdigest()
token = f"{payload_b64}.{sig}"
print(token)
```

## 5) How to use tokens with the MCP server

- Prefer Tailscale-only network access for best security: bind the MCP service to `127.0.0.1:8443` and publish via the Tailscale Service.
- When calling tools over HTTP or the chosen transport, include `Authorization: Bearer <token>` header.
- Tools decorated with scope requirements will validate the token and ensure the `scopes` claim contains required scopes.

## 6) Logging & audit

- Log token subject (`agent`) and scopes on each call. Keep the tailnet logs for connectivity-level evidence.
- Rotate `SYSTEMMANAGER_SHARED_SECRET` regularly if you use HMAC tokens.

---

If you want, I can also:
- Add a simple CLI script to mint HMAC tokens (short script in `scripts/`), or
- Add an example integration into `src/mcp_server.py` to apply `require_scopes(["monitor"])` to selected tools.
