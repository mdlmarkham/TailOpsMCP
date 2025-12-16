# Project Debug Rules (Non-Obvious Only)

- Authentication middleware in `src.auth.middleware` blocks all requests without proper tokens
- Docker commands fail silently without `_ensure_port_forwarding()` check in connector classes
- Custom security scanner in `src.security.scanner` consolidates vulnerability detection (not standard tools)
- Log level controlled by `LOG_LEVEL` environment variable, defaults to INFO
- Policy engine failures in `src.services.policy_gate` cause silent operation blocks
- MCP server supports both stdio and http-sse transports with different debugging approaches
- Coverage reports generated in `htmlcov/index.html` after test runs
- System identity logging shows actual server name in logs, not just "TailOpsMCP"
- Fast tests stop on first failure: `make test-fast` (no coverage, faster)
- Custom exception hierarchy with categories in `src.utils.errors` - always use SystemManagerError