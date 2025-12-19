# Project Architecture Rules (Non-Obvious Only)

- Dual authentication system with TSIDP OIDC and HMAC tokens via `SYSTEMMANAGER_AUTH_MODE` environment variable
- Dependency injection pattern using `src.server.dependencies.deps` singleton with lazy-loaded services
- Policy-driven execution architecture - all operations validated through `src.services.policy_gate` before execution
- Security-first design with mandatory authentication middleware blocking all requests without proper tokens
- Custom exception hierarchy using `SystemManagerError` with `ErrorCategory` enum (never raise bare exceptions)
- Docker operations require port forwarding checks in connector classes - commands fail silently without this
- MCP server with dual transport support (stdio for compatibility, http-sse for direct access)
- Consolidated security scanner in `src.security.scanner` (not standard bandit/safety tools)
- Custom package discovery via `pyproject.toml` requiring `src.` prefix in all imports
- Minimum 80% coverage requirement with pytest markers for test categorization
