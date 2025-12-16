# Project Coding Rules (Non-Obvious Only)

- Always use `SystemManagerError` from `src.utils.errors` with proper `ErrorCategory` instead of raising bare exceptions
- Import paths must include `src.` prefix due to package discovery in `pyproject.toml` 
- Use `src.server.dependencies.deps` singleton for all services - never instantiate directly
- All Docker operations require `_ensure_port_forwarding()` check in `src/connectors/docker_connector.py`
- Policy validation happens in `src.services.policy_gate` before any operation execution
- Authentication is mandatory - set `SYSTEMMANAGER_REQUIRE_AUTH=false` only for development
- Security scanner in `src.security.scanner` consolidates vulnerability detection, secrets scanning, and compliance checking (not standard bandit/safety)
- All MCP tools registered through `register_all_tools()` in `src.mcp_server.py`
- Use lazy-loaded properties in `src.server.dependencies.Dependencies` class
- Transport modes: stdio (default for MCP compatibility) or http-sse (for direct HTTP access)