# Project Documentation Rules (Non-Obvious Only)

- Source packages in `src/` directory with non-standard package discovery via `pyproject.toml`
- Two authentication modes: TSIDP OIDC (`SYSTEMMANAGER_AUTH_MODE=oidc`) vs HMAC tokens (`token`)
- OIDC mode requires explicit `TSIDP_URL`, `TSIDP_CLIENT_ID`, `TSIDP_CLIENT_SECRET` configuration
- Package imports require `src.` prefix due to custom package discovery
- MCP server main entry point is `src.mcp_server.py`, CLI deployment in `src/cli/deploy.py`
- Custom security scanner consolidates vulnerability detection, secrets scanning, compliance checking
- Policy-driven execution system in `src.services.policy_gate` validates all operations
- Minimum 80% test coverage required with extensive pytest markers for different test types
- FastMCP with dual transport support: stdio (default) and http-sse for direct HTTP access
- System uses dependency injection pattern through `src.server.dependencies.deps` singleton
