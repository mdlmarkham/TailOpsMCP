# AGENTS.md

This file provides guidance to agents when working with code in this repository.

## Non-Obvious Project Patterns

- **Dual Authentication System**: System supports both TSIDP OIDC and HMAC token authentication. Set `SYSTEMMANAGER_AUTH_MODE` environment variable to `"oidc"` or `"token"` (default). OIDC mode requires explicit `TSIDP_URL`, `TSIDP_CLIENT_ID`, and `TSIDP_CLIENT_SECRET`.

- **Custom Exception Hierarchy**: All errors use `SystemManagerError` with `ErrorCategory` enum (SYSTEM, VALIDATION, PERMISSION, UNAUTHORIZED, FORBIDDEN, CONFIGURATION). Never raise bare exceptions.

- **Dependency Injection Pattern**: All services accessed through `src.server.dependencies.deps` singleton. Services are lazy-loaded with properties, never instantiate directly.

- **Docker Port Forwarding Requirement**: Docker operations require `_ensure_port_forwarding()` check before each operation. Commands fail silently without this check.

- **Security-First Design**: Authentication middleware in `src.auth.middleware` blocks all requests without proper tokens. Set `SYSTEMMANAGER_REQUIRE_AUTH=false` only for development.

## Build Commands

- **Single Test**: `pytest tests/test_filename.py::test_function -v`
- **Fast Tests**: `make test-fast` (no coverage, stops on first failure)
- **Quality Pipeline**: `make ci` (runs lint, typecheck, security, complexity, then tests)
- **Auto-fix**: `make fix` (ruff format, isort, ruff check --fix)

## Critical Gotchas

- **Package Discovery**: Source packages are in `src/` directory with `pyproject.toml` using `packages = { find = { where = ["src"] } }`. Import paths must include `src.` prefix.

- **Security Scanning**: Custom security scanner in `src.security.scanner` consolidates vulnerability detection, secrets scanning, and compliance checking. Not standard bandit/safety.

- **Policy-Driven Execution**: All operations go through policy engine in `src.services.policy_gate`. Operations fail if policy validation fails, even with valid auth.

- **Transport Configuration**: MCP server supports both stdio and http-sse transports. Default is stdio for MCP compatibility, http-sse for direct HTTP access.

- **Coverage Requirements**: Minimum 80% coverage required. Tests in `tests/` directory with pytest markers: unit, integration, security, performance, edge_case, orchestration, slow, smoke, regression, compliance.

## Testing Structure

- **Test Markers**: Use pytest markers extensively. Run specific categories: `pytest -m "unit"` or `pytest -m "integration"`
- **Coverage Reports**: Generated in `htmlcov/index.html` after test runs
- **Security Tests**: Marked with `security` marker, focus on auth and policy validation
- **Mock Requirements**: Integration tests use extensive mocking in `tests/mock_*.py` files

Always use the projects virtual environment for testing and development to ensure dependencies are correctly managed.
Activate with: `source .venv/bin/activate` on Unix or `.venv\Scripts\activate` on Windows.

## Code Style Guidelines

- **Formatting**: Use ruff format (line-length 88, py311 target) and isort (black profile)
- **Linting**: Ruff checks, mypy strict typing required, no untyped defs
- **Error Handling**: Always use `SystemManagerError` with proper `ErrorCategory`, never bare exceptions
- **Imports**: Group imports (stdlib, third-party, local), isort handles automatically
- **Naming**: snake_case for functions/variables, PascalCase for classes, UPPER_CASE for constants
- **Type Hints**: Required for all public functions and class attributes
- **Security**: Never log secrets, always use dependency injection via `src.server.dependencies.deps`
