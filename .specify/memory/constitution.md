<!--
Sync Impact Report

- Version change: UNSET -> 0.1.1
- Modified principles: template placeholders replaced with project-specific principles
- Added sections: Operational Constraints & Security Requirements; Development Workflow & Release Policy; MCP Protocol Compliance & Standards; Error Handling & Resilience; Performance & Scalability Requirements; Testing Strategy; Documentation Requirements; Backup & Disaster Recovery; Monitoring & Alerting
- Removed sections: none
- Templates reviewed: .specify/templates/plan-template.md ✅ reviewed; .specify/templates/spec-template.md ✅ reviewed; .specify/templates/tasks-template.md ✅ reviewed
- Templates pending manual check: .specify/templates/commands/* ⚠ not found (no commands folder)
- Follow-up TODOs: RATIFICATION_DATE (TODO)
- Version bump: 0.1.0 -> 0.1.1 (added comprehensive operational sections)
-->

# SystemManager MCP Server Constitution

## Core Principles

### I. Security & Least Privilege (NON-NEGOTIABLE)
All external interfaces, administrative APIs, and agent connections MUST be authenticated and authorized. Network communication MUST be encrypted in transit (TLS). Management operations (Docker control, environment changes) MUST run with the minimum privileges required and SHOULD require explicit operator consent for high-risk actions. Audit logs for all privileged actions MUST be retained and tamper-evident.

### II. Token & Cost Efficiency (DESIGN CONSTRAINT)
APIs, protocols, and data returned to remote LLMs MUST minimize token usage. Responses SHOULD be compact, optionally summarized, and support streaming to avoid repeated resends of large contexts. Default behaviors MUST avoid returning full file contents or unbounded logs unless explicitly requested and bounded.

### III. Observability & Auditability
The server MUST emit structured logs, metrics (prometheus-format or equivalent), and traces for key operations (agent connections, Docker operations, file searches, environment changes). Security-relevant events (auth, permission changes, admin operations) MUST be audited with sufficient context to reproduce and investigate incidents.

### IV. Deterministic, Contract-First Interfaces
All external-facing behavior (HTTP APIs, Streamable HTTP endpoints) MUST be defined by explicit contracts and covered by automated contract tests. Changes that modify contracts MUST include a migration plan and appropriate version bump. Unit, integration, and contract tests MUST accompany feature changes that affect behavior.

### V. Simplicity, Portability & Resource Discipline
The project MUST favour small, well-audited dependencies and keep resource usage predictable to support deployment on Ubuntu/Debian and ProxMox LXC containers. Default deployments MUST be lean (reasonable memory/CPU footprint) and provide guidance for constrained environments. Complexity that increases operational burden MUST be justified and reviewed.

## Operational Constraints & Security Requirements

- Supported deployment targets: Debian/Ubuntu LTS, ProxMox LXC containers (recommendation: unprivileged LXC for isolation). The server MUST also run on compatible modern Linux kernels.
- Required privileges: The service SHOULD run as a dedicated, non-root user. Any Docker control surface MUST be gated and run via an internal agent with least privilege, preferably via a Unix socket with strict ownership and ACLs.
- Network: Control plane ports and Streamable HTTP endpoints MUST be protected behind TLS and optional firewall rules. Recommend binding administrative endpoints to localhost or an operator-managed interface by default.
- Secrets: Keys and credentials MUST be stored encrypted and only in operator-managed secrets stores (e.g., files with restricted permissions, Vault, or similar). Hardcoded secrets are forbidden.
- Data minimization: The server MUST avoid sending full file contents, secrets, or sensitive host metadata to remote models unless explicitly requested and approved by an operator with an auditable action.

## MCP Protocol Compliance & Standards

- The server MUST implement the MCP (Model Context Protocol) specification correctly and maintain compatibility with standard MCP clients.
- All MCP tools and resources MUST be documented with clear schemas, parameter definitions, and usage examples.
- Protocol extensions or custom features MUST be backward-compatible and clearly documented as non-standard.
- MCP session management MUST handle connection failures gracefully with appropriate retry logic and session cleanup.

## Error Handling & Resilience

- The server MUST handle partial failures gracefully (e.g., Docker daemon unavailable, file system errors) without crashing.
- All external dependencies (Docker, file systems, network services) MUST have appropriate timeout and retry configurations.
- Critical operations MUST include rollback mechanisms where feasible (e.g., Docker container state changes).
- Error messages returned to MCP clients MUST be informative but MUST NOT expose sensitive system information.

## Performance & Scalability Requirements

- The server MUST handle concurrent MCP connections efficiently (target: 50+ concurrent agent connections).
- Docker operations MUST complete within reasonable timeouts (e.g., container operations < 30 seconds, file searches < 10 seconds for typical directories).
- Memory usage MUST be bounded and predictable, with monitoring for memory leaks in long-running operations.
- The server SHOULD support horizontal scaling patterns for high-availability deployments.

## Testing Strategy

- MCP protocol compliance MUST be verified with automated contract tests against the MCP specification.
- Integration tests MUST cover Docker operations, file system interactions, and environment management scenarios.
- Security tests MUST validate authentication, authorization, and privilege escalation prevention.
- Performance tests MUST validate scalability targets under realistic load conditions.
- All tests MUST be runnable in isolated environments (Docker containers) to ensure reproducibility.

## Documentation Requirements

- API documentation MUST be automatically generated from code and kept synchronized with implementation.
- Deployment guides MUST include security hardening steps, performance tuning, and troubleshooting procedures.
- Operational runbooks MUST exist for common maintenance tasks, incident response, and recovery procedures.
- All documentation MUST be version-controlled alongside the codebase.

## Backup & Disaster Recovery

- Configuration and critical state MUST be backed up regularly and tested for restore capability.
- The server MUST support graceful shutdown and restart without data loss for managed operations.
- Recovery procedures MUST be documented and tested periodically.
- Critical data (audit logs, configuration) MUST have retention policies and secure storage.

## Monitoring & Alerting

- Health checks MUST be implemented for all critical subsystems (Docker connectivity, file system access, network interfaces).
- Alert thresholds MUST be defined for resource exhaustion, security events, and service degradation.
- Monitoring dashboards MUST provide visibility into MCP session activity, resource usage, and operational metrics.
- Alert responses MUST be documented with escalation procedures for security incidents.

## Development Workflow & Release Policy

- PRs: All changes MUST be submitted via pull requests; each PR MUST have at least one non-author approver and one security-aware reviewer for changes touching auth, networking, or privilege boundaries.
- Tests: Every change that affects behavior MUST include tests. Contract tests for external APIs are mandatory. CI pipelines MUST run unit, integration, and contract tests before merge.
- Releases: The project follows semantic versioning. Each release MUST include a changelog entry describing breaking changes, migrations, and security fixes.
- Security reviews: Security-relevant changes MUST include threat reasoning and automated verification where practicable.
- Code review: Reviews MUST verify compliance with this constitution, security practices, and performance requirements.
- CI/CD: Automated pipelines MUST include security scanning, dependency vulnerability checks, and performance regression detection.
- Release process: Major releases MUST undergo security audit and performance validation before deployment.

## Governance

Amendments to this constitution MUST be proposed as a documented change (pull request) explaining the rationale and impact. Amendments that add or redefine core principles (breaking governance expectations) are MAJOR changes and MUST be approved by at least two maintainers, one of whom MUST be a security or operations owner. Minor clarifications or wording fixes are PATCH-level changes and MAY be merged after routine review.

Versioning policy (summary):
- MAJOR: Backward-incompatible governance or principle removals/major redefinitions.
- MINOR: New principle/section added or material expansion of guidance.
- PATCH: Editorial clarifications, wording fixes, or non-substantive refinements.

**Version**: 0.1.1 | **Ratified**: TODO(RATIFICATION_DATE): initial adoption date to be recorded | **Last Amended**: 2025-11-15
