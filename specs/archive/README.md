# Archived Specifications

**Archive Date**: 2025-12-23

## Purpose

This directory contains specifications and task lists that have been substantially completed and are no longer actively used for project planning.

## Archived Items

### 001-systemmanager-mcp-server
**Completion Status**: 86% complete (45 of 52 tasks fully implemented)

Original feature specification for the SystemManager MCP Server with 9 phases:
- Phase 1-2: Setup & Foundational (100% complete)
- Phase 3-6: User Stories 1-4 (95% complete)
  - US1: Basic System Information ✅
  - US2: Docker Container Management ✅
  - US3: File System Exploration ✅
  - US4: Network Status & Connectivity ✅
- Phase 7: Deployment & Configuration (100% complete)
- Phase 8: Security & Monitoring (80% complete)
- Phase 9: Documentation & Testing (80% complete)

**Files**:
- spec.md - Feature specification
- plan.md - Implementation plan
- tasks.md - 52 implementation tasks
- data-model.md - Data models
- research.md - Research notes
- quickstart.md - Quick start guide

### master
**Completion Status**: 92% complete (22 of 24 tasks fully implemented)

Improvements and enhancements to the SystemManager MCP Server:
- Phase 1: Setup/Project Initialization (100% complete)
- Phase 2: Foundational/Core Infrastructure (100% complete)
- Phase 3: System Monitoring Foundation (100% complete)

**Files**:
- tasks.md - 24 improvement tasks
- plan.md - Enhancement plan
- data-model.md - Updated data models
- research.md - Research notes
- quickstart.md - Quick start guide
- tailscale_policy.md - Tailscale integration details
- toon.md - Toon format specification

## What Happened to Incomplete Tasks?

The remaining partially implemented tasks from these archived specs have been converted to bd issues for tracking:

- **TailOpsMCP-m7f** [P1]: Integrate rate limiting across all tool endpoints
- **TailOpsMCP-l40** [P2]: Create comprehensive performance benchmark suite with baseline metrics
- **TailOpsMCP-hij** [P2]: Enhance container resource monitoring with per-container metrics granularity
- **TailOpsMCP-9ty** [P2]: Document penetration testing procedures and security audit results

## Current State

The codebase has evolved significantly beyond these original specifications:

**Fully Implemented Core Features**:
- FastMCP-based server with HTTP and stdio transports
- Dual authentication (OIDC/Tailscale + HMAC token)
- Policy engine with operation tiers (OBSERVE/CONTROL/ADMIN)
- System monitoring, Docker management, file system exploration, network tools
- Comprehensive security framework with RBAC and audit logging
- Fleet management and inventory system
- Proxmox integration
- Remote agent support for distributed execution
- Workflow engine with scheduling
- Extensive test suite (50+ test files, 80%+ coverage)

**Advanced Features Added Beyond Original Scope**:
- Policy-driven execution with dry-run mode
- Target registry and validation
- Compliance monitoring and enforcement
- Security scanning integration
- Event system and observability
- Health monitoring and resource tracking

## Reference

These archived specifications can be referenced for:
- Historical context on project evolution
- Understanding original design decisions
- Onboarding documentation for project history
- Comparison with current implementation

For current work, use the bd issue tracking system:
```bash
bd ready --json  # Show ready-to-work issues
bd list          # Show all issues
```
