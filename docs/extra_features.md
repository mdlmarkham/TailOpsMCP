# Extra Features: Inventory, Stacks, Snapshots, Network Exposure (Control Plane Gateway)

This document summarizes the new feature set added to `TailOpsMCP` with the control plane gateway architecture:

## Control Plane Gateway Features

- **Target Registry Management** (`src/services/target_registry.py`)
  - Centralized management of all target systems through `targets.yaml`
  - Capability-based access control across all managed systems
  - Target-specific constraints and security policies

- **Multi-Target Inventory** (`src/inventory.py`)
  - Lightweight JSON-backed inventory for hosts and stacks across all targets
  - APIs: `add_host`, `remove_host`, `list_hosts`, `add_stack`, `remove_stack`, `list_stacks` with target context
  - Cross-target application discovery and management

- **Stack Abstraction & Git Helpers** (`src/stack.py`)
  - `StackManager` provides simple git helpers: `git_status`, `git_diff`, `git_checkout` across multiple targets
  - Multi-target stack deployment and management
  - Intended for local stacks; integrate with CI/CD for production across the infrastructure

- **Periodic Snapshots & Alerts** (`src/snapshotter.py`)
  - `Snapshotter` accepts a snapshot function and optional `alert_fn` for multi-target monitoring
  - Persists timestamped JSON snapshots to `./snapshots` or `SYSTEMMANAGER_SNAPSHOT_DIR` with target metadata
  - Cross-system health monitoring and alerting

- **Network Exposure / Port Mapping** (`src/tools/network_tools.py`)
  - `local_listening_ports()` parses `/proc/net/tcp` when available on target systems
  - `port_exposure_summary()` provides a small summary useful for alerts across the infrastructure
  - Multi-target network security assessment

- **Audit & Security Enhancements** (Gateway-Centric)
  - `src/utils/audit.py` now records `dry_run` flag and sanitizes args more robustly with target context
  - Centralized audit logging for all operations across all targets
  - Gateway-level security policy enforcement

## Gateway-Specific Capabilities

- **Centralized Target Discovery**: Automatic discovery and registration of new systems
- **Capability-Based Authorization**: Fine-grained control over what operations can be performed on each target
- **Cross-Target Operations**: Coordinated operations across multiple systems
- **Gateway Health Monitoring**: Monitoring of the control plane gateway itself
- **Target Connectivity Management**: Management of connections to all managed systems

See the source modules for simple usage examples and extension points with gateway context.
