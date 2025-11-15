# Extra Features: Inventory, Stacks, Snapshots, Network Exposure

This document summarizes the new feature set added to `SystemManager`:

- Host & Stack Inventory (`src/inventory.py`)
  - Lightweight JSON-backed inventory for hosts and stacks.
  - APIs: `add_host`, `remove_host`, `list_hosts`, `add_stack`, `remove_stack`, `list_stacks`.

- Stack Abstraction & Git Helpers (`src/stack.py`)
  - `StackManager` provides simple git helpers: `git_status`, `git_diff`, `git_checkout`.
  - Intended for local stacks; integrate with CI/CD for production.

- Periodic Snapshots & Alerts (`src/snapshotter.py`)
  - `Snapshotter` accepts a snapshot function and optional `alert_fn`.
  - Persists timestamped JSON snapshots to `./snapshots` or `SYSTEMMANAGER_SNAPSHOT_DIR`.

- Network Exposure / Port Mapping (`src/tools/network_tools.py`)
  - `local_listening_ports()` parses `/proc/net/tcp` when available.
  - `port_exposure_summary()` provides a small summary useful for alerts.

- Audit & Security Enhancements
  - `src/utils/audit.py` now records `dry_run` flag and sanitizes args more robustly.

See the source modules for simple usage examples and extension points.
