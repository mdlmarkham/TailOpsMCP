# Application Inventory & Multi-System Management

## Overview

TailOpsMCP's inventory system provides centralized visibility across all managed systems through the control plane gateway architecture. The system solves the common problem in multi-system management: **knowing what's running where across your entire infrastructure**.

With the control plane gateway, you can manage multiple systems (Proxmox LXC containers, VMs, bare-metal servers) from a single interface. The inventory system creates a comprehensive registry of applications and services deployed across all targets, enabling AI assistants to provide context-aware help across your entire infrastructure.

## Key Concepts

### Control Plane Gateway Architecture

The inventory system operates through the TailOpsMCP control plane gateway, which:

- **Centralizes Management**: Single gateway manages multiple target systems
- **Target Registry**: All managed systems are configured in `targets.yaml`
- **Capability-Based Access**: Fine-grained control over what operations can be performed
- **Audit Logging**: Comprehensive logging of all inventory operations

### Target Identity

Each managed system in the target registry is identified with:

- **Target ID**: Unique identifier for the system (e.g., `web-server-01`, `database-primary`)
- **Hostname**: The system's hostname (e.g., `dev1`, `media-server`)
- **Container ID**: Proxmox VMID/CTID if running in LXC (e.g., `103`)
- **System Type**: `lxc`, `vm`, `bare-metal`, or `docker`
- **Executor Type**: Connection method (`ssh`, `docker`, `proxmox`, `local`)

This allows the gateway to uniquely identify and manage each system in your infrastructure.

**Example**: Target `web-server-01` might be a Proxmox LXC container with ID 103 on host `dev1`.

### Application Metadata

For each application, the inventory tracks:

- **Name**: Application identifier (e.g., `ollama`, `jellyfin`)
- **Type**: Category (e.g., `ai-llm`, `media-server`, `database`)
- **Version**: Installed version
- **Port**: Primary port number
- **Service Name**: systemd service name (for management)
- **Config Path**: Configuration directory
- **Data Path**: Data storage directory
- **Auto-Detected**: Whether found by automatic scan
- **Notes**: Custom notes and documentation

## Auto-Detection

TailOpsMCP can automatically detect these applications:

| Category | Applications |
|----------|--------------|
| **Media** | Jellyfin, Plex |
| **Network** | Pi-hole, AdGuard Home, WireGuard |
| **Databases** | PostgreSQL, MySQL, MariaDB, MongoDB, Redis |
| **Web Servers** | Nginx, Apache |
| **Home Automation** | Home Assistant |
| **Monitoring** | Prometheus, Grafana |
| **AI/LLM** | Ollama |
| **Cloud** | Nextcloud |
| **Management** | Portainer |

### Detection Method

The inventory scanner uses multiple signals to detect applications across all managed targets:

1. **systemd Services**: Checks for running services by name on target systems
2. **Processes**: Looks for running processes on target systems
3. **Listening Ports**: Detects applications by their default ports
4. **File System**: Checks for config files and directories on target systems
5. **Version Commands**: Attempts to query version information from target systems

Each detection gets a confidence score (0.0 to 1.0). Applications need at least 0.3 confidence to be reported.

## Usage Workflows

### Initial Setup (Control Plane Gateway)

With the control plane gateway architecture, inventory setup is centralized:

1. **Configure Target Registry**: Define all managed systems in `targets.yaml`
2. **Gateway Deployment**: Deploy the TailOpsMCP gateway
3. **Inventory Discovery**: Use gateway tools to discover applications across all targets

### Interactive Inventory Setup

Use the `setup_inventory` MCP prompt through the gateway:

```
You: "Let's set up the inventory for all managed systems"

AI: "I'll help you set up the inventory across all targets. First, let me check the target registry..."

[AI calls get_target_registry to see available systems]

AI: "I see 3 targets configured: web-server-01, database-primary, media-server. Would you like to scan all systems?"

You: "Yes, scan all systems"

AI: "Great! Now let me scan for installed applications across all targets..."

[AI calls scan_installed_applications with target="all"]

AI: "Found applications across all targets:
- web-server-01: Nginx 1.24.0 (port 80), Node.js API (port 3000)
- database-primary: PostgreSQL 15.4 (port 5432), Redis 7.0.12 (port 6379)
- media-server: Jellyfin 10.8.0 (port 8096), Plex 1.32.0 (port 32400)

Should I add any other applications that weren't detected?"

You: "Yes, I also run a monitoring agent on port 8080 on web-server-01"

[AI calls add_application_to_inventory with target="web-server-01"]

AI: "Done! Inventory is now complete across all systems. I'll use this context to provide better assistance."
```

### Programmatic Setup

```python
# 1. Configure target registry (in targets.yaml)
# 2. Use gateway to scan all targets
from src.services.target_registry import TargetRegistry

# Initialize target registry
tr = TargetRegistry()

# Scan applications across all targets
results = tr.scan_applications_across_targets()
# Returns: {
#   "web-server-01": {"detected_count": 2, "applications": [...]},
#   "database-primary": {"detected_count": 2, "applications": [...]},
#   "media-server": {"detected_count": 2, "applications": [...]}
# }

# 3. Manually add missed applications to specific targets
tr.add_application_to_target(
    target_id="web-server-01",
    name="monitoring-agent",
    app_type="monitoring",
    port=8080,
    service_name="monitoring-agent",
    notes="Custom monitoring agent"
)

# 4. Review complete inventory across all targets
inventory = tr.get_complete_inventory()
# Returns comprehensive inventory across all managed systems
```

## Multi-System Scenarios (Control Plane Gateway)

### Scenario 1: Media Server + Database Server (Centralized Management)

**Target Registry Configuration:**
```yaml
# targets.yaml
version: "1.0"
targets:
  media-server:
    id: "media-server"
    type: "remote"
    executor: "ssh"
    connection:
      host: "192.168.1.101"
      username: "admin"
      key_path: "${SSH_KEY_MEDIA}"
    capabilities:
      - "system:read"
      - "container:read"
      - "file:read"

  database-primary:
    id: "database-primary"
    type: "remote"
    executor: "ssh"
    connection:
      host: "192.168.1.102"
      username: "dba"
      key_path: "${SSH_KEY_DATABASE}"
    capabilities:
      - "system:read"
      - "container:read"
      - "database:read"
```

**Gateway Inventory Discovery:**
```python
# Scan applications across all targets
from src.services.target_registry import TargetRegistry

tr = TargetRegistry()
results = tr.scan_applications_across_targets()

# Results:
# {
#   "media-server": {"detected_count": 2, "applications": ["Jellyfin", "Plex"]},
#   "database-primary": {"detected_count": 2, "applications": ["PostgreSQL", "Redis"]}
# }
```

Now when you ask the AI for help through the gateway, it knows:
- `media-server` has Jellyfin and Plex
- `database-primary` has PostgreSQL and Redis

The AI can provide targeted recommendations for each system through the centralized gateway.

### Scenario 2: Development Environment (Multi-Target)

**Target Registry for Development Environment:**
```yaml
targets:
  dev-web:
    id: "dev-web"
    type: "remote"
    executor: "ssh"
    connection:
      host: "192.168.1.103"
      username: "dev"
      key_path: "${SSH_KEY_DEV}"
    capabilities:
      - "system:read"
      - "container:read"
      - "file:read"
      - "file:write"

  dev-db:
    id: "dev-db"
    type: "remote"
    executor: "ssh"
    connection:
      host: "192.168.1.104"
      username: "dev"
      key_path: "${SSH_KEY_DEV}"
    capabilities:
      - "system:read"
      - "container:read"
      - "database:read"
      - "database:write"
```

**Benefits with Control Plane Gateway:**
- AI knows this is a dev environment across multiple targets
- Can perform coordinated operations across dev-web and dev-db
- Understands development-specific capabilities (more permissive access)
- Centralized audit logging for all development activities

### Scenario 3: Production Environment (Strict Controls)

**Target Registry with Enhanced Security:**
```yaml
targets:
  prod-web:
    id: "prod-web"
    type: "remote"
    executor: "ssh"
    connection:
      host: "10.0.1.10"
      username: "prod"
      key_path: "${SSH_KEY_PROD}"
    capabilities:
      - "system:read"
      - "container:read"
    constraints:
      require_approval: true
      audit_level: "high"

  prod-db:
    id: "prod-db"
    type: "remote"
    executor: "ssh"
    connection:
      host: "10.0.1.20"
      username: "prod"
      key_path: "${SSH_KEY_PROD}"
    capabilities:
      - "system:read"
      - "container:read"
    constraints:
      require_approval: true
      audit_level: "high"
```

**Security Benefits:**
- Approval gates for production operations
- Enhanced audit logging
- Fine-grained capability control
- Centralized security policy enforcement

## Inventory Storage Format (Control Plane Gateway)

With the control plane gateway architecture, inventory data is stored centrally in the gateway:

### Gateway Inventory Storage

The inventory is stored as JSON at `/var/lib/systemmanager/inventory.json` on the gateway:

```json
{
  "gateway": {
    "version": "1.0",
    "deployed_at": "2025-12-13T20:30:00Z",
    "target_count": 3
  },
  "targets": {
    "web-server-01": {
      "target_id": "web-server-01",
      "hostname": "web-01",
      "container_id": "101",
      "system_type": "lxc",
      "executor": "ssh",
      "capabilities": ["system:read", "container:read", "file:read"],
      "last_scan": "2025-12-13T20:30:00Z"
    },
    "database-primary": {
      "target_id": "database-primary",
      "hostname": "db-01",
      "container_id": "102",
      "system_type": "lxc",
      "executor": "ssh",
      "capabilities": ["system:read", "container:read", "database:read"],
      "last_scan": "2025-12-13T20:30:00Z"
    }
  },
  "applications": {
    "web-server-01": {
      "nginx": {
        "name": "nginx",
        "type": "web-server",
        "version": "1.24.0",
        "port": 80,
        "service_name": "nginx",
        "config_path": "/etc/nginx",
        "data_path": "/var/www/html",
        "auto_detected": true,
        "notes": null,
        "added_at": "2025-12-13T20:30:00Z"
      }
    },
    "database-primary": {
      "postgresql": {
        "name": "postgresql",
        "type": "database",
        "version": "15.4",
        "port": 5432,
        "service_name": "postgresql",
        "config_path": "/etc/postgresql",
        "data_path": "/var/lib/postgresql",
        "auto_detected": true,
        "notes": null,
        "added_at": "2025-12-13T20:30:00Z"
      }
    }
  },
  "stacks": {},
  "audit_log": []
}
```

### Target-Specific Inventory

Each target can also maintain its own local inventory if needed, but the gateway provides centralized management.

## API Reference (Control Plane Gateway)

### MCP Tools (Gateway Interface)

#### `scan_installed_applications`

Auto-detect applications running on specified target(s).

**Parameters:**
- `target` (string): Target ID or "all" for all targets (default: current target)
- `save_to_inventory` (bool): Auto-save to inventory (default: `true`)

**Returns:**
```python
{
  "scanned_at": "2025-12-13T20:30:00",
  "targets_scanned": ["web-server-01", "database-primary"],
  "results": {
    "web-server-01": {
      "detected_count": 2,
      "applications": ["nginx", "nodejs-api"]
    },
    "database-primary": {
      "detected_count": 2,
      "applications": ["postgresql", "redis"]
    }
  }
}
```
  "applications": [
    {
      "name": "ollama",
      "type": "ai-llm",
      "version": "0.1.14",
      "port": 11434,
      "confidence": 0.9
    }
  ],
  "saved_to_inventory": true
}
```

#### `get_inventory`

Get complete inventory (system identity + applications + stacks).

**Returns:**
```python
{
  "system": {
    "hostname": "dev1",
    "container_id": "103",
    "display_name": "dev1-103"
  },
  "applications": {...},
  "stacks": {...},
  "inventory_path": "/var/lib/systemmanager/inventory.json"
}
```

#### `add_application_to_inventory`

Manually add an application.

**Parameters:**
- `name` (str): Application identifier
- `app_type` (str): Category/type
- `version` (str, optional): Version number
- `port` (int, optional): Port number
- `service_name` (str, optional): systemd service
- `config_path` (str, optional): Config directory
- `data_path` (str, optional): Data directory
- `notes` (str, optional): Custom notes

#### `remove_application_from_inventory`

Remove an application.

**Parameters:**
- `name` (str): Application to remove

#### `set_system_identity`

Configure system identity.

**Parameters:**
- `hostname` (str, optional): System hostname
- `container_id` (str, optional): Proxmox VMID/CTID
- `container_type` (str, optional): `lxc`, `vm`, `bare-metal`
- `mcp_server_name` (str, optional): Custom MCP server name

### MCP Prompts

#### `setup_inventory`

Interactive workflow to guide through inventory setup:
1. System identity configuration
2. Auto-scan for applications
3. Manual additions
4. Review and save

Use this for initial setup or when onboarding a new system.

## Best Practices

### 1. Set Up Inventory on First Run

After installing TailOpsMCP, immediately run:
```
You: "Let's set up the inventory for this system"
```

This gives the AI context from the start.

### 2. Re-Scan After Installing New Apps

Whenever you install a new application:
```
You: "I just installed Pi-hole. Can you update the inventory?"

AI: [Calls scan_installed_applications]
```

### 3. Document Custom Applications

For any custom/non-standard apps, add manual entries with good notes:
```python
add_application_to_inventory(
    name="homelab-dashboard",
    app_type="web-ui",
    port=3000,
    notes="Custom React dashboard for monitoring all services"
)
```

### 4. Use Descriptive MCP Server Names

For multi-system setups, use clear names:
- `media-101` - Media server in container 101
- `db-102` - Database server in container 102
- `ai-103` - AI/LLM server in container 103

### 5. Keep Inventory Updated

Periodically review and update:
```
You: "Show me the current inventory and update any stale information"
```

## Benefits of Inventory Tracking

### 1. Context-Aware Assistance

**Without Inventory:**
```
You: "The database is slow"
AI: "Which database? PostgreSQL? MySQL? MongoDB? Where is it running?"
```

**With Inventory:**
```
You: "The database is slow"
AI: "I see you have PostgreSQL 15.4 on port 5432. Let me check the logs and performance metrics..."
```

### 2. Better Security Audits

The AI knows what services you're running and can:
- Check for known vulnerabilities in specific versions
- Verify configurations for each application
- Audit exposed ports against expected services

### 3. Troubleshooting Efficiency

Example:
```
You: "Something is using port 11434"
AI: "That's Ollama (your AI/LLM service). It's configured to run on that port. Is it behaving unexpectedly?"
```

### 4. Documentation

The inventory serves as living documentation of your infrastructure. Export it for reference:

```python
inventory = get_inventory()
# Save to file, add to wiki, etc.
```

### 5. Migration Planning

When planning to migrate services:
```
You: "I want to move Ollama to a new container"
AI: "Based on your inventory, Ollama is currently on dev1-103:
- Config: /etc/ollama
- Data: /usr/share/ollama
- Service: ollama.service
- Port: 11434

Here's the migration plan..."
```

## Troubleshooting

### Application Not Auto-Detected

If an application isn't detected automatically:

1. **Check if it's running:**
   ```bash
   systemctl status <service-name>
   ps aux | grep <app-name>
   ```

2. **Add it manually:**
   ```python
   add_application_to_inventory(name="...", app_type="...", ...)
   ```

3. **Contribute detection rules**: See `src/services/app_scanner.py` to add new detection patterns

### Wrong Version Detected

The auto-detection tries to parse version output, but sometimes gets it wrong. Update manually:

```python
# First, check current inventory
get_inventory()

# Remove old entry
remove_application_from_inventory("app-name")

# Add corrected entry
add_application_to_inventory(name="app-name", version="correct-version", ...)
```

### Multiple Systems Using Same Inventory File

Each TailOpsMCP instance should have its own inventory file. By default, it's stored at `/var/lib/systemmanager/inventory.json` on each LXC container.

If running multiple instances on the same host (not recommended), set different paths:

```bash
export SYSTEMMANAGER_INVENTORY="/var/lib/systemmanager/inventory-dev1.json"
```

## Future Enhancements

Planned features for the inventory system:

- **Dependency Tracking**: Map which apps depend on which (e.g., app → PostgreSQL)
- **Health Checks**: Auto-monitor applications and track uptime
- **Change History**: Track when apps were added/removed/updated
- **Backup Integration**: Automatically include inventory data in backups
- **Cross-System Queries**: Ask about all systems at once ("Show me all databases across all containers")
- **Application Templates**: Quick-add common stacks (LEMP, MEAN, etc.)

## See Also

- [MCP Prompts Documentation](./docs/prompts.md) - Including the `setup_inventory` prompt
- [HOMELAB_FEATURES.md](./HOMELAB_FEATURES.md) - Roadmap for inventory features
- [API Documentation](./docs/tool_registry.md) - Complete tool reference
