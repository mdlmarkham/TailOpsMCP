# Application Inventory & Multi-System Management

## Overview

TailOpsMCP's inventory system solves a common problem in home lab management: **knowing what's running where**. 

When you have multiple Proxmox LXC containers, each potentially running different services (Jellyfin on one, PostgreSQL on another, Ollama on a third), it becomes hard for an AI assistant to provide context-aware help. The inventory system creates a "scratchpad" of what applications are deployed on each system.

## Key Concepts

### System Identity

Each TailOpsMCP instance identifies itself with:

- **Hostname**: The system's hostname (e.g., `dev1`, `media-server`)
- **Container ID**: Proxmox VMID/CTID if running in LXC (e.g., `103`)
- **Container Type**: `lxc`, `vm`, or `bare-metal`
- **MCP Server Name**: Optional custom name for this MCP instance

This allows you to run multiple TailOpsMCP instances (one per LXC) and have them uniquely identified.

**Example**: `dev1-103` clearly identifies this as the `dev1` container with ID 103.

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

The scanner uses multiple signals to detect applications:

1. **systemd Services**: Checks for running services by name
2. **Processes**: Looks for running processes
3. **Listening Ports**: Detects applications by their default ports
4. **File System**: Checks for config files and directories
5. **Version Commands**: Attempts to query version information

Each detection gets a confidence score (0.0 to 1.0). Applications need at least 0.3 confidence to be reported.

## Usage Workflows

### Initial Setup (Interactive)

Use the `setup_inventory` MCP prompt:

```
You: "Let's set up the inventory for this system"

AI: "I'll help you set up the inventory. First, let me check the current system identity..."

[AI calls get_inventory to see current state]

AI: "I see this is 'dev1' (LXC container 103). Would you like to customize the MCP server name?"

You: "Keep it as dev1-103"

AI: "Great! Now let me scan for installed applications..."

[AI calls scan_installed_applications]

AI: "Found 5 applications:
- PostgreSQL 15.4 (port 5432)
- Nginx 1.24.0 (port 80)
- Ollama 0.1.14 (port 11434)
- Redis 7.0.12 (port 6379)
- Prometheus 2.45.0 (port 9090)

Should I add any other applications that weren't detected?"

You: "Yes, I also run a custom Python API on port 8000"

[AI calls add_application_to_inventory]

AI: "Done! Inventory is now complete. I'll use this context to provide better assistance."
```

### Programmatic Setup

```python
# 1. Set system identity
set_system_identity(
    hostname="dev1",
    container_id="103",
    container_type="lxc",
    mcp_server_name="dev1-103"
)

# 2. Auto-scan for applications
result = scan_installed_applications(save_to_inventory=True)
# Returns: {"detected_count": 5, "applications": [...]}

# 3. Manually add missed applications
add_application_to_inventory(
    name="custom-api",
    app_type="web-api",
    port=8000,
    service_name="custom-api",
    notes="Internal Python API for home automation"
)

# 4. Review complete inventory
inventory = get_inventory()
# Returns:
# {
#   "system": {"hostname": "dev1", "container_id": "103", ...},
#   "applications": {...},
#   "stacks": {...}
# }
```

## Multi-System Scenarios

### Scenario 1: Media Server + Database Server

**LXC 101 (media-101):**
```python
# Media server setup
set_system_identity(hostname="media", container_id="101", mcp_server_name="media-101")
scan_installed_applications()  # Detects: Jellyfin, Plex
```

**LXC 102 (db-102):**
```python
# Database server setup
set_system_identity(hostname="db", container_id="102", mcp_server_name="db-102")
scan_installed_applications()  # Detects: PostgreSQL, Redis
```

Now when you ask the AI for help, it knows:
- `media-101` has Jellyfin and Plex
- `db-102` has PostgreSQL and Redis

The AI can provide targeted recommendations for each system.

### Scenario 2: Development Environment

**LXC 103 (dev1-103):**
```python
set_system_identity(hostname="dev1", container_id="103", container_type="lxc")
scan_installed_applications()

# Add custom apps
add_application_to_inventory(
    name="local-ollama",
    app_type="ai-llm",
    version="0.1.14",
    port=11434,
    notes="Running Llama 3.2 and CodeLlama models"
)

add_application_to_inventory(
    name="dev-postgres",
    app_type="database",
    version="15.4",
    port=5432,
    notes="Development database - safe to reset"
)
```

**Benefits:**
- AI knows this is a dev environment (can be more aggressive with changes)
- Knows which Ollama models are available
- Understands the PostgreSQL instance is for development

## Inventory File Format

The inventory is stored as JSON at `/var/lib/systemmanager/inventory.json`:

```json
{
  "system": {
    "hostname": "dev1",
    "container_id": "103",
    "container_type": "lxc",
    "mcp_server_name": "dev1-103"
  },
  "applications": {
    "ollama": {
      "name": "ollama",
      "type": "ai-llm",
      "version": "0.1.14",
      "port": 11434,
      "service_name": "ollama",
      "config_path": "/etc/ollama",
      "data_path": "/usr/share/ollama",
      "auto_detected": true,
      "notes": null,
      "added_at": "2025-11-16T20:30:00Z"
    },
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
      "added_at": "2025-11-16T20:30:00Z"
    }
  },
  "stacks": {},
  "hosts": {}
}
```

## API Reference

### MCP Tools

#### `scan_installed_applications`

Auto-detect applications running on the system.

**Parameters:**
- `save_to_inventory` (bool): Auto-save to inventory (default: `true`)

**Returns:**
```python
{
  "scanned_at": "2025-11-16T20:30:00",
  "system": "dev1-103",
  "detected_count": 5,
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
