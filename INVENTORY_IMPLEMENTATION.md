# Application Inventory & Multi-System Support - Implementation Summary

**Date:** November 16, 2025  
**Commit:** 7234289  
**Feature:** Smart Inventory Management for LXC Applications

---

## 🎯 Problem Solved

**Before:** SystemManager couldn't differentiate between systems or track applications running directly on LXC containers (outside Docker). When managing multiple Proxmox containers, the AI had no context about what was deployed where.

**After:** Each SystemManager instance can identify itself (e.g., `dev1-103`) and maintain an inventory of installed applications (Jellyfin, Pi-hole, Ollama, PostgreSQL, etc.), enabling context-aware assistance.

---

## 📦 What Was Implemented

### 1. Data Models (src/inventory.py)

#### SystemIdentity
```python
@dataclass
class SystemIdentity:
    hostname: str                    # e.g., "dev1"
    container_id: Optional[str]      # Proxmox VMID/CTID, e.g., "103"
    container_type: Optional[str]    # "lxc", "vm", "bare-metal"
    mcp_server_name: Optional[str]   # Custom MCP instance name
    
    def get_display_name(self) -> str:
        # Returns "dev1-103" or custom name
```

**Purpose:** Uniquely identify this SystemManager instance when managing multiple LXC containers.

#### ApplicationMetadata
```python
@dataclass
class ApplicationMetadata:
    name: str                        # e.g., "ollama"
    type: str                        # e.g., "ai-llm"
    version: Optional[str]           # e.g., "0.1.14"
    port: Optional[int]              # e.g., 11434
    service_name: Optional[str]      # systemd service name
    config_path: Optional[str]       # Config directory
    data_path: Optional[str]         # Data directory
    auto_detected: bool              # True if found by scanner
    notes: Optional[str]             # Custom documentation
```

**Purpose:** Track metadata about applications running on the LXC container.

### 2. Application Scanner (src/services/app_scanner.py)

**17 Detection Rules** for common home lab applications:

| Category | Apps |
|----------|------|
| Media | Jellyfin, Plex |
| Network | Pi-hole, AdGuard Home, WireGuard |
| Databases | PostgreSQL, MySQL, MariaDB, MongoDB, Redis |
| Web | Nginx, Apache |
| Monitoring | Prometheus, Grafana |
| Other | Home Assistant, Nextcloud, Portainer, Ollama |

**Detection Signals:**
- ✓ systemd services (0.4 confidence weight)
- ✓ Running processes (0.3 confidence weight)
- ✓ Listening ports (0.2 confidence weight)
- ✓ File existence (0.3 confidence weight)

**Minimum confidence:** 0.3 (30%) to report detection

**Example Output:**
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
      "service_name": "ollama",
      "confidence": 0.9
    }
  ]
}
```

### 3. MCP Server Enhancements (src/mcp_server.py)

#### Automatic System Detection at Startup

```python
# Auto-detects on first run:
system_identity = SystemIdentity(
    hostname=socket.gethostname(),      # e.g., "dev1"
    container_id=extract_from_cgroup(), # e.g., "103" from /proc/self/cgroup
    container_type="lxc"                # Detected from cgroup
)
```

**Logs:**
```
INFO: Auto-detected system identity: dev1-103
INFO: MCP Server ID: dev1-103
```

#### New MCP Tools

1. **`scan_installed_applications`**
   - Auto-detect applications using ApplicationScanner
   - Optionally save to inventory automatically
   - Returns detected apps with confidence scores

2. **`get_inventory`**
   - Return complete inventory (system + apps + stacks)
   - Shows inventory file path
   - Timestamp of retrieval

3. **`add_application_to_inventory`**
   - Manually add an application
   - All metadata fields optional except name and type
   - Marks as `auto_detected: false`

4. **`remove_application_from_inventory`**
   - Remove application by name
   - Returns error if not found

5. **`set_system_identity`**
   - Configure/update system identity
   - All fields optional (uses current values if not provided)
   - Updates global `system_identity` variable
   - Useful for multi-system setups

#### New MCP Prompt: `setup_inventory`

Interactive workflow that guides users through:
1. System identity configuration
2. Auto-scanning for applications
3. Manual additions for missed apps
4. Review and save

**Usage:**
```
You: "Let's set up the inventory for this system"
AI: [Walks through the workflow step-by-step]
```

### 4. Documentation

#### docs/inventory.md (New - 600+ lines)
- Complete guide to inventory management
- Auto-detection details
- Multi-system scenarios
- API reference
- Best practices
- Troubleshooting

#### README.md (Updated)
- Added "Smart Inventory Management" to feature list
- New section: "📦 Application Inventory" with examples
- Multi-system management explanation
- Links to inventory.md

#### docs/prompts.md (Updated)
- Added `setup_inventory` prompt documentation
- Usage examples
- Link to inventory.md

---

## 🚀 Usage Examples

### Initial Setup

```
User: "Let's set up the inventory for this system"

AI: "I'll help you set up the inventory. First, let me check the current identity..."
[Calls get_inventory]

AI: "This system is auto-detected as 'dev1-103' (LXC container). 
     Now scanning for installed applications..."
[Calls scan_installed_applications]

AI: "Found 5 applications:
- PostgreSQL 15.4 (port 5432)
- Nginx 1.24.0 (port 80)
- Ollama 0.1.14 (port 11434)
- Redis 7.0.12 (port 6379)
- Prometheus 2.45.0 (port 9090)

Would you like to add any other applications?"

User: "Yes, I also run a custom Python API on port 8000"

AI: [Calls add_application_to_inventory]
"Added! Inventory is complete."
```

### Multi-System Scenario

**System 1 (media-101):**
```python
set_system_identity(hostname="media", container_id="101", mcp_server_name="media-101")
scan_installed_applications()
# Detects: Jellyfin, Plex
```

**System 2 (db-102):**
```python
set_system_identity(hostname="db", container_id="102", mcp_server_name="db-102")
scan_installed_applications()
# Detects: PostgreSQL, Redis
```

Now queries like *"show me all databases"* can be routed to `db-102`, while media queries go to `media-101`.

### Context-Aware Troubleshooting

**Without Inventory:**
```
User: "The database is slow"
AI: "Which database? PostgreSQL? MySQL? Where is it located?"
```

**With Inventory:**
```
User: "The database is slow"
AI: "I see you have PostgreSQL 15.4 on port 5432. Let me check logs and metrics..."
[Calls manage_container, analyze_container_logs, get_system_status]
```

---

## 📊 Benefits

### 1. Context-Aware Assistance
AI knows what applications are running and can provide targeted help.

### 2. Multi-System Support
Each LXC container is uniquely identified: `hostname-containerID`

### 3. Better Security Audits
Can check for vulnerabilities in specific application versions.

### 4. Efficient Troubleshooting
Knows port mappings, service names, config paths automatically.

### 5. Living Documentation
Inventory serves as auto-generated infrastructure documentation.

### 6. Migration Planning
Knows what needs to be moved and where data is stored.

---

## 🔧 Technical Details

### Inventory Storage

**File:** `/var/lib/systemmanager/inventory.json`

**Format:**
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
      "auto_detected": true,
      "added_at": "2025-11-16T20:30:00Z"
    }
  },
  "stacks": {},
  "hosts": {}
}
```

### Environment Variables

```bash
# Override inventory location (optional)
export SYSTEMMANAGER_INVENTORY="/custom/path/inventory.json"
```

### Auto-Detection at Startup

On first run (when `inventory.json` doesn't exist):
1. Detects hostname via `socket.gethostname()`
2. Checks `/proc/self/cgroup` for LXC container ID
3. Determines container type (`lxc`, `vm`, or `bare-metal`)
4. Creates `SystemIdentity` and saves to inventory
5. Logs: `"Auto-detected system identity: dev1-103"`

---

## 🎨 Code Architecture

```
src/
├── inventory.py                 # Data models (SystemIdentity, ApplicationMetadata)
├── mcp_server.py               # MCP tools + prompt + auto-detection
└── services/
    └── app_scanner.py          # Application detection engine

docs/
└── inventory.md                # Complete documentation

Data Flow:
1. Server starts → Auto-detect system identity
2. User runs `setup_inventory` prompt
3. AI calls `scan_installed_applications`
4. ApplicationScanner checks services/processes/ports/files
5. Results saved to inventory.json
6. Future queries use inventory for context
```

---

## 🧪 Testing on dev1

To test this feature on your dev1 server:

```bash
# 1. Deploy to dev1
ssh root@dev1.tailf9480.ts.net "cd /opt/systemmanager && git pull && systemctl restart systemmanager-mcp"

# 2. Check logs for auto-detection
ssh root@dev1.tailf9480.ts.net "journalctl -u systemmanager-mcp -n 50 | grep identity"

# Expected:
# INFO: Auto-detected system identity: dev1-103
# INFO: MCP Server ID: dev1-103

# 3. Test scanning via MCP
# In Claude/Copilot:
"Let's set up the inventory for this system"

# Or via Python:
python << 'EOF'
import requests
response = requests.post(
    "http://dev1.tailf9480.ts.net:8080/mcp",
    json={
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "scan_installed_applications",
            "arguments": {"save_to_inventory": True}
        },
        "id": 1
    }
)
print(response.json())
EOF

# 4. View inventory file
ssh root@dev1.tailf9480.ts.net "cat /var/lib/systemmanager/inventory.json"
```

---

## 📈 Future Enhancements

- [ ] Dependency tracking (app → database relationships)
- [ ] Health check integration per application
- [ ] Change history (track when apps added/removed)
- [ ] Cross-system queries ("show all PostgreSQL instances")
- [ ] Application templates (quick-add LEMP stack, etc.)
- [ ] Backup integration (include inventory in backups)
- [ ] Web UI for inventory management

---

## 📝 Files Changed

| File | Lines Changed | Description |
|------|---------------|-------------|
| `src/inventory.py` | +65 | Added SystemIdentity, ApplicationMetadata, inventory methods |
| `src/services/app_scanner.py` | +372 (new) | Application detection engine with 17 rules |
| `src/mcp_server.py` | +286 | Auto-detection, 5 MCP tools, setup_inventory prompt |
| `docs/inventory.md` | +620 (new) | Complete documentation |
| `README.md` | +85 | Updated features, added inventory section |
| `docs/prompts.md` | +24 | Added setup_inventory prompt docs |

**Total:** ~1,452 lines added

---

## ✅ Completion Checklist

- [x] Data models (SystemIdentity, ApplicationMetadata)
- [x] Application scanner with 17 detection rules
- [x] Auto-detection at MCP server startup
- [x] 5 new MCP tools for inventory management
- [x] Interactive setup_inventory prompt
- [x] Complete documentation (inventory.md)
- [x] Updated README with inventory section
- [x] Updated prompts.md
- [x] Git commit and push to GitHub
- [ ] Deploy and test on dev1 server
- [ ] Verify with live MCP client (Claude/Copilot)

---

## 🎯 Next Steps

1. **Deploy to dev1:**
   ```bash
   ssh root@dev1.tailf9480.ts.net "cd /opt/systemmanager && git pull && systemctl restart systemmanager-mcp"
   ```

2. **Test the setup_inventory prompt:**
   ```
   "Let's set up the inventory for this system"
   ```

3. **Verify detection:**
   - Check what applications are auto-detected
   - Manually add any missed apps
   - Review the inventory.json file

4. **Multi-system test (if you have multiple LXCs):**
   - Deploy to second container
   - Configure unique MCP server names
   - Test cross-system queries

---

**Commit:** `7234289`  
**Branch:** `master`  
**Status:** ✅ Ready for deployment
