# TailOpsMCP

🛰️ **TailOpsMCP — A secure MCP control surface for Tailscale-connected homelabs**

> **Secure remote monitoring and AI-assisted operations for your homelab over Tailscale — powered by MCP**  
> Model Context Protocol (MCP) server for managing Proxmox LXC containers, Docker stacks, and system administration - all through natural language with AI assistants.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-compatible-blue.svg)](https://www.docker.com/)
[![Proxmox](https://img.shields.io/badge/proxmox-LXC-orange.svg)](https://www.proxmox.com/)
[![Tailscale](https://img.shields.io/badge/tailscale-integrated-blue.svg)](https://tailscale.com/)

---

## 🎯 What is TailOpsMCP?

TailOpsMCP is an MCP (Model Context Protocol) server that lets you manage your home lab infrastructure using AI assistants like Claude, ChatGPT, or any MCP-compatible client. Instead of remembering complex commands, just ask:

- *"Deploy my monitoring stack from GitHub"*
- *"Analyze the auth logs for security issues"*
- *"What's using all the CPU on dev1?"*
- *"Update all packages on the server"*

Perfect for **home lab enthusiasts**, **self-hosters**, and **DevOps engineers** running Proxmox, Docker, and Tailscale.

---

## ✨ Key Features

### 🚀 **Current Capabilities**

- ✅ **Smart Inventory Management** - Auto-detect and track applications running on LXC (Jellyfin, Pi-hole, Ollama, PostgreSQL, etc.)
- ✅ **Multi-System Support** - Identify systems by hostname + container ID for managing multiple LXCs with one AI
- ✅ **MCP Prompts** - Pre-configured workflows for common tasks (security audit, health check, troubleshooting, inventory setup)
- ✅ **Docker Compose Stack Management** - Deploy GitOps-style stacks from repos (like Portainer/Komodo)
- ✅ **Proxmox LXC Detection** - Automatic virtualization environment detection
- ✅ **AI-Powered Log Analysis** - Root cause detection with actionable recommendations
- ✅ **System Monitoring** - CPU, memory, disk, network with historical metrics
- ✅ **Docker Container Management** - Start/stop/restart/logs for all containers
- ✅ **Systemd Service Management** - Control system services
- ✅ **Package Management** - Update systems, install packages
- ✅ **Security Auditing** - AI-powered security log analysis
- ✅ **File Operations** - Read, search, and analyze system files
- ✅ **Network Diagnostics** - Interface status, connectivity tests

### 🔒 **Security First**

- ✅ **OAuth 2.1 with TSIDP** - Tailscale Identity Provider authentication
- ✅ **Token Introspection** - RFC 7662 compliant token validation
- ✅ **Systemd Hardening** - Secrets in environment files, not command line
- ✅ **Audit Logging** - Complete tracking of all operations
- ✅ **Scope-Based Access** - Fine-grained permission control

### 🔮 **Roadmap** (See [HOMELAB_FEATURES.md](./HOMELAB_FEATURES.md))

- 🔄 **LXC Network Auditing** - Review and audit container network configs
- 🔄 **Backup & Snapshots** - Automated backups with verification
- 🔄 **Certificate Management** - Let's Encrypt automation
- 🔄 **Reverse Proxy Management** - Traefik/Nginx/Caddy configuration
- 🔄 **Proxmox API Integration** - Full VM/container management
- 🔄 **Security Scanning** - Container vulnerability detection

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────┐
│  AI Assistant (Claude/ChatGPT/etc)             │
│  - Natural language commands                   │
│  - Context-aware suggestions                   │
└──────────────────┬──────────────────────────────┘
                   │ MCP Protocol
┌──────────────────▼──────────────────────────────┐
│  TailOpsMCP MCP Server                          │
│  ┌──────────────────────────────────────────┐  │
│  │ OAuth/OIDC (Tailscale Identity)         │  │
│  └──────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────┐  │
│  │ AI-Powered Analysis                      │  │
│  │ - Log analysis with root cause detection│  │
│  │ - Security auditing                      │  │
│  │ - Performance recommendations            │  │
│  └──────────────────────────────────────────┘  │
└──────────────────┬──────────────────────────────┘
                   │
    ┌──────────────┼──────────────┬──────────────┐
    │              │              │              │
┌───▼────┐  ┌─────▼─────┐  ┌────▼─────┐  ┌────▼─────┐
│Proxmox │  │  Docker   │  │ Systemd  │  │Tailscale │
│  LXC   │  │ Compose   │  │ Services │  │  Network │
└────────┘  └───────────┘  └──────────┘  └──────────┘
```

---

## 🚀 Quick Start

### Method 1: Proxmox LXC (Recommended)

Use the automated Proxmox installer script (inspired by [tteck's scripts](https://community-scripts.github.io/ProxmoxVE/)):

```bash
bash -c "$(wget -qLO - https://raw.githubusercontent.com/mdlmarkham/TailOpsMCP/master/ct/build.func)"
```

This will:
- Create a Debian 12 LXC container (2GB RAM, 2 CPU cores, 4GB disk)
- Install Python 3.12, Docker, and all dependencies
- Walk you through Tailscale OAuth setup
- Configure and start the systemd service
- Provide complete installation summary

### Method 2: Manual Installation (Any Linux)

#### Prerequisites

- **OS**: Linux (Ubuntu 22.04+, Debian 11+, Proxmox LXC)
- **Python**: 3.11 or higher
- **Docker**: For container management features (optional)
- **Tailscale**: For secure OAuth authentication (optional but recommended)

#### Installation Steps

```bash
# 1. Download and run the installer
curl -fsSL https://raw.githubusercontent.com/mdlmarkham/TailOpsMCP/master/install.sh | sudo bash

# Or clone and run manually
git clone https://github.com/mdlmarkham/TailOpsMCP.git
cd TailOpsMCP
sudo bash install.sh
```

The interactive installer will:
1. ✅ Check system requirements (Python, Docker, Tailscale)
2. 🔧 Choose authentication method (OAuth or Token)
3. 🔐 Configure Tailscale OAuth (with step-by-step guide)
4. 📦 Install TailOpsMCP and dependencies
5. ⚙️ Create systemd service
6. 🚀 Start and verify the server

#### Post-Installation

```bash
# Check service status
sudo systemctl status systemmanager-mcp

# View logs
sudo journalctl -u systemmanager-mcp -f

# Test the server
curl http://localhost:8080/.well-known/oauth-protected-resource/mcp
```

### One-Shot Installation

```bash
# Download and run the installer
curl -fsSL https://raw.githubusercontent.com/mdlmarkham/TailOpsMCP/master/install.sh | sudo bash
```

The installer will:
1. ✅ Check system requirements
2. ✅ Install Python dependencies
3. ✅ Set up systemd service
4. ✅ Configure Tailscale OAuth (if available)
5. ✅ Create secure environment file
6. ✅ Start the server

### Manual Installation

```bash
# 1. Clone repository
git clone https://github.com/mdlmarkham/TailOpsMCP.git
cd TailOpsMCP

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure authentication (choose one)

# Option A: Tailscale OAuth (Recommended)
cp deploy/.env.template .env
nano .env  # Add your TSIDP credentials
chmod 600 .env

# Option B: Token-based auth (Simpler)
export SYSTEMMANAGER_AUTH_MODE=token
export SYSTEMMANAGER_SHARED_SECRET="your-secret-here"

# 4. Start the server
python -m src.mcp_server
```

---

## 🔐 Tailscale Integration

TailOpsMCP supports **Tailscale Identity Provider (TSIDP)** for OAuth 2.1 authentication.

### Setup TSIDP

1. **Enable TSIDP** in your Tailscale admin console:
   ```
   Settings → OAuth → Identity Provider → Enable
   ```

2. **Register OAuth client**:
   - Navigate to OAuth applications
   - Create new application
   - Set redirect URI: `https://vscode.dev/redirect`
   - Note the Client ID and Secret

3. **Configure TailOpsMCP**:
   ```bash
   # Edit /opt/systemmanager/.env
   SYSTEMMANAGER_AUTH_MODE=oidc
   TSIDP_URL=https://tsidp.tail12345.ts.net
   TSIDP_CLIENT_ID=your-client-id
   TSIDP_CLIENT_SECRET=your-client-secret
   SYSTEMMANAGER_BASE_URL=http://your-server.tail12345.ts.net:8080
   ```

4. **Restart service**:
   ```bash
   sudo systemctl restart systemmanager-mcp
   ```

### Tailscale ACLs

Add to your `tailscale-acl.json`:
```json
{
  "acls": [
    {
      "action": "accept",
      "src": ["group:admins"],
      "dst": ["tag:infrastructure:8080"]
    }
  ],
  "tagOwners": {
    "tag:infrastructure": ["group:admins"]
  }
}
```

---

## 🐳 Proxmox Integration

### LXC Container Detection

TailOpsMCP automatically detects when running inside a Proxmox LXC container:

```json
{
  "virtualization": {
    "type": "lxc",
    "method": "systemd-detect-virt"
  }
}
```

### Recommended LXC Configuration

```bash
# /etc/pve/lxc/103.conf
arch: amd64
cores: 2
memory: 2048
net0: name=eth0,bridge=vmbr0,firewall=1,ip=dhcp
rootfs: local-lvm:vm-103-disk-0,size=8G

# Enable Docker in LXC
features: nesting=1,keyctl=1
lxc.apparmor.profile: unconfined
lxc.cgroup2.devices.allow: c 10:200 rwm  # /dev/net/tun for Tailscale
```

### Network Auditing (Coming Soon)

```python
# Audit LXC network configuration
audit_lxc_network(container_id=103)

# Output:
# - Network interfaces and bridges
# - Firewall rules
# - Port forwards
# - Security recommendations
```

---

## 📦 Application Inventory

TailOpsMCP can track what applications are running directly on your LXC container (not just Docker), providing context-aware assistance.

### Initial Setup

Use the interactive **setup_inventory** prompt to configure your system:

```
You: "Let's set up the inventory for this system"

AI will guide you through:
1. System identification (hostname, container ID, type)
2. Auto-scan for installed applications
3. Manual additions if needed
4. Review and save
```

### Auto-Detection

TailOpsMCP can auto-detect these applications:

- **Media Servers**: Jellyfin, Plex
- **Network Services**: Pi-hole, AdGuard Home, WireGuard
- **Databases**: PostgreSQL, MySQL, MariaDB, MongoDB, Redis
- **Web Servers**: Nginx, Apache
- **Home Automation**: Home Assistant
- **Monitoring**: Prometheus, Grafana
- **AI/LLM**: Ollama
- **Other**: Nextcloud, Portainer, and more

### API Examples

```python
# Scan for installed applications
scan_installed_applications(save_to_inventory=True)

# View complete inventory
get_inventory()
# Returns: system identity, applications, Docker stacks

# Manually add an application
add_application_to_inventory(
    name="ollama",
    app_type="ai-llm",
    version="0.1.14",
    port=11434,
    service_name="ollama",
    config_path="/etc/ollama",
    notes="Running Llama 3.2 model"
)

# Update system identity (for multi-system setups)
set_system_identity(
    hostname="dev1",
    container_id="103",
    container_type="lxc",
    mcp_server_name="dev1-103"  # Unique name for this MCP instance
)
```

### Multi-System Management

When managing multiple LXC containers with a single AI:

1. Each system gets a unique identifier: `hostname-containerID` (e.g., `dev1-103`)
2. The inventory tracks what's running on each system
3. AI provides context-aware suggestions based on what you have installed
4. Inventory stored in `/var/lib/systemmanager/inventory.json` per system

### Benefits

✓ **Context-Aware Help**: AI knows what apps you're running  
✓ **Better Troubleshooting**: Targeted recommendations based on your stack  
✓ **Documentation**: Auto-generated infrastructure documentation  
✓ **Security Audits**: Application-specific security checks  
✓ **Performance Analysis**: Understanding resource usage by app  

---

## 🐋 Docker Integration

### Docker Compose Stack Management

Deploy and manage stacks like Portainer/Komodo:

```python
# Deploy stack from GitHub
deploy_stack(
    stack_name="monitoring",
    repo_url="https://github.com/user/prometheus-stack",
    branch="main",
    env_vars={"DOMAIN": "metrics.home.lab"}
)

# Update stack (git pull + docker compose up)
update_stack("monitoring")

# List all stacks
list_stacks()
```

### Container Management

```python
# AI-powered log analysis
analyze_container_logs(
    name_or_id="nginx",
    context="Why is it restarting?"
)

# Start/stop/restart
manage_container(action="restart", name_or_id="nginx")

# Get container list with status
get_container_list()
```

---

## 📊 Usage Examples

### With Claude Desktop

Add to your `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "tailopsmcp": {
      "type": "http",
      "url": "http://your-server.tail12345.ts.net:8080/mcp"
    }
  }
}
```

Then ask Claude:
- *"Show me system status"*
- *"What are the top processes by CPU usage?"*
- *"Analyze the syslog for security issues"*
- *"Check if my web server container is running"*
- *"Test connectivity to database.home.lab:5432"*
- *"Pull the latest nginx image"*

### With GitHub Copilot Chat (VS Code)

The MCP protocol is supported natively - just install and reload VS Code.

Example prompts:
- *"@tailopsmcp what containers are running?"*
- *"@tailopsmcp analyze Docker logs for my app container"*
- *"@tailopsmcp check system resource usage"*

### Programmatic Access (Python)

```python
import requests

# Token-based auth
headers = {"Authorization": f"Bearer {token}"}

# OAuth-based auth
# (OAuth flow handled by MCP client)

response = requests.post(
    "http://your-server:8080/mcp",
    json={
        "method": "tools/call",
        "params": {
            "name": "get_system_status",
            "arguments": {"format": "json"}
        }
    },
    headers=headers
)

print(response.json())
```

---

## 🔧 Configuration

### Environment Variables

TailOpsMCP is configured via `/opt/systemmanager/.env`:

```bash
# Authentication Mode (oidc or token)
SYSTEMMANAGER_AUTH_MODE=oidc
SYSTEMMANAGER_REQUIRE_AUTH=true

# Tailscale OAuth (TSIDP)
TSIDP_URL=https://tsidp.tail12345.ts.net
TSIDP_CLIENT_ID=your_client_id
TSIDP_CLIENT_SECRET=your_client_secret
SYSTEMMANAGER_BASE_URL=http://server.tail12345.ts.net:8080

# Or Token-based
# SYSTEMMANAGER_SHARED_SECRET=your_secret_here

# Logging
LOG_LEVEL=INFO  # DEBUG, INFO, WARNING, ERROR
```

### Service Management

```bash
# Check status
sudo systemctl status systemmanager-mcp

# View logs
sudo journalctl -u systemmanager-mcp -f

# Restart
sudo systemctl restart systemmanager-mcp

# Enable/disable auto-start
sudo systemctl enable systemmanager-mcp
sudo systemctl disable systemmanager-mcp
```

### Update to Latest Version

```bash
# Run the update script (Proxmox LXC only)
pct exec 103 -- bash -c "$(wget -qLO - https://raw.githubusercontent.com/mdlmarkham/TailOpsMCP/master/ct/build.func)" -s --update

# Or manually
cd /opt/systemmanager
sudo systemctl stop systemmanager-mcp
git pull
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
sudo systemctl start systemmanager-mcp
```

---

## 🛠️ Advanced Usage

### Custom Scopes and Permissions

TailOpsMCP supports fine-grained scope-based authorization:

```python
# Define scopes for different users/teams
SCOPES = {
    "system:read": "Read system status",
    "system:write": "Modify system settings",
    "docker:read": "View containers",
    "docker:write": "Manage containers",
    "network:read": "View network info",
    "network:write": "Modify network settings"
}
```

Configure in TSIDP OAuth application or token claims.

### AI-Powered Log Analysis

TailOpsMCP uses MCP sampling for intelligent log analysis:

```bash
# Analyze container logs
analyze_container_logs(
    name_or_id="nginx",
    lines=500,
    context="Why is the container crashing?",
    use_ai=True
)

# Analyze system logs (syslog, journal)
analyze_container_logs(
    name_or_id="/var/log/syslog",
    context="Find security issues"
)
```

Returns:
- **Summary**: Overview of log contents
- **Errors**: Identified errors with severity
- **Root Cause**: AI-determined likely causes
- **Recommendations**: Actionable fixes

### Docker Compose GitOps Workflow

```python
# Deploy stack from GitHub repo
deploy_stack(
    stack_name="monitoring",
    repo_url="https://github.com/user/prometheus-stack",
    branch="main",
    compose_file="docker-compose.yml",
    env_vars={
        "GRAFANA_DOMAIN": "grafana.home.lab",
        "PROMETHEUS_RETENTION": "30d"
    }
)

# Update stack (git pull + redeploy)
update_stack("monitoring")

# Remove stack
remove_stack("monitoring", remove_volumes=False)
```

### Systemd Service Management (Roadmap)

```python
# Manage systemd services
manage_service(
    action="restart",  # start, stop, restart, enable, disable
    service_name="nginx"
)

# Get service status
get_service_status("nginx")
```

---

## 🐛 Troubleshooting

### Service Won't Start

```bash
# Check logs for errors
sudo journalctl -u systemmanager-mcp -n 100 --no-pager

# Common issues:
# 1. Python not found - check venv path in service file
# 2. Missing dependencies - reinstall: pip install -r requirements.txt
# 3. Port already in use - check: sudo lsof -i :8080
```

### OAuth Authentication Failing

```bash
# Verify TSIDP configuration
curl https://tsidp.tail12345.ts.net/.well-known/openid-configuration

# Test token introspection
curl -X POST https://tsidp.tail12345.ts.net/api/v2/oauth/introspect \
  -u "client_id:client_secret" \
  -d "token=your_access_token"

# Check server logs
sudo journalctl -u systemmanager-mcp -f | grep -i oauth
```

### Container Management Not Working

```bash
# Verify Docker socket permissions
ls -la /var/run/docker.sock

# If permission denied, add systemmanager user to docker group
# (Current version runs as root, but for non-root:)
sudo usermod -aG docker systemmanager

# Test Docker access
docker ps
```

### Tailscale Connectivity Issues

```bash
# Check Tailscale status
tailscale status

# Verify DNS resolution
dig server.tail12345.ts.net

# Test local access first
curl http://localhost:8080/.well-known/oauth-protected-resource/mcp

# Then test via Tailscale hostname
curl http://server.tail12345.ts.net:8080/.well-known/oauth-protected-resource/mcp
```

### High Memory Usage

TailOpsMCP is lightweight but Docker containers add up:

```bash
# Check memory usage
free -h

# Limit systemmanager memory (edit service file)
sudo nano /etc/systemd/system/systemmanager-mcp.service

# Add under [Service]:
MemoryMax=512M
MemoryHigh=384M

sudo systemctl daemon-reload
sudo systemctl restart systemmanager-mcp
```

---

## 🗺️ Roadmap

### ✅ Current Features (v1.0)

- [x] System monitoring (CPU, memory, disk, network)
- [x] Docker container management
- [x] AI-powered log analysis (Docker + system logs)
- [x] Network diagnostics (ping, traceroute, port testing)
- [x] SSL certificate checking
- [x] Tailscale OAuth (TSIDP) authentication
- [x] Token-based authentication
- [x] HTTP streaming transport (MCP)
- [x] Proxmox LXC detection

### 🚧 Phase 2 (Q1 2025)

- [ ] Docker Compose stack management (deploy/update/remove)
- [ ] Systemd service management
- [ ] LXC network auditing
- [ ] Package management (apt/yum update/install)
- [ ] File operations (read/write/search)
- [ ] Enhanced security scopes

### 🔮 Phase 3 (Q2 2025)

- [ ] Proxmox API integration (VM/CT management)
- [ ] Backup and snapshot management
- [ ] Resource usage alerts and notifications
- [ ] Multi-node cluster support
- [ ] Web UI dashboard (optional)

### 💡 Phase 4 (Future)

- [ ] Ansible playbook execution
- [ ] Infrastructure-as-Code validation
- [ ] Cost tracking and optimization
- [ ] Security scanning and compliance
- [ ] Integration with Home Assistant
- [ ] Mobile app for emergency access

See [HOMELAB_FEATURES.md](./HOMELAB_FEATURES.md) for detailed roadmap.

---

## 🤝 Contributing

We welcome contributions from the home lab community!

### Ways to Contribute

1. **Report Bugs**: Open an issue with details about the problem
2. **Feature Requests**: Suggest new tools or improvements
3. **Code Contributions**: Submit pull requests
4. **Documentation**: Help improve docs and examples
5. **Share Your Setup**: Tell us how you're using TailOpsMCP

### Development Setup

```bash
# Clone the repository
git clone https://github.com/mdlmarkham/TailOpsMCP.git
cd TailOpsMCP

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run tests
pytest

# Run server in development mode
python -m src.mcp_server
```

### Code Style

- Follow PEP 8 guidelines
- Add type hints to all functions
- Write docstrings for new tools
- Include tests for new features

### Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`pytest`)
5. Commit with clear message (`git commit -m 'Add amazing feature'`)
6. Push to branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

---

## 📜 License

MIT License - see [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **[Proxmox VE](https://www.proxmox.com/)** - Best open-source hypervisor for home labs
- **[Tailscale](https://tailscale.com/)** - Zero-config VPN that just works
- **[FastMCP](https://github.com/jlowin/fastmcp)** - Python framework for MCP servers
- **[Model Context Protocol](https://modelcontextprotocol.io/)** - Standard for AI assistant integrations
- **[Community Scripts](https://community-scripts.github.io/ProxmoxVE/)** - Inspiration for the installer
- **[Home Lab Community](https://www.reddit.com/r/homelab/)** - For all the inspiration and support

---

## 📞 Support

- **Documentation**: [https://github.com/mdlmarkham/TailOpsMCP](https://github.com/mdlmarkham/TailOpsMCP)
- **Issues**: [GitHub Issues](https://github.com/mdlmarkham/TailOpsMCP/issues)
- **Discussions**: [GitHub Discussions](https://github.com/mdlmarkham/TailOpsMCP/discussions)

---

<div align="center">

**Built with ❤️ for the Home Lab Community**

If you find this useful, please ⭐ star the repo!

</div>

## Usage

### MCP Client Connection

```python
import asyncio
from mcp import Client

async def main():
    async with Client.connect("http://localhost:8080") as client:
        # Get system status
        status = await client.call_tool("get_system_status", {})
        print("System Status:", status)
        
        # List Docker containers
        containers = await client.call_tool("get_container_list", {})
        print("Containers:", containers)

asyncio.run(main())
```

### Available MCP Tools (22 Total)

**Note**: Tool access controlled by scopes. See [Security Documentation](docs/SECURITY.md) for authorization requirements.

#### System Monitoring (5 tools) - Scope: `system:read`
- `get_system_status` — CPU, memory, disk, uptime, load average
- `get_top_processes` — Top processes by CPU/memory (supports `format="toon"`)
- `get_network_status` — Network interfaces with addresses and stats
- `get_network_io_counters` — Network I/O statistics summary
- `health_check` — Server health status (no auth required)

#### Docker Management (6 tools)
- `get_container_list` — List containers (scope: `container:read`, supports `format="toon"`)
- `manage_container` — Start/stop/restart/logs (scope: `container:write`, **HIGH RISK**)
- `analyze_container_logs` 🆕 — AI-powered log analysis with root cause detection (scope: `container:read`)
- `list_docker_images` — List images (scope: `container:read`)
- `update_docker_container` — Update with latest image (scope: `container:admin`, **CRITICAL**, requires approval)
- `pull_docker_image` — Pull from registry (scope: `docker:admin`, **CRITICAL**, requires approval)

#### File Operations (1 consolidated tool) - Scope: `file:read`
- `file_operations` — List/read/tail/search files (**HIGH RISK** - path restrictions apply)

#### Network Diagnostics (8 tools)
- `ping_host` — Ping with latency (scope: `network:diag`, supports `format="toon"`)
- `test_port_connectivity` — TCP connectivity (scope: `network:diag`)
- `dns_lookup` — DNS resolution (scope: `network:diag`)
- `check_ssl_certificate` — SSL cert validation (scope: `network:diag`)
- `http_request_test` — HTTP testing (scope: `network:diag`, **HIGH RISK**, requires approval)
- `get_active_connections` — Network connections (scope: `network:read`, supports `format="toon"`)
- `get_docker_networks` — Docker networks (scope: `container:read`)
- `traceroute` — Route tracing (scope: `network:diag`)

#### System Administration (3 tools) - Scope: `system:admin`
- `check_system_updates` — Check for updates (scope: `system:read`)
- `update_system_packages` — Update all packages (**CRITICAL**, requires approval)
- `install_package` — Install packages (**CRITICAL**, requires approval)

**Risk Levels**:
- 🟢 **Low**: Read-only operations, safe for monitoring
- 🟡 **Moderate**: Network diagnostics, limited impact
- 🟠 **High**: Write operations, requires scoped access
- 🔴 **Critical**: Destructive operations, requires approval + scoped access

## Deployment

### Security Checklist

Before deploying to production:

- [ ] ✅ **Deploy behind Tailscale** (NEVER expose to public internet)
- [ ] ✅ **Configure Tailscale ACLs** to limit access to tagged devices
- [ ] ✅ **Enable authentication** (`SYSTEMMANAGER_REQUIRE_AUTH=true`)
- [ ] ✅ **Generate scoped tokens** with appropriate TTLs
- [ ] ✅ **Enable audit logging** to track operations
- [ ] ✅ **Review [Security Documentation](docs/SECURITY.md)**

### Deployment Options

#### Standard Linux Deployment

```bash
# Systemd service
sudo cp deploy/systemd/systemmanager-mcp.service /etc/systemd/system/
sudo systemctl enable systemmanager-mcp
sudo systemctl start systemmanager-mcp
```

### Tailscale Services (Zero-Config Service Discovery)

Tailscale Services provides enterprise-grade service discovery and high availability:

```bash
# Quick setup (interactive)
sudo /opt/systemmanager/scripts/setup_tailscale_service.sh

# Manual setup
tailscale serve \
  --service=svc:systemmanager-mcp \
  --tls-terminated-tcp=8080 \
  tcp://localhost:8080

# Then approve in admin console:
# https://login.tailscale.com/admin/services
```

**Benefits:**
- 🌐 **Stable Names**: Access via `http://systemmanager-mcp.yourtailnet.ts.net:8080`
- 🔄 **High Availability**: Multiple hosts with automatic failover
- 🔍 **Auto-Discovery**: DNS SRV records for service discovery
- 🔐 **Service ACLs**: Granular access control per service
- 🚀 **Zero Reconfiguration**: Move hosts without updating clients

**Documentation**: See [TAILSCALE_SERVICES.md](./TAILSCALE_SERVICES.md) for complete guide

### ProxMox LXC Containers

Deploy as a lightweight container with minimal resource requirements.

## Development

### Project Structure

```
src/
├── models/          # Data models
├── services/        # Business logic
├── cli/            # Command-line interface
└── lib/            # Utilities and helpers

tests/              # Test suite
deploy/             # Deployment configurations
docs/               # Documentation
```

### Testing

```bash
# Run tests
pytest tests/

# Run with coverage
pytest --cov=src tests/

# Run specific test categories
pytest tests/unit/
pytest tests/integration/
pytest tests/contract/
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

Please ensure all changes adhere to the project constitution and include appropriate tests.

## License

MIT License - see LICENSE file for details.

## Documentation

### Core Documentation
- **Getting Started**: This README
- **🔒 Security Model**: [docs/SECURITY.md](./docs/SECURITY.md) — **READ THIS FIRST** for tailnet deployments
- **Installation**: [install.sh](./install.sh) — Automated Linux deployment
- **API Reference**: [docs/tool_registry.md](./docs/tool_registry.md) — Complete MCP tool catalog
- **Integration Guide**: [docs/integration.md](./docs/integration.md) — Multi-host deployment

### Security & Configuration
- **Security Documentation**: [docs/SECURITY.md](./docs/SECURITY.md) — Defense-in-depth model, threat scenarios
- **Configuration Examples**: [docs/security-configs/](./docs/security-configs/) — Minimal, production, maximum security configs
- **Token Generation**: [docs/security-configs/example-tokens.md](./docs/security-configs/example-tokens.md) — Token examples by use case
- **Tailscale ACLs**: [docs/security-configs/tailscale-acl.production.jsonc](./docs/security-configs/tailscale-acl.production.jsonc) — Production ACL template

### Advanced Features
- **🆕 Intelligent Log Analysis**: [docs/INTELLIGENT_LOG_ANALYSIS.md](./docs/INTELLIGENT_LOG_ANALYSIS.md) — AI-powered log analysis with sampling
- **TOON Format**: [TOON_INTEGRATION.md](./TOON_INTEGRATION.md) — 15-40% token savings guide
- **Tailscale Services**: [TAILSCALE_SERVICES.md](./TAILSCALE_SERVICES.md) — Zero-config service discovery
- **Testing Guide**: [TESTING_REMOTE_GUIDE.md](./TESTING_REMOTE_GUIDE.md) — Remote testing procedures

## Support

- Repository: [github.com/mdlmarkham/TailOpsMCP](https://github.com/mdlmarkham/TailOpsMCP)
- Issues: [GitHub Issues](https://github.com/mdlmarkham/TailOpsMCP/issues)
- Discussions: [GitHub Discussions](https://github.com/mdlmarkham/TailOpsMCP/discussions)