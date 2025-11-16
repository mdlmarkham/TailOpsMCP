# SystemManager MCP Server

A secure Model Context Protocol (MCP) server for remote system management and monitoring. Provides AI agents with tools to monitor system health, manage Docker containers, explore file systems, and check network status.

**Security Model**: Designed for **Tailscale-only deployment** with defense-in-depth security. Tailscale ACLs provide network-level security, while application-level authorization (bearer tokens + scopes) and audit logging provide additional protection. See [Security Documentation](docs/SECURITY.md) for details.

## Features

- **System Monitoring**: Real-time CPU, memory, disk, and network metrics
- **Docker Management**: Container lifecycle operations and status monitoring
- **🆕 Intelligent Log Analysis**: AI-powered log analysis with root cause detection and recommendations
- **File System Exploration**: Directory listing and file search capabilities
- **Network Status**: Interface monitoring and connectivity testing
- **Defense-in-Depth Security**: 
  - **Network Layer**: Tailscale ACLs control WHO can reach server
  - **Application Layer**: Bearer tokens + scopes control WHAT they can do
  - **Audit Layer**: Comprehensive logging tracks WHO did WHAT with Tailscale identity
  - **Approval Gates**: Critical operations require interactive approval
- **Multiple Transports**: stdio and HTTP SSE protocol support
- **Tailscale Integration**: Native Tailscale Services deployment support

## Quick Start

### Prerequisites

- Python 3.11+
- Docker (for container management features)
- Tailscale (optional, for Tailscale Services deployment)

### Installation

```bash
# Clone the repository
git clone https://github.com/your-org/systemmanager-mcp-server.git
cd systemmanager-mcp-server

# Install dependencies
pip install -r requirements.txt

# Run the server
python -m src.mcp_server
```

### Docker Deployment

```bash
# Build and run with Docker
docker build -t systemmanager-mcp-server .
docker run -d \
  --name systemmanager-mcp \
  -p 8080:8080 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  systemmanager-mcp-server
```

### TOON Format (Token-Efficient Responses)

SystemManager supports TOON (Token-Oriented Object Notation) for 15-40% token savings:

```python
# Use format parameter on any MCP tool
response = await mcp.call_tool(
    "get_top_processes",
    {"limit": 10, "format": "toon"}  # vs "json" (default)
)

# JSON response: ~177 tokens
# TOON response: ~117 tokens  (33.9% savings!)
```

**Token Savings by Data Type:**
- **Processes/Connections**: 30-52% reduction (tabular format)
- **Container Lists**: 9-30% reduction
- **System Status**: 2-10% reduction (nested structures)
- **Overall Average**: 15-40% fewer tokens

**Example TOON Output:**
```javascript
// Instead of:
{"processes":[{"pid":1,"name":"systemd","cpu":0.0},...],"timestamp":"..."}

// TOON format:
{"processes":"[pid,name,cpu][1,\"systemd\",0.0]...","timestamp":"..."}
```

**Documentation**: See [TOON_INTEGRATION.md](./TOON_INTEGRATION.md) for benchmarks and usage

### Configuration

Create `/etc/systemmanager/config.yaml`:

```yaml
server:
  host: "localhost"
  port: 8080
  transport: "http-sse"
  auth_required: true

security:
  auth_tokens:
    - "your-secret-token-here"
  rate_limit: 100

logging:
  level: "INFO"
```

**⚠️ IMPORTANT SECURITY NOTE**: 
This configuration shows basic settings. For production deployments:
1. **Always deploy behind Tailscale** - Never expose directly to internet
2. **Enable authentication** - Set `SYSTEMMANAGER_REQUIRE_AUTH=true`
3. **Use scoped tokens** - Grant minimum required privileges
4. **Enable audit logging** - Track who did what
5. **See [Security Documentation](docs/SECURITY.md)** for complete security model

## Security

SystemManager implements **defense-in-depth** for tailnet deployments:

```
Network Layer (Tailscale ACLs)
  ↓ Controls WHO can reach server
Application Layer (Bearer Tokens + Scopes)
  ↓ Controls WHAT they can do
Approval Layer (Interactive Gates)
  ↓ Prevents unauthorized critical operations
Audit Layer (Tailscale Identity Logging)
  ↓ Tracks WHO did WHAT for forensics
```

### Quick Security Setup

```bash
# 1. Deploy behind Tailscale (REQUIRED)
tailscale up --advertise-tags=tag:systemmanager-server

# 2. Generate authentication secret
export SYSTEMMANAGER_SHARED_SECRET="$(openssl rand -hex 32)"

# 3. Enable authentication
export SYSTEMMANAGER_REQUIRE_AUTH=true

# 4. Generate scoped tokens
python scripts/mint_token.py --agent "monitoring" --scopes "readonly" --ttl 30d
python scripts/mint_token.py --agent "admin" --scopes "admin" --ttl 24h
```

### Token Scopes

| Scope | Permissions | Use Case |
|-------|------------|----------|
| `readonly` | View metrics, containers, logs | Monitoring, observability |
| `container:write` | Start/stop/restart containers | Container orchestration |
| `container:admin` | Update containers, pull images | Deployment automation |
| `system:admin` | Install packages, update system | Patch management |
| `admin` | All permissions | Emergency access only |

**Documentation**: 
- [Complete Security Model](docs/SECURITY.md)
- [Token Generation Examples](docs/security-configs/example-tokens.md)
- [Security Configurations](docs/security-configs/)

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

- Repository: [github.com/mdlmarkham/SystemManager](https://github.com/mdlmarkham/SystemManager)
- Issues: [GitHub Issues](https://github.com/mdlmarkham/SystemManager/issues)
- Discussions: [GitHub Discussions](https://github.com/mdlmarkham/SystemManager/discussions)