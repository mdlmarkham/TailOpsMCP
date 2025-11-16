# SystemManager MCP Server

A secure Model Context Protocol (MCP) server for remote system management and monitoring. Provides AI agents with tools to monitor system health, manage Docker containers, explore file systems, and check network status.

## Features

- **System Monitoring**: Real-time CPU, memory, disk, and network metrics
- **Docker Management**: Container lifecycle operations and status monitoring
- **File System Exploration**: Directory listing and file search capabilities
- **Network Status**: Interface monitoring and connectivity testing
- **Security First**: Authentication, authorization, and audit logging
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

### Available MCP Tools

### System Monitoring (6 tools)
- `get_system_status` — CPU, memory, disk, uptime, load average
- `get_system_overview` — Comprehensive system + containers + network snapshot
- `get_top_processes` — Top processes by CPU/memory (supports `format=\"toon\"`)
- `get_network_status` — Network interfaces with addresses and stats
- `get_network_io_counters` — Network I/O statistics summary
- `health_check` — Server health status

### Docker Management (5 tools)
- `get_container_list` — List all containers with status (supports `format=\"toon\"`)
- `start_container` — Start a container by name/ID
- `stop_container` — Stop a container gracefully
- `restart_container` — Restart a container
- `get_container_logs` — Retrieve recent container logs

### File Operations (5 tools)
- `list_directory` — List directory contents
- `get_file_info` — Get file metadata and stats
- `read_file` — Read file contents with line limits
- `tail_file` — Get last N lines from file (for logs)
- `search_files` — Search for files by pattern (wildcards)

### Network Diagnostics (11 tools)
- `ping_host` — Ping with latency stats (supports `format=\"toon\"`)
- `test_tcp_port` — TCP connectivity test with latency
- `dns_lookup` — DNS resolution (A, AAAA, MX, TXT, CNAME)
- `check_ssl_certificate` — SSL cert validation and expiry
- `http_request_test` — HTTP request performance testing
- `get_active_connections` — Network connections summary (supports `format=\"toon\"`)
- `check_open_ports` — Port scanning on localhost
- `get_docker_networks` — Docker network inspection
- `traceroute` — Network route tracing (requires traceroute binary)

**All tools support optional `format` parameter**: `\"json\"` (default) or `\"toon\"` (token-efficient)

- `get_system_status` - System health metrics
- `get_container_list` - Docker container information
- `list_directory` - File system directory listing
- `search_files` - File search by pattern
- `get_network_status` - Network interface status

## Security

- **Authentication**: Bearer token authentication
- **Authorization**: Role-based access control
- **Audit Logging**: Comprehensive operation logging
- **Resource Limits**: Rate limiting and operation constraints
- **TLS Support**: Encrypted communication for HTTP transport

## Deployment Options

### Standard Linux Deployment

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
- **Installation**: [install.sh](./install.sh) — Automated Linux deployment
- **API Reference**: [docs/tool_registry.md](./docs/tool_registry.md) — Complete MCP tool catalog
- **Integration Guide**: [docs/integration.md](./docs/integration.md) — Multi-host deployment & security
- **LLM Prompts**: [docs/prompts.md](./docs/prompts.md) — Prompt templates and decision rules

### Advanced Features
- **TOON Format**: [TOON_INTEGRATION.md](./TOON_INTEGRATION.md) — 15-40% token savings guide
- **Tailscale Services**: [TAILSCALE_SERVICES.md](./TAILSCALE_SERVICES.md) — Zero-config service discovery
- **Testing Guide**: [TESTING_REMOTE_GUIDE.md](./TESTING_REMOTE_GUIDE.md) — Remote testing procedures

## Support

- Repository: [github.com/mdlmarkham/SystemManager](https://github.com/mdlmarkham/SystemManager)
- Issues: [GitHub Issues](https://github.com/mdlmarkham/SystemManager/issues)
- Discussions: [GitHub Discussions](https://github.com/mdlmarkham/SystemManager/discussions)