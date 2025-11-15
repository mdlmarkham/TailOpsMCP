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

### Available Tools

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

### Tailscale Services

```bash
# Enable Tailscale Services
tailscale serve --config=deploy/tailscale-service.json
```

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

- Tool Registry: `docs/tool_registry.md` — detailed tool catalog and schemas.
- LLM Prompt Templates: `docs/prompts.md` — prompt templates, decision rules, and examples.
- Integration & Deployment: `docs/integration.md` — multi-host Tailscale deployment, tokens, and hardening.

## Support

- Documentation: [docs.systemmanager.local](https://docs.systemmanager.local)
- Issues: [GitHub Issues](https://github.com/your-org/systemmanager-mcp-server/issues)
- Discussions: [GitHub Discussions](https://github.com/your-org/systemmanager-mcp-server/discussions)