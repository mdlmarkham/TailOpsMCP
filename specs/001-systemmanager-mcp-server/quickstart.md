# Quickstart: SystemManager MCP Server

**Date**: 2025-11-15  
**Purpose**: Get the SystemManager MCP server running quickly with basic configuration.

## Prerequisites

- Python 3.11+ installed
- Docker installed (for container management features)
- Tailscale installed (optional, for Tailscale Services deployment)

## Installation

### Method 1: Docker (Recommended)

```bash
# Clone the repository
git clone https://github.com/your-org/systemmanager-mcp-server.git
cd systemmanager-mcp-server

# Build the Docker image
docker build -t systemmanager-mcp-server .

# Run the server
docker run -d \
  --name systemmanager-mcp \
  -p 8080:8080 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /etc/systemmanager:/etc/systemmanager \
  systemmanager-mcp-server
```

### Method 2: Python Virtual Environment

```bash
# Clone the repository
git clone https://github.com/your-org/systemmanager-mcp-server.git
cd systemmanager-mcp-server

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\\Scripts\\activate.bat  # Windows

# Install dependencies
pip install -r requirements.txt

# Run the server
python -m src.mcp_server
```

## Basic Configuration

Create a configuration file at `/etc/systemmanager/config.yaml`:

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
  max_file_size: 10485760

logging:
  level: "INFO"
  file: "/var/log/systemmanager-mcp.log"

docker:
  socket_path: "/var/run/docker.sock"

filesystem:
  allowed_paths:
    - "/var/log"
    - "/tmp"
    - "/home"
```

## Tailscale Services Deployment

### Enable Tailscale Services

1. Ensure Tailscale is installed and authenticated
2. Create Tailscale service configuration:

```json
{
  "version": "1",
  "services": {
    "svc:systemmanager-mcp": {
      "endpoints": {
        "tcp:8080": "localhost:8080"
      }
    }
  }
}
```

3. Start the service:
```bash
# Start the MCP server first, then:
tailscale serve --config=tailscale-service.json
```

## Basic Usage

### Connect with MCP Client

```python
import asyncio
from mcp import Client

async def main():
    # Connect to the server
    async with Client.connect("http://localhost:8080") as client:
        # Get system status
        status = await client.call_tool("get_system_status", {})
        print("System Status:", status)
        
        # List Docker containers
        containers = await client.call_tool("get_container_list", {})
        print("Containers:", containers)
        
        # List directory
        files = await client.call_tool("list_directory", {"path": "/var/log"})
        print("Log files:", files)

asyncio.run(main())
```

### Command Line Interface

```bash
# System status
python -m src.cli.deploy system-status

# Docker containers
python -m src.cli.deploy list-containers

# File system info
python -m src.cli.deploy list-directory --path /var/log
```

## Security Configuration

### Authentication

1. **Bearer Token Authentication**:
   ```bash
   curl -H "Authorization: Bearer your-token" \
        http://localhost:8080/api/v1/system/status
   ```

2. **Environment Variables**:
   ```bash
   export SYSTEMMANAGER_AUTH_TOKEN="your-token"
   python -m src.mcp_server
   ```

### Access Control

Configure allowed operations in `config.yaml`:

```yaml
security:
  allowed_operations:
    - "get_system_status"
    - "get_container_list"
    - "list_directory"
    # Add or remove operations as needed
```

## Monitoring and Logs

### Log Files

- Application logs: `/var/log/systemmanager-mcp.log`
- Audit logs: `/var/log/systemmanager-audit.log`
- Docker logs: `docker logs systemmanager-mcp`

### Health Checks

```bash
# Check if server is running
curl http://localhost:8080/health

# Check system metrics
curl http://localhost:8080/metrics
```

## Troubleshooting

### Common Issues

1. **Docker socket permission denied**:
   ```bash
   # Add user to docker group
   sudo usermod -aG docker $USER
   ```

2. **Port already in use**:
   ```bash
   # Change port in config.yaml
   server:
     port: 8081
   ```

3. **Authentication errors**:
   ```bash
   # Check auth token in config
   # Regenerate token if needed
   openssl rand -hex 32
   ```

### Debug Mode

Enable debug logging for troubleshooting:

```yaml
logging:
  level: "DEBUG"
  file: "/var/log/systemmanager-debug.log"
```

## Next Steps

- Review the full API documentation
- Configure monitoring and alerting
- Set up backup and recovery procedures
- Implement custom tools for your specific needs

This quickstart guide should get you up and running with the SystemManager MCP server. For advanced configuration and customization, refer to the full documentation.