# Quickstart: TailOpsMCP Server Improvements

**Date**: 2025-11-15
**Purpose**: Quick implementation guide for production-ready MCP server improvements

## **Prerequisites**

- Python 3.11+ installed
- Docker installed (for container management features)
- Tailscale installed (optional, for Tailscale Services deployment)

## **Installation & Setup**

### **1. Install Dependencies**

```bash
# Install core dependencies
pip install mcp psutil docker pydantic cryptography

# Install development dependencies
pip install pytest pytest-asyncio black mypy
```

### **2. Clone and Setup**

```bash
# Clone the repository
git clone https://github.com/your-org/tailopsmcp-server.git
cd tailopsmcp-server

# Install in development mode
pip install -e .
```

## **Basic Configuration**

### **Environment Configuration**

Create `.env` file:
```env
# Server configuration
HOST=localhost
PORT=8080
TRANSPORT=stdio
AUTH_REQUIRED=true

# Security
RATE_LIMIT=100
MAX_FILE_SIZE=10485760

# Docker
DOCKER_SOCKET=/var/run/docker.sock

# Logging
LOG_LEVEL=INFO
LOG_FILE=/var/log/systemmanager-mcp.log
```

### **Basic Server Implementation**

```python
# src/mcp_server.py
from mcp.server.fastmcp import FastMCP
from mcp.server.session import ServerSession
from pydantic import BaseModel, Field
from typing import Dict
import psutil

# Initialize MCP server with structured output
mcp = FastMCP("TailOpsMCP")

# Define structured response models
class SystemStatus(BaseModel):
    cpu_percent: float = Field(..., ge=0, le=100)
    memory_usage: Dict[str, float]
    uptime: int

# System monitoring tool with structured output
@mcp.tool()
async def get_system_status() -> SystemStatus:
    """Get current system health metrics."""
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()

    return SystemStatus(
        cpu_percent=cpu_percent,
        memory_usage={
            "total": memory.total,
            "available": memory.available,
            "used": memory.used,
            "percent": memory.percent
        },
        uptime=int(psutil.boot_time())
    )

if __name__ == "__main__":
    mcp.run(transport="stdio")
```

## **Advanced Features**

### **1. OAuth 2.1 Authentication**

```python
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings

class TailOpsMCPTokenVerifier(TokenVerifier):
    async def verify_token(self, token: str) -> AccessToken | None:
        # Implement your token validation logic
        if validate_token(token):
            return AccessToken(
                token=token,
                scopes=["system:read", "docker:manage"],
                user_id="system-user"
            )
        return None

# Create protected server
mcp = FastMCP(
    "TailOpsMCP",
    token_verifier=TailOpsMCPTokenVerifier(),
    auth=AuthSettings(
        issuer_url="https://auth.example.com",
        required_scopes=["system:read"]
    )
)
```

### **2. Advanced System Monitoring**

```python
import asyncio
from mcp.server.fastmcp import Context

@mcp.tool()
async def get_detailed_system_metrics(ctx: Context) -> Dict:
    """Get comprehensive system metrics with progress reporting."""

    await ctx.info("Starting system metrics collection")

    # Report progress for long operations
    await ctx.report_progress(0.2, 1.0, "Collecting CPU metrics")
    cpu_times = psutil.cpu_times()
    cpu_percent = psutil.cpu_percent(interval=1, percpu=True)

    await ctx.report_progress(0.5, 1.0, "Collecting memory metrics")
    memory = psutil.virtual_memory()
    swap = psutil.swap_memory()

    await ctx.report_progress(0.8, 1.0, "Collecting disk metrics")
    disk_io = psutil.disk_io_counters()

    await ctx.info("System metrics collection complete")

    return {
        "cpu": {
            "percent": cpu_percent,
            "times": cpu_times._asdict()
        },
        "memory": {
            "total": memory.total,
            "available": memory.available,
            "used": memory.used,
            "percent": memory.percent,
            "swap": swap._asdict()
        },
        "disk": disk_io._asdict() if disk_io else {}
    }
```

### **3. Docker Container Management**

```python
import docker
from docker.errors import DockerException

class DockerManager:
    def __init__(self):
        self.client = None

    async def ensure_connected(self):
        if not self.client:
            try:
                self.client = docker.DockerClient.from_env()
            except DockerException as e:
                raise RuntimeError(f"Docker daemon unavailable: {e}")

@mcp.tool()
async def get_container_stats(container_id: str) -> Dict:
    """Get detailed container statistics."""
    manager = DockerManager()
    await manager.ensure_connected()

    try:
        container = manager.client.containers.get(container_id)
        stats = container.stats(stream=False)

        return {
            "container_id": container_id,
            "name": container.name,
            "status": container.status,
            "cpu_stats": stats.get("cpu_stats", {}),
            "memory_stats": stats.get("memory_stats", {}),
            "network_stats": stats.get("networks", {})
        }
    except docker.errors.NotFound:
        raise ValueError(f"Container {container_id} not found")
```

## **Testing**

### **Unit Tests**

```python
# tests/test_system_monitor.py
import pytest
from src.services.system_monitor import SystemMonitor

@pytest.mark.asyncio
async def test_get_system_status():
    """Test system status retrieval."""
    monitor = SystemMonitor()
    status = await monitor.get_status()

    assert status.cpu_percent >= 0
    assert status.cpu_percent <= 100
    assert status.uptime > 0
    assert "total" in status.memory_usage
```

### **Contract Tests**

```python
# tests/contract/test_mcp_protocol.py
import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client

@pytest.mark.asyncio
async def test_mcp_protocol_compliance():
    """Test MCP protocol compliance."""
    async with stdio_client(("python", "-m", "src.mcp_server")) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # Test tool listing
            tools = await session.list_tools()
            assert len(tools.tools) > 0

            # Test tool execution
            result = await session.call_tool("get_system_status", {})
            assert "cpu_percent" in result.content[0].text
```

## **Deployment**

### **Docker Deployment**

```dockerfile
# Multi-stage Dockerfile
FROM python:3.11-slim as builder

RUN apt-get update && apt-get install -y gcc python3-dev
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

FROM python:3.11-slim

# Security hardening
RUN addgroup --system --gid 1000 systemmanager \
    && adduser --system --uid 1000 --ingroup systemmanager --shell /bin/false systemmanager

# Copy Python packages from builder
COPY --from=builder /root/.local /home/systemmanager/.local
COPY --chown=systemmanager:systemmanager . /app

WORKDIR /app
USER systemmanager

EXPOSE 8080
CMD ["python", "-m", "src.mcp_server"]
```

### **Docker Compose**

```yaml
version: "3.8"
services:
  systemmanager-mcp:
    build: .
    container_name: systemmanager-mcp
    user: "1000:1000"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./config:/etc/systemmanager:ro
    ports:
      - "8080:8080"
    environment:
      - LOG_LEVEL=INFO
```

### **LXC Container Deployment**

```bash
# LXC configuration for Proxmox
pct create 100 local:vztmpl/ubuntu-22.04-standard_22.04-1_amd64.tar.gz \
  --storage local-lvm \
  --unprivileged 1 \
  --features nesting=1 \
  --net0 name=eth0,bridge=vmbr0,firewall=1 \
  --memory 512 \
  --cores 2

# Start container and deploy
pct start 100
pct exec 100 -- bash -c "
  apt-get update && apt-get install -y python3 python3-pip
  pip3 install mcp psutil docker pydantic
  python3 -m src.mcp_server
"
```

## **Monitoring & Health Checks**

### **Health Check Endpoint**

```python
from mcp.server.fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse

mcp = FastMCP("TailOpsMCP")

@mcp.custom_route(path="/health", methods=["GET"])
async def health_check(request: Request) -> JSONResponse:
    """Health check endpoint for load balancers."""
    return JSONResponse({
        "status": "healthy",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat()
    })
```

### **Metrics Endpoint**

```python
@mcp.custom_route(path="/metrics", methods=["GET"])
async def get_metrics(request: Request) -> JSONResponse:
    """Prometheus-style metrics endpoint."""
    metrics = {
        "requests_total": 1234,
        "requests_per_minute": 12,
        "active_sessions": 5,
        "memory_usage": psutil.virtual_memory().percent
    }
    return JSONResponse(metrics)
```

## **Security Hardening**

### **Transport Security**

```python
from mcp.server.transport_security import TransportSecuritySettings

security_settings = TransportSecuritySettings(
    enable_dns_rebinding_protection=True,
    allowed_hosts=["localhost:8080", "api.example.com"],
    allowed_origins=["https://app.example.com"]
)

mcp = FastMCP("TailOpsMCP", transport_security=security_settings)
```

### **Rate Limiting**

```python
from mcp.server.middleware import RateLimitMiddleware

mcp = FastMCP(
    "TailOpsMCP",
    middleware=[
        RateLimitMiddleware(max_requests=100, window_seconds=60)
    ]
)
```

## **Troubleshooting**

### **Common Issues**

1. **Docker Connection Issues**:
   ```bash
   # Check Docker socket permissions
   ls -la /var/run/docker.sock
   sudo chmod 666 /var/run/docker.sock
   ```

2. **Permission Errors**:
   ```bash
   # Run as non-root user
   useradd -r -s /bin/false systemmanager
   chown -R systemmanager:systemmanager /app
   ```

3. **Port Already in Use**:
   ```bash
   # Change port in configuration
   echo "PORT=8081" >> .env
   ```

### **Debug Mode**

```python
# Enable debug logging
import logging
logging.basicConfig(level=logging.DEBUG)

# Run with debug mode
mcp.run(transport="stdio", debug=True)
```

This quickstart guide provides a comprehensive foundation for implementing production-ready improvements to the TailOpsMCP server with security, monitoring, and deployment best practices.
