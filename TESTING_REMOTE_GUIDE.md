# Remote System Testing Guide for TailOpsMCP Server

**Last Updated**: November 15, 2025

## Table of Contents
1. [Project Overview](#project-overview)
2. [Architecture & Components](#architecture--components)
3. [Pre-Deployment Review](#pre-deployment-review)
4. [Remote Deployment Options](#remote-deployment-options)
5. [Testing Strategy](#testing-strategy)
6. [Validation Checklist](#validation-checklist)

---

## Project Overview

**TailOpsMCP Server** is an async Python application implementing the Model Context Protocol (MCP) for secure remote system management. It provides AI agents with tools to monitor system health, manage Docker containers, explore filesystems, and check network status.

**Key Characteristics:**
- Protocol: Model Context Protocol (MCP)
- Python Version: 3.11+
- Dependencies: fastmcp, docker SDK, psutil, pydantic, cryptography
- Deployment: Docker container or systemd service
- Transport: HTTP-SSE or stdio
- Security: Bearer token authentication, audit logging
- Optional: Tailscale Services integration for secure remote access

---

## Architecture & Components

### Core Modules

| Module | Purpose | Status |
|--------|---------|--------|
| `src/mcp_server.py` | Main MCP server implementation | ⚠️ See Issues |
| `src/models/` | Pydantic data models (system, containers, files, network) | ✅ Good |
| `src/services/` | System monitoring, Docker management, file exploration | ✅ Good |
| `src/tools/` | Stack and network tools for MCP tools | ✅ Good |
| `src/auth/token_auth.py` | HMAC-based token verification | ✅ Good |
| `src/utils/` | Error handling, retry logic, audit logging, toon formatting | ✅ Good |

### Deployment Artifacts

- **Docker**: `Dockerfile` (Python 3.11-slim, non-root user)
- **Compose**: `docker-compose.yml` with optional Tailscale sidecar
- **Systemd**: `deploy/systemd/systemmanager-mcp.service` for Linux
- **Scripts**: `scripts/setup_dev_env.ps1` for Windows development

### Test Coverage

| Test File | Coverage |
|-----------|----------|
| `test_system_status.py` | System model validation |
| `test_token_auth.py` | Token verification and expiry |
| `test_toon.py` | Toon formatting logic |
| `test_stack_network.py` | Network stack operations |
| `contract/test_mcp_protocol.py` | MCP protocol compliance |

---

## Pre-Deployment Review

### ⚠️ Critical Issues Found

#### Issue #1: Blocking CPU Sampling in Async Context
**Severity**: HIGH  
**Location**: `src/mcp_server.py:35`, `src/services/system_monitor.py:18`  
**Problem**: `psutil.cpu_percent(interval=1)` blocks the event loop for 1 second, stalling all concurrent MCP requests.

**Recommendation**: 
```python
# Replace blocking call
cpu_percent = psutil.cpu_percent(interval=None)  # Non-blocking
# OR use executor
cpu_percent = await asyncio.to_thread(psutil.cpu_percent, interval=1)
```

#### Issue #2: Missing Windows Platform Guard
**Severity**: MEDIUM  
**Location**: `src/mcp_server.py:55`  
**Problem**: Direct call to `os.getloadavg()` raises `AttributeError` on Windows (not POSIX).

**Recommendation**:
```python
load_avg = {}
if hasattr(os, 'getloadavg'):
    load_avg = {"1m": os.getloadavg()[0], "5m": os.getloadavg()[1], "15m": os.getloadavg()[2]}
else:
    load_avg = {"1m": None, "5m": None, "15m": None, "note": "Not available on this platform"}
```

### ✅ Strengths Observed

- **Security**: Non-root Docker user, restrictive systemd hardening
- **Error Handling**: Comprehensive error models with categorization
- **Validation**: Pydantic models with strict type checking
- **Logging**: Structured audit logging with correlation IDs
- **Health Checks**: Built-in HTTP health endpoint
- **Token Auth**: HMAC-based authentication with expiry validation

---

## Remote Deployment Options

### Option 1: Docker (Recommended for Linux)

#### Prerequisites
- Docker Engine 20.10+
- 2GB RAM, 10GB disk minimum
- Docker socket accessible or Docker daemon running

#### Deployment Steps

```bash
# On remote machine
git clone https://github.com/your-org/systemmanager-mcp-server.git
cd systemmanager-mcp-server

# Build image
docker build -t systemmanager-mcp-server:latest .

# Create config
mkdir -p /etc/systemmanager
cat > /etc/systemmanager/config.yaml << 'EOF'
server:
  host: "0.0.0.0"
  port: 8080
  transport: "http-sse"
  auth_required: true

security:
  auth_tokens:
    - "dev-token-$(date +%s)"  # Replace with real token
  rate_limit: 100

logging:
  level: "INFO"
  file: "/var/log/systemmanager/mcp.log"

docker:
  socket_path: "/var/run/docker.sock"
EOF

# Run container
docker run -d \
  --name systemmanager-mcp \
  --restart unless-stopped \
  -p 8080:8080 \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v /etc/systemmanager:/etc/systemmanager:ro \
  -v /var/log/systemmanager:/var/log/systemmanager \
  -e LOG_LEVEL=INFO \
  systemmanager-mcp-server:latest

# Verify health
curl -s http://localhost:8080/health | jq .
```

### Option 2: Systemd Service (Linux/VM)

#### Prerequisites
- Python 3.11+ installed
- Systemd init system
- sudo access

#### Installation Steps

```bash
# Install system dependencies
sudo apt-get update
sudo apt-get install -y python3.11 python3.11-venv python3-pip git

# Create service user
sudo useradd -r -s /bin/false systemmanager

# Clone repository
cd /opt
sudo git clone https://github.com/your-org/systemmanager-mcp-server.git
cd systemmanager-mcp-server
sudo chown -R systemmanager:systemmanager /opt/systemmanager-mcp-server

# Setup virtual environment
sudo -u systemmanager python3.11 -m venv venv
sudo -u systemmanager venv/bin/pip install --upgrade pip
sudo -u systemmanager venv/bin/pip install -r requirements.txt

# Copy systemd service
sudo cp deploy/systemd/systemmanager-mcp.service /etc/systemd/system/

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable systemmanager-mcp
sudo systemctl start systemmanager-mcp

# Verify status
sudo systemctl status systemmanager-mcp
```

### Option 3: Tailscale Services (Secure Remote Access)

#### Prerequisites
- Tailscale installed on remote machine
- Tailnet admin access
- MCP server running locally (Docker or systemd)

#### Setup

```bash
# 1. Authenticate Tailscale
tailscale up

# 2. Create service config
cat > /etc/systemmanager/tailscale-service.json << 'EOF'
{
  "version": "1",
  "services": {
    "svc:systemmanager-mcp": {
      "macsKey": "tskey-...",  # Generate with `tailscale serve`
      "endpoints": {
        "tcp:8080": "localhost:8080"
      }
    }
  }
}
EOF

# 3. Start Tailscale sidecar
docker run -d \
  --name systemmanager-tailscale \
  --restart unless-stopped \
  -v /var/lib/tailscale:/var/lib/tailscale \
  -v /dev/net/tun:/dev/net/tun \
  --cap-add=NET_ADMIN \
  --cap-add=SYS_MODULE \
  tailscale/tailscale:latest

# 4. Access from any Tailscale device
curl -H "Authorization: Bearer <token>" \
  https://systemmanager-mcp.<tailnet>.ts.net/tools/get_system_status
```

---

## Testing Strategy

### Phase 1: Local Unit Tests (Pre-Deployment)

```bash
# Setup
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install pytest pytest-asyncio

# Run tests
pytest tests/ -v
pytest tests/ --cov=src --cov-report=html
```

**Expected Results**:
- `test_system_status.py`: ✅ Model validation passes
- `test_token_auth.py`: ✅ Token verification works
- `test_toon.py`: ✅ Toon formatting works
- `test_stack_network.py`: ✅ Network operations pass

### Phase 2: Docker Image Validation

```bash
# Build and inspect
docker build -t systemmanager-mcp-server:test .
docker run --rm systemmanager-mcp-server:test python -c "import src.mcp_server; print('OK')"

# Run tests in container
docker run --rm -v $(pwd)/tests:/app/tests systemmanager-mcp-server:test \
  pytest tests/ -v
```

### Phase 3: Remote Deployment Testing

#### Test 1: Server Startup
```bash
# SSH to remote machine
ssh user@remote-host

# Check service status
systemctl status systemmanager-mcp
# OR for Docker:
docker ps | grep systemmanager-mcp

# Check logs
journalctl -u systemmanager-mcp -f
# OR for Docker:
docker logs -f systemmanager-mcp
```

#### Test 2: Health Check
```bash
# From local machine
curl -s http://remote-host:8080/health | jq .

# Expected response:
# {
#   "status": "healthy",
#   "uptime": 123.45,
#   "timestamp": "2025-11-15T10:30:00Z"
# }
```

#### Test 3: Tool Invocation (Get System Status)
```bash
# Generate test token
TOKEN=$(python scripts/mint_token.py --agent "test-agent" --scopes "monitor" --ttl 3600)

# Call tool
curl -X POST http://remote-host:8080/tools/get_system_status \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"format": "json"}' | jq .

# Expected response structure:
# {
#   "success": true,
#   "data": {
#     "cpu_percent": 23.5,
#     "memory_usage": {...},
#     "disk_usage": {...},
#     "uptime": 3600,
#     "timestamp": "2025-11-15T10:30:00Z"
#   }
# }
```

#### Test 4: Container Management (Docker-specific)
```bash
TOKEN=$(python scripts/mint_token.py --agent "test-agent" --scopes "docker" --ttl 3600)

# List containers
curl -X POST http://remote-host:8080/tools/get_container_list \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}' | jq .
```

#### Test 5: File System Operations
```bash
TOKEN=$(python scripts/mint_token.py --agent "test-agent" --scopes "fs" --ttl 3600)

# List directory
curl -X POST http://remote-host:8080/tools/list_directory \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"path": "/var/log"}' | jq .

# Search files
curl -X POST http://remote-host:8080/tools/search_files \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"pattern": "*.log", "path": "/var/log"}' | jq .
```

#### Test 6: Network Status
```bash
TOKEN=$(python scripts/mint_token.py --agent "test-agent" --scopes "monitor" --ttl 3600)

curl -X POST http://remote-host:8080/tools/get_network_status \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}' | jq .
```

### Phase 4: Load & Stress Testing

#### Concurrent Requests
```bash
# Install ab (Apache Bench)
sudo apt-get install apache2-utils

# Test with 10 concurrent connections, 100 total requests
TOKEN=$(python scripts/mint_token.py --agent "test-agent" --scopes "monitor" --ttl 3600)

ab -n 100 -c 10 -H "Authorization: Bearer $TOKEN" \
  http://remote-host:8080/tools/get_system_status

# Expected: <5% error rate, response times < 1s
```

#### Memory/Resource Monitoring
```bash
# During load test, monitor on remote machine
watch -n 1 'free -h && docker stats'
# OR
watch -n 1 'free -h && systemctl status systemmanager-mcp | grep Memory'
```

### Phase 5: Security Testing

#### Token Validation
```bash
# Test with invalid token
curl -X POST http://remote-host:8080/tools/get_system_status \
  -H "Authorization: Bearer invalid-token" \
  -H "Content-Type: application/json" \
  -d '{}' | jq .

# Expected: 401 Unauthorized
```

#### Scope Verification
```bash
# Create token with limited scopes
LIMITED_TOKEN=$(python scripts/mint_token.py --agent "test" --scopes "monitor" --ttl 3600)

# Try to use Docker scope (should fail)
curl -X POST http://remote-host:8080/tools/get_container_list \
  -H "Authorization: Bearer $LIMITED_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}' | jq .

# Expected: 403 Forbidden or appropriate error
```

---

## Validation Checklist

### Pre-Deployment
- [ ] All unit tests pass locally (`pytest tests/ -v`)
- [ ] Docker image builds successfully (`docker build .`)
- [ ] No security warnings in dependencies (`pip audit`)
- [ ] Type checking passes (`mypy src/`)
- [ ] Code formatting clean (`black --check src/`)

### Deployment
- [ ] Remote machine meets prerequisites (Python 3.11+, Docker, etc.)
- [ ] Git repository cloned and on correct branch
- [ ] Configuration file created and validated
- [ ] Service starts without errors (check logs)
- [ ] Health endpoint responds (HTTP 200)

### Functional Testing
- [ ] [✅] System status tool returns valid data
- [ ] [✅] Token authentication enforced
- [ ] [✅] Token expiry verified
- [ ] [✅] Scope-based access control working
- [ ] [✅] Container operations work (if Docker enabled)
- [ ] [✅] File system operations work within allowed paths
- [ ] [✅] Network status reports correct interfaces
- [ ] [✅] Error responses properly formatted
- [ ] [✅] Audit logging capturing events

### Performance
- [ ] Response time < 1 second for most tools
- [ ] Concurrent requests handled (10+ simultaneous)
- [ ] Memory usage < 200MB baseline
- [ ] CPU usage < 50% during normal operation
- [ ] No memory leaks after 1 hour of operation

### Security
- [ ] Unauthenticated requests rejected
- [ ] Expired tokens rejected
- [ ] Invalid signatures rejected
- [ ] Scope-based access enforced
- [ ] File operations restricted to allowed paths
- [ ] Docker socket access is read-only
- [ ] Non-root user enforced in container
- [ ] Audit logs captured with timestamps

### Production Readiness
- [ ] Logs properly rotated (not filling disk)
- [ ] Service auto-restarts on failure
- [ ] Health checks pass consistently
- [ ] Graceful shutdown on SIGTERM
- [ ] Documentation up-to-date
- [ ] Runbook created for troubleshooting

---

## Quick Start Commands

### Local Testing
```bash
# Clone and setup
git clone https://github.com/your-org/systemmanager-mcp-server.git
cd systemmanager-mcp-server

# Run all tests
pytest tests/ -v

# Run specific test
pytest tests/test_system_status.py -v
```

### Remote Deployment (Docker)
```bash
# Build and push
docker build -t your-registry/systemmanager-mcp:v1 .
docker push your-registry/systemmanager-mcp:v1

# On remote machine
docker run -d \
  --name systemmanager-mcp \
  --restart unless-stopped \
  -p 8080:8080 \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v /etc/systemmanager:/etc/systemmanager:ro \
  your-registry/systemmanager-mcp:v1

# Verify
curl http://localhost:8080/health
```

### Remote Deployment (Systemd)
```bash
# On remote machine
sudo apt-get install -y python3.11 python3.11-venv git
sudo useradd -r systemmanager
cd /opt && sudo git clone https://github.com/your-org/systemmanager-mcp-server.git
cd systemmanager-mcp-server
sudo -u systemmanager python3.11 -m venv venv
sudo -u systemmanager venv/bin/pip install -r requirements.txt
sudo cp deploy/systemd/systemmanager-mcp.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now systemmanager-mcp
sudo systemctl status systemmanager-mcp
```

---

## Troubleshooting

### Server Won't Start
```bash
# Check logs
journalctl -u systemmanager-mcp -n 50 --no-pager

# Validate config
python -c "import yaml; yaml.safe_load(open('/etc/systemmanager/config.yaml'))"

# Check port in use
sudo netstat -tlnp | grep 8080

# Run with debug logging
PYTHONUNBUFFERED=1 python -m src.mcp_server --debug
```

### High CPU Usage
- Check for blocking calls (see Issue #1 in Pre-Deployment Review)
- Monitor concurrent requests: `ab -n 1000 -c 50 http://localhost:8080/`
- Check Docker daemon CPU usage: `docker stats`

### Authentication Failures
```bash
# Verify token generation
python scripts/mint_token.py --agent "test" --scopes "monitor" --ttl 3600

# Check token expiry
python -c "import datetime; print(datetime.datetime.utcnow() + datetime.timedelta(hours=1))"

# Inspect token
TOKEN=<your-token> python -c "print(__import__('base64').urlsafe_b64decode(TOKEN.split('.')[0] + '=='))"
```

### File Access Issues
- Verify allowed paths in config
- Check file permissions: `ls -la /var/log/`
- Check container mount: `docker exec systemmanager-mcp mount | grep /var`

---

## Next Steps

1. **Fix Critical Issues** → Address blocking CPU call and Windows guard
2. **Run Local Tests** → Validate all tests pass
3. **Deploy to Dev** → Test on development remote machine
4. **Load Test** → Verify performance under load
5. **Security Audit** → Run security scan on dependencies
6. **Documentation** → Create runbook for operations team
7. **Deploy to Production** → Follow deployment checklist

