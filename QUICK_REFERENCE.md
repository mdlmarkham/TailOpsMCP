# SystemManager MCP - Quick Reference Card

**Project Status**: ⚠️ Ready for Testing (after fixes)  
**Review Date**: November 15, 2025

---

## 30-Second Overview

**What**: MCP server for secure remote system management via AI agents  
**Why**: Allows Claude/other AI to monitor systems, manage Docker, explore files  
**Where**: Deploy on Linux (Docker or systemd)  
**How**: REST API with bearer token auth

---

## Critical Issues (Fix First!)

| Issue | Severity | Location | Fix |
|-------|----------|----------|-----|
| Blocking CPU call blocks event loop for 1 sec | HIGH | `src/mcp_server.py:35` | Use `psutil.cpu_percent(interval=None)` |
| Windows incompatibility with `os.getloadavg()` | MEDIUM | `src/mcp_server.py:55` | Add `if hasattr(os, 'getloadavg')` guard |

---

## Testing Workflows

### Local Testing (5 minutes)
```bash
# Setup
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Test
pytest tests/ -v
```

### Docker Deployment (10 minutes)
```bash
# Build
docker build -t systemmanager-mcp:v1 .

# Run
docker run -d -p 8080:8080 \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  systemmanager-mcp:v1

# Verify
curl http://localhost:8080/health
```

### Remote Testing (15 minutes)
```bash
# Generate token
TOKEN=$(python scripts/mint_token.py --agent "test" --scopes "monitor" --ttl 3600)

# Run tests
python scripts/remote_test_runner.py --host <remote-ip> --port 8080 --token $TOKEN

# View report
open test_report.html
```

---

## Files You Created

| File | Purpose |
|------|---------|
| `TESTING_REMOTE_GUIDE.md` | Complete testing & deployment guide |
| `PROJECT_REVIEW_SUMMARY.md` | This review with all findings |
| `scripts/remote_test_runner.py` | Automated test suite with HTML reports |
| `scripts/verify_deployment.py` | Pre/post-deployment verification |

---

## Key Architecture

```
┌─────────────────────────────────────┐
│   AI Agent (Claude via MCP Client)  │
└────────────────┬────────────────────┘
                 │
         HTTP/SSE or stdio
                 │
        ┌────────▼────────┐
        │ MCP Server      │
        │ (Port 8080)     │
        └────────┬────────┘
                 │
    ┌────────────┼────────────┐
    │            │            │
    ▼            ▼            ▼
 System        Docker      Filesystem
 Monitor       Manager      Explorer
    │            │            │
    └────────────┼────────────┘
                 │
            Unix/Linux
            System Calls
```

---

## Deployment Options

### Option 1: Docker (Recommended)
```bash
docker run -d -p 8080:8080 \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v /etc/systemmanager:/etc/systemmanager:ro \
  systemmanager-mcp:v1
```
**Best for**: Quick deployment, containerized environments

### Option 2: Systemd Service
```bash
sudo cp deploy/systemd/systemmanager-mcp.service /etc/systemd/system/
sudo systemctl enable --now systemmanager-mcp
```
**Best for**: Linux VMs, persistent services, direct system access

### Option 3: Tailscale Services (Secure Remote)
```bash
# Add Tailscale sidecar to Docker setup
# Provides end-to-end encryption, no firewall config needed
```
**Best for**: Secure remote access through Tailnet

---

## Testing Checklist

- [ ] **Local Tests**: `pytest tests/ -v` passes
- [ ] **Docker Build**: `docker build -t systemmanager-mcp:v1 .` succeeds
- [ ] **Health Check**: `curl http://localhost:8080/health` returns 200
- [ ] **Auth Test**: Invalid token returns 401
- [ ] **Tool Test**: `get_system_status` returns valid JSON
- [ ] **Remote Test**: `remote_test_runner.py` shows all ✓ PASS
- [ ] **Load Test**: `ab -n 100 -c 10` succeeds without errors
- [ ] **Logs**: No errors in `docker logs` or `journalctl`

---

## Common Commands

### Build & Deploy
```bash
# Build image
docker build -t systemmanager-mcp:v1 .

# Run locally
docker run -d --name systemmanager-mcp \
  -p 8080:8080 \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  systemmanager-mcp:v1

# Systemd deployment
sudo systemctl start systemmanager-mcp
sudo systemctl status systemmanager-mcp
sudo journalctl -u systemmanager-mcp -f
```

### Testing
```bash
# Generate test token
TOKEN=$(python scripts/mint_token.py --agent "test" --scopes "monitor" --ttl 3600)

# Test endpoint
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/tools/get_system_status -d '{}'

# Run test suite
python scripts/remote_test_runner.py --host localhost --port 8080 --token $TOKEN

# Check deployment
python scripts/verify_deployment.py --check-health --host localhost --port 8080
```

### Debugging
```bash
# View logs
docker logs -f systemmanager-mcp
journalctl -u systemmanager-mcp -f

# Check health
curl http://localhost:8080/health | jq .

# Verify auth
curl -H "Authorization: Bearer invalid" \
  http://localhost:8080/tools/get_system_status -d '{}'
```

---

## Configuration (Quick)

**File**: `/etc/systemmanager/config.yaml`

```yaml
server:
  host: "0.0.0.0"
  port: 8080
  auth_required: true

security:
  auth_tokens:
    - "your-token-here"
  rate_limit: 100

logging:
  level: "INFO"
```

---

## Performance Targets

| Metric | Target | Notes |
|--------|--------|-------|
| Response Time | <1 second | P95 latency |
| Concurrent Connections | 10+ | Without degradation |
| Memory Usage | <200MB | Baseline for container |
| Startup Time | <5 seconds | To healthy state |
| CPU Usage | <50% | During normal operations |

---

## Security Summary

✅ **Implemented**:
- Bearer token authentication (HMAC)
- Token expiry validation
- Scope-based access control
- Audit logging with correlation IDs
- Non-root Docker user
- Systemd hardening
- Read-only mounts

⚠️ **Verify**:
- Allowed filesystem paths configured correctly
- Docker socket permissions (`ls -la /var/run/docker.sock`)
- Token generation secure (use strong secrets)
- Logs properly rotated (don't fill disk)

---

## Troubleshooting

### Server Won't Start
```bash
# Check config syntax
python -c "import yaml; yaml.safe_load(open('/etc/systemmanager/config.yaml'))"

# Check logs
docker logs systemmanager-mcp | head -50

# Test port availability
sudo netstat -tlnp | grep 8080
```

### High CPU/Memory
- Issue #1: Blocking CPU call (see critical issues)
- Monitor with: `docker stats` or `top`
- Run load test to verify performance

### Auth Failures
```bash
# Verify token generation
TOKEN=$(python scripts/mint_token.py --agent "test" --scopes "monitor" --ttl 3600)
echo $TOKEN  # Should see token string

# Check token expiry
python -c "import datetime; print(datetime.datetime.utcnow() + datetime.timedelta(hours=1))"
```

### File Access Issues
- Check allowed paths in `/etc/systemmanager/config.yaml`
- Verify permissions: `ls -la /var/log/`
- Check Docker mount: `docker inspect systemmanager-mcp | grep -A 5 Mounts`

---

## Next Steps

### This Week
1. Fix Issue #1 and #2 (30 min)
2. Run local tests (5 min)
3. Build Docker image (5 min)

### Next Week
1. Deploy to dev remote system (20 min)
2. Run comprehensive test suite (20 min)
3. Load test and verify performance (30 min)

### Two Weeks
1. Security review/audit (1 hour)
2. Documentation review (30 min)
3. Go/no-go decision for production

---

## Important Links

- **Full Review**: `PROJECT_REVIEW_SUMMARY.md`
- **Testing Guide**: `TESTING_REMOTE_GUIDE.md`
- **Test Runner**: `scripts/remote_test_runner.py`
- **Health Check**: `scripts/verify_deployment.py`

---

## Support

For issues or questions:
1. Check `TESTING_REMOTE_GUIDE.md` - "Troubleshooting" section
2. Review project specs in `/specs` folder
3. Check logs: `docker logs` or `journalctl`
4. Run verification script: `verify_deployment.py`

---

**Last Updated**: November 15, 2025  
**Review Status**: Complete ✓
