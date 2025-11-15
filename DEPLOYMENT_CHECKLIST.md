# SystemManager MCP - Deployment Checklist

**Date**: _______________  
**Environment**: □ Dev  □ Staging  □ Production  
**Deployed By**: _______________  
**Approval**: _______________

---

## Phase 1: Pre-Deployment Review & Fixes ✓

**Target Completion**: Before any remote deployment  
**Owner**: Development Team

- [ ] **Issue #1 Fixed**: Blocking CPU call replaced with non-blocking version
  - File: `src/mcp_server.py` line ~35
  - Change: `psutil.cpu_percent(interval=1)` → `psutil.cpu_percent(interval=None)`
  - Verified by: _______________

- [ ] **Issue #2 Fixed**: Windows platform guard added
  - File: `src/mcp_server.py` line ~55
  - Change: Added `if hasattr(os, 'getloadavg'):` guard
  - Verified by: _______________

- [ ] **Local Tests Pass**
  ```bash
  pytest tests/ -v
  ```
  Result: _____ PASS / _____ FAIL
  Date: _______________

- [ ] **Type Checking Clean**
  ```bash
  mypy src/ --ignore-missing-imports
  ```
  Result: _____ PASS / _____ FAIL
  Date: _______________

- [ ] **Code Formatting Valid**
  ```bash
  black --check src/
  ```
  Result: _____ PASS / _____ FAIL
  Date: _______________

- [ ] **Linting Clean**
  ```bash
  flake8 src/ --max-line-length=88
  ```
  Result: _____ PASS / _____ FAIL
  Date: _______________

---

## Phase 2: Deployment Preparation ✓

**Target Completion**: Day before deployment  
**Owner**: DevOps/Infrastructure

### Docker Image Build

- [ ] **Docker Image Built Successfully**
  ```bash
  docker build -t systemmanager-mcp:v1.0.0 .
  ```
  Image ID: _______________
  Date: _______________

- [ ] **Image Scanned for Vulnerabilities**
  ```bash
  docker scan systemmanager-mcp:v1.0.0
  ```
  Vulnerabilities Found: □ None  □ Low  □ Medium  □ High
  Remediation: _______________

- [ ] **Image Pushed to Registry** (if applicable)
  ```bash
  docker push your-registry/systemmanager-mcp:v1.0.0
  ```
  Registry: _______________
  Date: _______________

### Remote System Preparation

- [ ] **Remote System Prerequisites Verified**
  ```bash
  python scripts/verify_deployment.py --check-prereq --target docker
  ```
  All Checks Passed: □ Yes  □ No
  Issues Found: _______________
  Date: _______________

- [ ] **Configuration File Created**
  - Path: `/etc/systemmanager/config.yaml`
  - Auth Token Generated: _______________
  - Allowed Paths Configured: _______________
  - Date Created: _______________

- [ ] **Required Directories Created**
  ```bash
  sudo mkdir -p /var/log/systemmanager /etc/systemmanager
  sudo chmod 755 /var/log/systemmanager
  ```
  Date: _______________

- [ ] **Docker Socket Verified Accessible**
  ```bash
  ls -la /var/run/docker.sock
  ```
  Permissions: _______________
  Owner: _______________
  Date: _______________

---

## Phase 3: Deployment Execution ✓

**Target Completion**: Deployment day  
**Owner**: DevOps/Infrastructure  
**Rollback Plan**: _______________

### Docker Container Deployment

- [ ] **Container Started Successfully**
  ```bash
  docker run -d \
    --name systemmanager-mcp \
    --restart unless-stopped \
    -p 8080:8080 \
    -v /var/run/docker.sock:/var/run/docker.sock:ro \
    -v /etc/systemmanager:/etc/systemmanager:ro \
    -v /var/log/systemmanager:/var/log/systemmanager \
    systemmanager-mcp:v1.0.0
  ```
  Container ID: _______________
  Date/Time: _______________
  Deployed By: _______________

- [ ] **Container Running**
  ```bash
  docker ps | grep systemmanager-mcp
  ```
  Status: _______________
  Date Verified: _______________

- [ ] **Logs Accessible**
  ```bash
  docker logs systemmanager-mcp
  ```
  No Errors: □ Yes  □ No
  Issues: _______________
  Date: _______________

### Systemd Service Deployment (if applicable)

- [ ] **Systemd Service File Installed**
  ```bash
  sudo cp deploy/systemd/systemmanager-mcp.service /etc/systemd/system/
  ```
  Date: _______________

- [ ] **Systemd Daemon Reloaded**
  ```bash
  sudo systemctl daemon-reload
  ```
  Date: _______________

- [ ] **Service Enabled**
  ```bash
  sudo systemctl enable systemmanager-mcp
  ```
  Date: _______________

- [ ] **Service Started**
  ```bash
  sudo systemctl start systemmanager-mcp
  ```
  Date/Time: _______________
  Started By: _______________

- [ ] **Service Status Good**
  ```bash
  sudo systemctl status systemmanager-mcp
  ```
  Status: _______________
  Date Verified: _______________

---

## Phase 4: Post-Deployment Validation ✓

**Target Completion**: Within 1 hour of deployment  
**Owner**: QA/Testing Team

### Basic Health Checks

- [ ] **Health Endpoint Responds**
  ```bash
  curl http://<remote>:8080/health
  ```
  Status Code: _____ (Expected: 200)
  Response: _______________
  Date Verified: _______________

- [ ] **Health Status: Healthy**
  ```bash
  curl http://<remote>:8080/health | jq .status
  ```
  Status: _______________
  Date: _______________

### Connectivity & Authentication

- [ ] **Authentication Required**
  ```bash
  curl http://<remote>:8080/tools/get_system_status -d '{}'
  ```
  Status Code: _____ (Expected: 401)
  Date: _______________

- [ ] **Valid Token Accepted**
  ```bash
  curl -H "Authorization: Bearer $TOKEN" \
    http://<remote>:8080/tools/get_system_status -d '{}'
  ```
  Status Code: _____ (Expected: 200)
  Date: _______________

### Functional Testing

- [ ] **System Status Tool Works**
  - Command tested: `get_system_status`
  - Result: □ Success  □ Failed
  - Data points verified:
    - [ ] cpu_percent present
    - [ ] memory_usage present
    - [ ] disk_usage present
    - [ ] timestamp valid
  - Date: _______________

- [ ] **Network Status Tool Works**
  - Command tested: `get_network_status`
  - Result: □ Success  □ Failed
  - Date: _______________

- [ ] **File System Tool Works**
  - Command tested: `list_directory` with path `/var/log`
  - Result: □ Success  □ Failed
  - Date: _______________

- [ ] **Docker Management Tool Works** (if Docker features enabled)
  - Command tested: `get_container_list`
  - Result: □ Success  □ Failed
  - Date: _______________

### Performance Validation

- [ ] **Response Time Acceptable**
  ```bash
  python scripts/remote_test_runner.py --host <remote> --port 8080 --token $TOKEN
  ```
  Average Response Time: _____ seconds (Target: <1s)
  Max Response Time: _____ seconds
  Date: _______________

- [ ] **Handles Concurrent Requests**
  ```bash
  ab -n 100 -c 10 -H "Authorization: Bearer $TOKEN" \
    http://<remote>:8080/tools/get_system_status
  ```
  Requests/sec: _____
  Failed Requests: _____ (Expected: 0)
  Date: _______________

### Security Validation

- [ ] **Expired Token Rejected**
  - Tested with: Expired token
  - Result: □ Rejected  □ Failed
  - Date: _______________

- [ ] **Invalid Token Rejected**
  - Tested with: Malformed token
  - Result: □ Rejected  □ Failed
  - Date: _______________

- [ ] **Scope Enforcement Works**
  - Token with scopes: "monitor"
  - Attempted access to: Docker tools
  - Result: □ Denied  □ Failed
  - Date: _______________

- [ ] **Audit Logging Active**
  - Checked logs for audit entries
  - Log format: _______________
  - Sample entries: _______________
  - Date: _______________

### Comprehensive Test Suite

- [ ] **All Automated Tests Pass**
  ```bash
  python scripts/remote_test_runner.py --host <remote> --port 8080 --token $TOKEN
  ```
  Tests Passed: _____ / _____
  Tests Failed: _____
  HTML Report Generated: _______________
  Date: _______________

---

## Phase 5: Post-Deployment Monitoring ✓

**Target Completion**: Continuous  
**Owner**: Operations Team

### Initial Monitoring (First 24 hours)

- [ ] **Logs Monitored for Errors**
  - Monitoring tool: _______________
  - Frequency: Every hour
  - Errors found: □ None  □ Some (Details: _______________)
  - Date/Time: _______________

- [ ] **Resource Usage Monitored**
  ```bash
  docker stats systemmanager-mcp
  ```
  Memory Usage: _____ (Expected: <200MB)
  CPU Usage: _____ % (Expected: <50%)
  Date: _______________

- [ ] **Service Availability Verified**
  ```bash
  # Continuous health checks
  watch -n 60 'curl -s http://<remote>:8080/health | jq .status'
  ```
  Uptime: _____ % (Target: 99.9%)
  Date: _______________

- [ ] **Restart/Recovery Behavior Verified**
  - Tested: Graceful shutdown
  - Result: □ Auto-restart  □ Manual required
  - Time to recover: _____
  - Date: _______________

### Extended Monitoring (First 7 days)

- [ ] **Daily Health Report Generated**
  - Report Date: _______________
  - Status: □ Healthy  □ Issues Found
  - Issues: _______________

- [ ] **Performance Baselines Established**
  - Avg Response Time: _____ seconds
  - P95 Response Time: _____ seconds
  - Memory Baseline: _____ MB
  - CPU Baseline: _____ %
  - Date: _______________

- [ ] **No Critical Errors in Logs**
  - Error check performed: _______________
  - Errors found: □ None  □ Some (Details: _______________)
  - Date: _______________

---

## Phase 6: Sign-Off & Documentation ✓

**Target Completion**: Deployment + 3 days  
**Owner**: Project Lead

### Documentation

- [ ] **Deployment Summary Documented**
  - File: _______________
  - Deployment Method: □ Docker  □ Systemd  □ Tailscale
  - Version Deployed: _______________
  - Date Documented: _______________

- [ ] **Configuration Documented**
  - Config file location: _______________
  - Key settings documented: □ Yes  □ No
  - Sensitive values stored securely: □ Yes  □ No
  - Date: _______________

- [ ] **Issues/Deviations Documented**
  - Issues encountered: _______________
  - Resolutions applied: _______________
  - Follow-up actions: _______________
  - Date: _______________

- [ ] **Runbook Updated**
  - File: _______________
  - Includes: □ Startup  □ Shutdown  □ Troubleshooting  □ Health checks
  - Date: _______________

### Approval

- [ ] **Technical Sign-Off**
  - Approved By: _______________ (Name/Title)
  - Date: _______________
  - Issues Known: □ None  □ Some (List: _______________)

- [ ] **Operations Sign-Off**
  - Approved By: _______________ (Name/Title)
  - Date: _______________
  - Ready for Production: □ Yes  □ Not Yet

- [ ] **Security Sign-Off**
  - Reviewed By: _______________ (Name/Title)
  - Date: _______________
  - Security Issues: □ None  □ Some (List: _______________)

---

## Rollback Procedure

**Execute if**: Critical issues detected that cannot be fixed within 1 hour

```bash
# Docker Rollback
docker stop systemmanager-mcp
docker rm systemmanager-mcp
docker run -d ... systemmanager-mcp:v0.9.0  # Previous version

# OR Systemd Rollback
sudo systemctl stop systemmanager-mcp
sudo systemctl start systemmanager-mcp  # Previous version installed
```

- [ ] **Rollback Executed** (if needed)
  - Date/Time: _______________
  - Reason: _______________
  - Executed By: _______________
  - Previous Version: _______________

---

## Sign-Off Summary

| Role | Name | Date | Status |
|------|------|------|--------|
| Development Lead | | | □ Approved  □ Not Approved |
| DevOps Lead | | | □ Approved  □ Not Approved |
| QA Lead | | | □ Approved  □ Not Approved |
| Security Lead | | | □ Approved  □ Not Approved |
| Project Manager | | | □ Approved  □ Not Approved |

**Overall Status**: □ GO  □ NO-GO (Reason: _______________)

---

## Notes & Comments

```
_________________________________________________________________

_________________________________________________________________

_________________________________________________________________

_________________________________________________________________

_________________________________________________________________
```

---

**Checklist Completed By**: _______________  
**Date Completed**: _______________  
**Next Review Date**: _______________

**File Location**: `/PATH/TO/DEPLOYMENT_CHECKLIST_[DATE].md`
