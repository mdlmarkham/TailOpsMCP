# Security Hardening Checklist

Based on AI analysis of system logs, these improvements are recommended:

## 🔴 **Critical - Immediate Action Required**

### 1. Rotate Exposed Secrets
- [ ] Generate new TSIDP client secret
- [ ] Update `.env` file with new secret
- [ ] Remove old secret from TSIDP
- [ ] Audit logs for exposed secrets and rotate/truncate if needed

**Commands:**
```bash
# Create new client in TSIDP (via admin panel)
# Then update the .env file
sudo vim /opt/systemmanager/.env
sudo chmod 600 /opt/systemmanager/.env
```

## ⚠️ **High Priority**

### 2. Convert to Systemd Service Management
- [ ] Create `/opt/systemmanager/.env` from template
- [ ] Add secrets to `.env` file
- [ ] Set permissions: `chmod 600 /opt/systemmanager/.env`
- [ ] Run deployment script: `./deploy/secure-deploy.sh`
- [ ] Verify service is running: `systemctl status systemmanager-mcp`

**Benefits:**
- Automatic restart on failure
- No secrets in command line
- Proper logging to journald
- Process supervision
- Clean shutdown handling

### 3. Stop Using Root for Deployment
- [ ] Create dedicated deploy user: `systemmanager`
- [ ] Grant sudo access for service management only
- [ ] Use SSH keys instead of password
- [ ] Configure restricted SSH shell if needed

**Commands:**
```bash
# Create user
sudo useradd -r -s /bin/bash -d /opt/systemmanager -m systemmanager

# Add to docker group if needed
sudo usermod -aG docker systemmanager

# Update systemd service to run as this user
# Edit /etc/systemd/system/systemmanager-mcp.service
# Change: User=systemmanager, Group=systemmanager
```

### 4. Secure Secret Management

Current: Secrets in `.env` file with `chmod 600`

**Better options:**
- [ ] Use systemd credentials: `systemd-creds encrypt`
- [ ] Use HashiCorp Vault
- [ ] Use cloud provider secret manager (AWS Secrets Manager, etc.)

### 5. Implement CI/CD Pipeline
- [ ] Set up GitHub Actions for deployment
- [ ] Use deployment keys instead of SSH
- [ ] Automated testing before deployment
- [ ] Rollback capability

## 📊 **Medium Priority**

### 6. Enhanced Logging & Monitoring
- [ ] Configure log rotation for `/opt/systemmanager/logs`
- [ ] Set up centralized logging (ELK, Loki, etc.)
- [ ] Add health check endpoint monitoring
- [ ] Set up alerts for service failures

### 7. Access Control Improvements
- [ ] Audit Tailscale ACLs
- [ ] Implement per-user SSH keys
- [ ] Enable session logging
- [ ] Regular access reviews

### 8. Network Security
- [ ] Ensure HTTPS for production (not HTTP)
- [ ] Use Tailscale HTTPS certificates
- [ ] Configure firewall rules
- [ ] Enable rate limiting

## ✅ **Deployment Steps**

1. **Prepare environment file:**
   ```bash
   cd /opt/systemmanager
   sudo cp deploy/.env.template .env
   sudo chmod 600 .env
   sudo vim .env  # Add your secrets
   ```

2. **Run secure deployment:**
   ```bash
   cd /opt/systemmanager
   sudo ./deploy/secure-deploy.sh
   ```

3. **Verify deployment:**
   ```bash
   sudo systemctl status systemmanager-mcp
   sudo journalctl -u systemmanager-mcp -f
   ```

4. **Test MCP server:**
   ```bash
   curl -v http://dev1.tailf9480.ts.net:8080/.well-known/oauth-protected-resource/mcp
   ```

## 📝 **Post-Deployment**

- [ ] Rotate TSIDP client secret
- [ ] Remove old deployment logs with exposed secrets
- [ ] Document new deployment process
- [ ] Train team on secure practices
- [ ] Schedule security audit

## 🔒 **Security Best Practices**

1. **Never pass secrets on command line** - use environment files or secret managers
2. **Use systemd for service management** - automatic restart, proper logging
3. **Principle of least privilege** - dedicated users, minimal permissions
4. **Regular audits** - review access logs, rotate credentials
5. **Defense in depth** - network security + application security + access controls
