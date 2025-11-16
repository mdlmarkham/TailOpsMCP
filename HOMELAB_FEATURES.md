# SystemManager MCP - Home Lab Features Roadmap

## **Your Use Cases** 🎯

### 1. Docker Compose Stack Management (Komodo-like)
**Status:** 🚧 In Development

**Features:**
- ✅ Deploy stacks from GitHub repositories
- ✅ Update stacks (git pull + docker compose up)
- ✅ List all stacks with status
- ✅ Remove stacks (with optional volume cleanup)
- 🔄 Webhook support for auto-deployment
- 🔄 Stack templates/marketplace
- 🔄 Multi-environment support (dev/staging/prod)

**Implementation:** `src/services/compose_manager.py`

**Required Package:**
```bash
pip install GitPython
```

**Example Usage:**
```python
# Deploy a stack
deploy_stack(
    stack_name="monitoring",
    repo_url="https://github.com/user/prometheus-stack",
    branch="main",
    env_vars={"DOMAIN": "metrics.home.lab"}
)

# Update stack
update_stack("monitoring")

# List all stacks
list_stacks()
```

---

### 2. LXC Container Network Auditing
**Status:** 🔄 Planned

**Features:**
- View LXC container network configuration
- Audit port forwards and NAT rules
- Check firewall rules per container
- Visualize network topology
- Detect security misconfigurations
- Compare against baseline/policy

**Implementation Plan:**
- Read `/etc/pve/lxc/*.conf` (Proxmox LXC configs)
- Parse network interfaces and bridges
- Query iptables/nftables for rules
- AI-powered security analysis

**Tools to Add:**
```python
- audit_lxc_network(container_id)
- list_lxc_containers()
- get_lxc_network_config(container_id)
- check_lxc_firewall_rules(container_id)
```

---

### 3. Service Management
**Status:** ✅ Can be implemented now

**Features:**
- Start/stop/restart systemd services
- Enable/disable services at boot
- View service status and logs
- Service dependency tree
- Failed service detection

**Implementation:**
```python
# Tool: manage_systemd_service
- Action: start, stop, restart, enable, disable, status
- Uses: systemctl commands
- Returns: status, logs, enabled state
```

---

### 4. System Updates
**Status:** ⚠️ Partially Implemented

**Current:**
- ✅ Check for updates
- ✅ Install specific packages
- 🔄 Full system upgrade

**Needed:**
- Unattended upgrades configuration
- Update scheduling
- Pre/post-update snapshots
- Rollback capability
- Update notifications

---

## **Additional Home Lab Capabilities** 💡

### 5. Backup & Snapshot Management
**Priority:** 🔥 High

**Features:**
- Schedule automated backups
- LXC/VM snapshots (Proxmox integration)
- Docker volume backups
- Database dumps (MySQL, PostgreSQL)
- Backup to S3/NAS/local
- Restore operations
- Backup verification

**Tools:**
```python
- create_snapshot(container_id, name)
- list_snapshots(container_id)
- restore_snapshot(container_id, snapshot_name)
- backup_docker_volume(volume_name, destination)
- backup_database(type, name, destination)
```

---

### 6. Certificate Management
**Priority:** 🔥 High (for HTTPS)

**Features:**
- Let's Encrypt automation
- Certificate renewal monitoring
- Certificate expiry alerts
- SSL/TLS configuration auditing
- Certificate deployment to services

**Tools:**
```python
- renew_certificate(domain)
- check_certificate_expiry(domain)
- deploy_certificate(domain, service)
- list_certificates()
```

---

### 7. DNS Management
**Priority:** 🟡 Medium

**Features:**
- Pi-hole integration
- Local DNS record management
- DNS-over-HTTPS configuration
- DHCP lease monitoring
- DNS query analytics

**Tools:**
```python
- add_dns_record(hostname, ip)
- list_dns_records()
- get_dhcp_leases()
- query_dns_stats()
```

---

### 8. Reverse Proxy Management
**Priority:** 🔥 High

**Features:**
- Traefik/Nginx/Caddy configuration
- Auto-discovery of services
- SSL termination
- Load balancer health checks
- Rate limiting rules

**Tools:**
```python
- add_proxy_route(domain, backend_url)
- list_proxy_routes()
- reload_proxy_config()
- check_proxy_health()
```

---

### 9. Resource Monitoring & Alerts
**Priority:** 🔥 High

**Features:**
- Historical metrics (CPU, RAM, disk, network)
- Container resource usage
- Disk space alerts
- Temperature monitoring (if available)
- Custom alert thresholds
- Integration with notification systems

**Tools:**
```python
- get_historical_metrics(start, end, metric)
- set_alert_threshold(metric, value, action)
- get_container_stats(container_id)
- check_disk_health()
```

---

### 10. Network Diagnostics
**Priority:** 🟡 Medium

**Features:**
- Port scanning (internal network)
- Bandwidth monitoring
- Network connectivity tests
- Latency monitoring
- Wake-on-LAN
- VLAN management

**Tools:**
```python
- scan_network_ports(ip_range)
- test_connectivity(host, port)
- get_bandwidth_stats(interface)
- wake_on_lan(mac_address)
```

---

### 11. Git Repository Management
**Priority:** 🟢 Low

**Features:**
- Clone/pull repositories
- Watch for changes
- Automated deployments on push
- Git hooks integration
- Multi-repo operations

**Already used in:** Stack deployment

---

### 12. Cron/Scheduled Tasks
**Priority:** 🟡 Medium

**Features:**
- List cron jobs
- Create/edit/delete cron jobs
- View cron history/logs
- Systemd timer management
- Task scheduling via MCP

**Tools:**
```python
- list_cron_jobs()
- add_cron_job(schedule, command)
- list_systemd_timers()
```

---

### 13. Database Management
**Priority:** 🟡 Medium

**Features:**
- Create/drop databases
- User management
- Backup/restore
- Query execution
- Performance monitoring
- Connection pool stats

**Tools:**
```python
- create_database(type, name)
- backup_database(name, destination)
- execute_query(database, query)
- get_db_stats(database)
```

---

### 14. Email/Notification System
**Priority:** 🟢 Low

**Features:**
- Send alerts via email
- Webhook notifications
- Discord/Slack integration
- SMS alerts (Twilio)
- Push notifications

**Tools:**
```python
- send_notification(type, message, priority)
- configure_notification_channel(type, config)
```

---

### 15. Security Scanning
**Priority:** 🔥 High

**Features:**
- Container vulnerability scanning (Trivy)
- Open port detection
- Weak password detection
- Security audit reports
- Compliance checking

**Tools:**
```python
- scan_container_vulnerabilities(image)
- audit_security_configuration()
- check_open_ports()
- generate_security_report()
```

---

### 16. Proxmox Integration
**Priority:** 🔥 High (if you use Proxmox)

**Features:**
- List VMs and containers
- Start/stop/restart VMs
- Create VMs from templates
- Snapshot management
- Resource allocation
- Migration between nodes

**Tools:**
```python
- list_proxmox_vms()
- manage_vm(vmid, action)
- create_vm_from_template(template, name)
- migrate_vm(vmid, target_node)
```

---

### 17. Home Automation Integration
**Priority:** 🟢 Low

**Features:**
- Home Assistant integration
- IoT device management
- Energy monitoring
- Smart home automation
- Sensor data collection

---

### 18. Media Server Management
**Priority:** 🟢 Low

**Features:**
- Plex/Jellyfin management
- Media library scanning
- Transcoding queue monitoring
- Download automation (Sonarr/Radarr)

---

## **Implementation Priority**

### **Phase 1: Core Infrastructure** (Immediate)
1. ✅ Docker Compose Stack Management
2. ✅ Service Management (systemd)
3. ✅ System Updates Enhancement
4. 🔄 LXC Network Auditing

### **Phase 2: Security & Reliability** (Short-term)
5. Backup & Snapshot Management
6. Certificate Management
7. Security Scanning
8. Enhanced Monitoring & Alerts

### **Phase 3: Automation & Integration** (Medium-term)
9. Reverse Proxy Management
10. Proxmox Integration
11. DNS Management
12. Scheduled Tasks

### **Phase 4: Advanced Features** (Long-term)
13. Database Management
14. Network Diagnostics
15. Git Repository Management
16. Notification System

---

## **Next Steps**

1. Add `GitPython` to `requirements.txt`
2. Create MCP tools for Compose Stack management
3. Implement systemd service management tools
4. Add LXC network auditing
5. Test stack deployment with sample repos

Would you like me to implement any of these features now?
