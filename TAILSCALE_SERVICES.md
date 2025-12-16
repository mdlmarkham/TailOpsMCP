# Tailscale Services Integration for SystemManager MCP

## Overview
Integrate SystemManager MCP Server with Tailscale Services for zero-configuration service discovery across your tailnet.

## What Tailscale Services Provides

### Benefits
1. **Stable Service Names**: Access via `http://systemmanager-mcp.yourtailnet.ts.net:8080` regardless of which host runs the server
2. **High Availability**: Multiple hosts can advertise the same service (automatic failover)
3. **Access Control**: Granular ACL policies for who can access the service
4. **Auto-Discovery**: DNS SRV records enable automatic service discovery
5. **No Port Conflicts**: TailVIP (virtual IP) eliminates port conflicts across hosts

## Current Configuration

Your existing `tailscale-service.json`:
```json
{
  "version": "1",
  "services": {
    "svc:systemmanager-mcp": {
      "endpoints": {
        "tcp:8080": "localhost:8080"
      },
      "description": "TailOpsMCP Server - Remote system management and monitoring"
    }
  }
}
```

## Setup Steps

### 1. Define the Service in Tailscale Admin Console

```bash
# Navigate to https://login.tailscale.com/admin/services
# Click "Advertise" → "Define a Service"
#
# Name: systemmanager-mcp
# Description: TailOpsMCP Server - Remote system management and monitoring
# Endpoints: tcp:8080
# Tags: tag:systemmanager (optional but recommended)
```

### 2. Configure the Service Host

On `dev1.tailf9480.ts.net`:

```bash
# Option A: Using CLI (recommended - automatic config + advertise)
cd /opt/systemmanager
tailscale serve --service=svc:systemmanager-mcp --tls-terminated-tcp=8080 tcp://localhost:8080

# Option B: Using config file (more control)
tailscale serve set-config --all tailscale-service.json
tailscale serve advertise svc:systemmanager-mcp
```

### 3. Approve the Service Host

```bash
# Check pending approval
tailscale status --json | jq '.Self.CapMap."service-host"'

# Approve in admin console:
# https://login.tailscale.com/admin/services
# Find "systemmanager-mcp" → Click → Approve pending host
```

### 4. Configure Auto-Approval (Optional)

Add to your Tailscale ACL policy:

```json
{
  "autoApprovers": {
    "services": {
      "svc:systemmanager-mcp": ["tag:server", "tag:systemmanager"]
    }
  }
}
```

### 5. Set Access Control

Add grant rules to your ACL:

```json
{
  "grants": [
    {
      "src": ["autogroup:admin"],
      "dst": ["svc:systemmanager-mcp"],
      "app": {
        "tailscale.com/cap/funnel": ["tcp:8080"]
      }
    },
    {
      "src": ["group:ops", "tag:monitoring"],
      "dst": ["svc:systemmanager-mcp"],
      "app": {
        "tailscale.com/cap/funnel": ["tcp:8080"]
      }
    }
  ]
}
```

## Access Methods

### Via MagicDNS
```bash
# Standard MCP client
http://systemmanager-mcp.yourtailnet.ts.net:8080/sse

# VS Code MCP config update (.vscode/mcp.json)
{
  "mcpServers": {
    "TailOpsMCP": {
      "url": "http://systemmanager-mcp.yourtailnet.ts.net:8080/sse"
    }
  }
}
```

### Via DNS SRV Discovery
```python
import socket
import dns.resolver

# Automatic service discovery
answers = dns.resolver.resolve('_systemmanager-mcp._tcp.yourtailnet.ts.net', 'SRV')
for rdata in answers:
    print(f"Host: {rdata.target}, Port: {rdata.port}")
```

### Via TailVIP (Virtual IP)
```bash
# Get the service VIP
tailscale status | grep systemmanager-mcp

# Access via VIP (auto-assigned, stable across hosts)
http://100.x.x.x:8080/sse
```

## High Availability Setup

### Multiple Hosts
```bash
# On dev1.tailf9480.ts.net
tailscale serve --service=svc:systemmanager-mcp --tls-terminated-tcp=8080 tcp://localhost:8080

# On dev2.tailf9480.ts.net (backup)
tailscale serve --service=svc:systemmanager-mcp --tls-terminated-tcp=8080 tcp://localhost:8080

# Tailscale automatically load balances between healthy hosts
```

### Health Checks (Coming Soon)
Tailscale Services will support automatic health checks to remove unhealthy hosts from rotation.

## Deployment Script

Create `scripts/setup_tailscale_service.sh`:

```bash
#!/bin/bash
set -e

echo "🔧 Setting up TailOpsMCP as Tailscale Service..."

# Check if already configured
if tailscale serve status --json | jq -e '.services."svc:systemmanager-mcp"' > /dev/null 2>&1; then
    echo "✅ Service already configured"
    tailscale serve status
    exit 0
fi

# Configure and advertise the service
echo "📡 Configuring service endpoint..."
tailscale serve --service=svc:systemmanager-mcp \
    --tls-terminated-tcp=8080 \
    tcp://localhost:8080

echo "✅ Service configured! Waiting for admin approval..."
echo ""
echo "Next steps:"
echo "1. Go to https://login.tailscale.com/admin/services"
echo "2. Find 'systemmanager-mcp' and approve the host"
echo "3. Access via: http://systemmanager-mcp.<tailnet>.ts.net:8080/sse"

# Show status
tailscale serve status
```

## Testing Service Discovery

```python
#!/usr/bin/env python3
"""Test Tailscale Service discovery for TailOpsMCP"""

import socket
import requests
try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False
    print("⚠️  Install dnspython for SRV record testing: pip install dnspython")

def test_magicdns():
    """Test access via MagicDNS name"""
    print("\n🔍 Testing MagicDNS access...")
    try:
        response = requests.get("http://systemmanager-mcp.yourtailnet.ts.net:8080/sse", timeout=5)
        print(f"✅ MagicDNS: {response.status_code}")
        return True
    except Exception as e:
        print(f"❌ MagicDNS failed: {e}")
        return False

def test_srv_discovery():
    """Test DNS SRV record discovery"""
    if not HAS_DNS:
        return False

    print("\n🔍 Testing DNS SRV discovery...")
    try:
        answers = dns.resolver.resolve('_systemmanager-mcp._tcp.yourtailnet.ts.net', 'SRV')
        for rdata in answers:
            print(f"✅ SRV Record: {rdata.target}:{rdata.port} (priority={rdata.priority}, weight={rdata.weight})")
        return True
    except Exception as e:
        print(f"❌ SRV discovery failed: {e}")
        return False

def test_direct_ip():
    """Test direct TailVIP access"""
    print("\n🔍 Testing TailVIP access...")
    print("💡 Get TailVIP with: tailscale status | grep systemmanager-mcp")
    # Note: VIP changes per tailnet, user must find it
    return None

if __name__ == "__main__":
    print("🧪 Tailscale Service Discovery Test\n")
    print("=" * 60)

    results = {
        "MagicDNS": test_magicdns(),
        "SRV Records": test_srv_discovery(),
        "TailVIP": test_direct_ip()
    }

    print("\n" + "=" * 60)
    print("📊 Results:")
    for method, result in results.items():
        status = "✅" if result is True else "❌" if result is False else "💡"
        print(f"  {status} {method}")
```

## Monitoring & Management

### Check Service Status
```bash
# Check if service is advertising
tailscale serve status --json | jq '.services."svc:systemmanager-mcp"'

# Check service host capability
tailscale status --json | jq '.Self.CapMap."service-host"'

# List all services in admin console
# https://login.tailscale.com/admin/services
```

### Drain Before Maintenance
```bash
# Gracefully stop accepting new connections
tailscale serve drain svc:systemmanager-mcp

# Wait for connections to close, then stop service
sudo systemctl stop systemmanager-mcp

# Remove service configuration
tailscale serve clear svc:systemmanager-mcp
```

### Update Service Configuration
```bash
# Change port or endpoint
tailscale serve --service=svc:systemmanager-mcp \
    --tls-terminated-tcp=8081 \
    tcp://localhost:8081

# Verify update
tailscale serve status
```

## Benefits vs Direct Access

| Aspect | Direct (dev1:8080) | Tailscale Service |
|--------|-------------------|-------------------|
| **Service Name** | Tied to host | Stable service name |
| **Failover** | Manual | Automatic |
| **Discovery** | Hard-coded config | DNS SRV / MagicDNS |
| **Access Control** | Node ACLs | Service-specific ACLs |
| **Load Balancing** | None | Automatic across hosts |
| **Migration** | Update all clients | Transparent |

## Migration from Direct Access

### Before (Current)
```json
// .vscode/mcp.json
{
  "mcpServers": {
    "TailOpsMCP": {
      "url": "http://dev1.tailf9480.ts.net:8080/sse"
    }
  }
}
```

### After (Tailscale Service)
```json
// .vscode/mcp.json
{
  "mcpServers": {
    "TailOpsMCP": {
      "url": "http://systemmanager-mcp.king-grouse.ts.net:8080/sse"
    }
  }
}
```

**Advantages:**
- Service name stays same even if you move to different host
- Add dev2, dev3 as backup hosts without config changes
- Centralized access control via Tailscale ACLs

## Troubleshooting

### Service not appearing
```bash
# Check if advertising
tailscale serve status

# Check host capability
tailscale status --json | jq '.Self.CapMap."service-host"'

# Verify device is tagged (required for service hosts)
tailscale status --json | jq '.Self.Tags'
```

### Cannot connect
```bash
# Check ACL allows access
# https://login.tailscale.com/admin/acls

# Verify service is approved
# https://login.tailscale.com/admin/services

# Test direct connection
curl -v http://systemmanager-mcp.<tailnet>.ts.net:8080/sse
```

### Multiple hosts conflict
```bash
# Tailscale load balances automatically
# Check which hosts are advertising
tailscale serve status --all

# Drain specific host if needed
tailscale serve drain svc:systemmanager-mcp
```

## Next Steps

1. **Define Service** in Tailscale admin console
2. **Run Setup Script** on dev1.tailf9480.ts.net
3. **Approve Host** in admin console
4. **Update VS Code Config** to use service name
5. **(Optional) Add Backup Host** on dev2 for HA
6. **(Optional) Set Auto-Approval** policy for automated deployments

## References

- [Tailscale Services Documentation](https://tailscale.com/kb/1552/tailscale-services)
- [Service Configuration File](https://tailscale.com/kb/1589/tailscale-services-configuration-file)
- [ACL Policy Syntax](https://tailscale.com/kb/1337/policy-syntax)
- [DNS SRV Records](https://tailscale.com/kb/1054/dns#srv-records)
