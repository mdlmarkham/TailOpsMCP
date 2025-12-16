"""
Gateway configuration templates for SystemManager control plane.

Provides YAML configuration templates for different gateway deployment scenarios.
"""

BASIC_GATEWAY_TEMPLATE = """
# Basic Gateway Configuration Template
# Minimal gateway configuration for getting started

version: "1.0"

# Gateway configuration
gateway:
  id: "{gateway_id}"
  name: "Basic Gateway"
  description: "Minimal gateway configuration for getting started"
  mode: "gateway"
  role: "standalone"

  # Discovery settings
  discovery_method: "proxmox_api"
  discovery_interval: 300
  auto_register: false
  max_fleet_size: 20

  # Security settings
  require_gateway_auth: true
  gateway_token: "{gateway_token}"

  # Monitoring settings
  health_check_interval: 60
  state_sync_interval: 30

# Target registry (will be populated by discovery)
targets:
  # Local gateway target
  gateway-local:
    id: "gateway-local"
    type: "local"
    executor: "local"
    capabilities:
      - "system:read"
      - "container:read"
      - "network:read"
      - "file:read"
    constraints:
      timeout: 30
      concurrency: 5
      sudo_policy: "none"
    metadata:
      hostname: "{hostname}"
      platform: "{platform}"
      tags: ["gateway", "local", "control-plane"]
"""

PROXMOX_GATEWAY_TEMPLATE = """
# Proxmox Gateway Configuration Template
# Gateway configuration for Proxmox host management

version: "1.0"

# Gateway configuration
gateway:
  id: "{gateway_id}"
  name: "Proxmox Gateway"
  description: "Gateway for managing Proxmox host and containers"
  mode: "gateway"
  role: "primary"

  # Discovery settings
  discovery_method: "proxmox_api"
  discovery_interval: 180
  auto_register: true
  max_fleet_size: 50

  # Security settings
  require_gateway_auth: true
  gateway_token: "{gateway_token}"

  # Monitoring settings
  health_check_interval: 45
  state_sync_interval: 20

# Proxmox target configuration
targets:
  # Proxmox host target
  proxmox-host:
    id: "proxmox-host"
    type: "remote"
    executor: "proxmox"
    connection:
      host: "{proxmox_host}"
      port: 8006
      username: "{proxmox_username}"
      password: "{proxmox_password}"
      timeout: 60
    capabilities:
      - "system:read"
      - "container:read"
      - "container:control"
    constraints:
      timeout: 120
      concurrency: 3
      sudo_policy: "limited"
    metadata:
      hostname: "{proxmox_hostname}"
      platform: "proxmox"
      tags: ["proxmox", "host", "gateway"]

  # Gateway local target
  gateway-local:
    id: "gateway-local"
    type: "local"
    executor: "local"
    capabilities:
      - "system:read"
      - "container:read"
      - "network:read"
    constraints:
      timeout: 30
      concurrency: 5
      sudo_policy: "none"
    metadata:
      hostname: "{hostname}"
      platform: "{platform}"
      tags: ["gateway", "local"]
"""

MULTI_GATEWAY_TEMPLATE = """
# Multi-Gateway Configuration Template
# Configuration for gateway clusters with redundancy

version: "1.0"

# Gateway configuration
gateway:
  id: "{gateway_id}"
  name: "Multi-Gateway Cluster Node"
  description: "Gateway node in a multi-gateway cluster"
  mode: "gateway"
  role: "{gateway_role}"  # primary, secondary, or standalone

  # Discovery settings
  discovery_method: "proxmox_api"
  discovery_interval: 240
  auto_register: true
  max_fleet_size: 100

  # Security settings
  require_gateway_auth: true
  gateway_token: "{gateway_token}"

  # Cluster settings
  cluster_members:
    - "{primary_gateway_id}"
    - "{secondary_gateway_id}"

  # Monitoring settings
  health_check_interval: 30
  state_sync_interval: 15

# Target registry
targets:
  # This gateway's local target
  gateway-local:
    id: "gateway-local"
    type: "local"
    executor: "local"
    capabilities:
      - "system:read"
      - "container:read"
      - "network:read"
      - "cluster:coordination"
    constraints:
      timeout: 30
      concurrency: 10
      sudo_policy: "none"
    metadata:
      hostname: "{hostname}"
      platform: "{platform}"
      tags: ["gateway", "local", "cluster"]

  # Proxmox host target (if applicable)
  proxmox-host:
    id: "proxmox-host"
    type: "remote"
    executor: "proxmox"
    connection:
      host: "{proxmox_host}"
      port: 8006
      username: "{proxmox_username}"
      password: "{proxmox_password}"
      timeout: 60
    capabilities:
      - "system:read"
      - "container:read"
      - "container:control"
    constraints:
      timeout: 120
      concurrency: 5
      sudo_policy: "limited"
    metadata:
      hostname: "{proxmox_hostname}"
      platform: "proxmox"
      tags: ["proxmox", "host"]
"""

DEVELOPMENT_GATEWAY_TEMPLATE = """
# Development Gateway Configuration Template
# Configuration for development and testing environments

version: "1.0"

# Gateway configuration
gateway:
  id: "{gateway_id}"
  name: "Development Gateway"
  description: "Gateway for development and testing"
  mode: "gateway"
  role: "standalone"

  # Discovery settings (disabled for development)
  discovery_method: "manual"
  discovery_interval: 600
  auto_register: false
  max_fleet_size: 10

  # Security settings (relaxed for development)
  require_gateway_auth: false
  gateway_token: ""

  # Monitoring settings
  health_check_interval: 120
  state_sync_interval: 60

# Development targets
targets:
  # Local development target
  dev-local:
    id: "dev-local"
    type: "local"
    executor: "local"
    capabilities:
      - "system:read"
      - "container:read"
      - "container:control"
      - "network:read"
      - "file:read"
    constraints:
      timeout: 30
      concurrency: 10
      sudo_policy: "none"
      require_approval: false
    metadata:
      hostname: "{hostname}"
      platform: "{platform}"
      tags: ["development", "local", "gateway"]

  # Mock Proxmox target for testing
  mock-proxmox:
    id: "mock-proxmox"
    type: "remote"
    executor: "proxmox"
    connection:
      host: "localhost"
      port: 8006
      username: "root@pam"
      password: ""
      timeout: 30
    capabilities:
      - "system:read"
      - "container:read"
    constraints:
      timeout: 60
      concurrency: 2
      sudo_policy: "none"
      require_approval: false
    metadata:
      hostname: "mock-proxmox"
      platform: "proxmox"
      tags: ["development", "mock", "proxmox"]
"""


class GatewayConfigTemplates:
    """Gateway configuration template manager."""

    TEMPLATES = {
        "basic": BASIC_GATEWAY_TEMPLATE,
        "proxmox": PROXMOX_GATEWAY_TEMPLATE,
        "multi": MULTI_GATEWAY_TEMPLATE,
        "development": DEVELOPMENT_GATEWAY_TEMPLATE,
    }

    @classmethod
    def get_template(cls, template_name: str) -> str:
        """Get a configuration template by name."""
        if template_name not in cls.TEMPLATES:
            raise ValueError(
                f"Unknown template: {template_name}. Available: {list(cls.TEMPLATES.keys())}"
            )

        return cls.TEMPLATES[template_name]

    @classmethod
    def list_templates(cls) -> list:
        """List available configuration templates."""
        return list(cls.TEMPLATES.keys())

    @classmethod
    def render_template(cls, template_name: str, context: dict) -> str:
        """Render a configuration template with context variables."""
        template = cls.get_template(template_name)

        # Add default context values
        default_context = {
            "gateway_id": "gateway-001",
            "gateway_token": "",
            "hostname": "localhost",
            "platform": "unknown",
            "proxmox_host": "192.168.1.100",
            "proxmox_username": "root@pam",
            "proxmox_password": "",
            "proxmox_hostname": "proxmox-host",
            "gateway_role": "standalone",
            "primary_gateway_id": "gateway-primary",
            "secondary_gateway_id": "gateway-secondary",
        }

        # Merge context with defaults
        merged_context = {**default_context, **context}

        # Render template
        return template.format(**merged_context)


def create_gateway_config(
    template_name: str, output_path: str, context: dict = None
) -> str:
    """Create a gateway configuration file from a template."""
    if context is None:
        context = {}

    # Render template
    config_content = GatewayConfigTemplates.render_template(template_name, context)

    # Write to file
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(config_content)

    return output_path
