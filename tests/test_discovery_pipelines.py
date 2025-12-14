"""
Test module for Discovery Pipelines implementation.
"""

import unittest
import asyncio
from unittest.mock import Mock, patch
from src.services.proxmox_discovery import ProxmoxDiscovery
from src.services.node_probing import NodeProbing
from src.services.discovery_pipeline import DiscoveryPipeline
from src.services.discovery_manager import DiscoveryManager
from src.models.fleet_inventory import ProxmoxHost, Node, NodeType, Runtime, ConnectionMethod


class TestProxmoxDiscovery(unittest.TestCase):
    """Test Proxmox discovery functionality."""
    
    def test_proxmox_discovery_initialization(self):
        """Test ProxmoxDiscovery initialization."""
        discovery = ProxmoxDiscovery()
        self.assertEqual(discovery.api_config, {})
        
        api_config = {"host": "proxmox.example.com", "username": "test"}
        discovery = ProxmoxDiscovery(api_config)
        self.assertEqual(discovery.api_config, api_config)
    
    @patch('subprocess.run')
    def test_is_proxmox_environment(self, mock_run):
        """Test Proxmox environment detection."""
        discovery = ProxmoxDiscovery()
        
        # Mock successful Proxmox commands
        mock_run.return_value.returncode = 0
        self.assertTrue(discovery._is_proxmox_environment())
        
        # Mock failed Proxmox commands
        mock_run.return_value.returncode = 1
        self.assertFalse(discovery._is_proxmox_environment())
    
    def test_create_discovery_event(self):
        """Test discovery event creation."""
        discovery = ProxmoxDiscovery()
        event = discovery.create_discovery_event(
            "test_source",
            "Test message",
            target_id="test-id",
            target_type="test-type"
        )
        
        self.assertEqual(event.event_type, "discovery")
        self.assertEqual(event.source, "test_source")
        self.assertEqual(event.message, "Test message")
        self.assertEqual(event.target_id, "test-id")


class TestNodeProbing(unittest.TestCase):
    """Test node probing functionality."""
    
    def test_node_probing_initialization(self):
        """Test NodeProbing initialization."""
        probing = NodeProbing()
        self.assertEqual(probing.tailscale_config, {})
        
        tailscale_config = {"enabled": True, "ssh_user": "root"}
        probing = NodeProbing(tailscale_config)
        self.assertEqual(probing.tailscale_config, tailscale_config)
    
    def test_parse_os_info(self):
        """Test OS information parsing."""
        probing = NodeProbing()
        
        os_info = """NAME="Ubuntu"
VERSION="20.04"
ID=ubuntu
ID_LIKE=debian"""
        
        parsed = probing._parse_os_info(os_info)
        self.assertEqual(parsed["NAME"], "Ubuntu")
        self.assertEqual(parsed["VERSION"], "20.04")
        self.assertEqual(parsed["ID"], "ubuntu")
    
    def test_parse_docker_status(self):
        """Test Docker status parsing."""
        probing = NodeProbing()
        
        # Docker installed
        status = "Docker version 20.10.17, build 100c701"
        parsed = probing._parse_docker_status(status)
        self.assertTrue(parsed["installed"])
        self.assertEqual(parsed["version"], "20.10.17")
        
        # Docker not installed
        status = "Docker not installed"
        parsed = probing._parse_docker_status(status)
        self.assertFalse(parsed["installed"])
    
    def test_create_probe_event(self):
        """Test probe event creation."""
        probing = NodeProbing()
        
        node = Node(
            name="test-node",
            node_type=NodeType.CONTAINER,
            host_id="test-host",
            runtime=Runtime.SYSTEMD,
            connection_method=ConnectionMethod.SSH
        )
        
        probe_result = {
            "connection_tests": {
                "ssh": {"success": True}
            },
            "services": ["service1", "service2"],
            "timestamp": "2023-01-01T00:00:00Z"
        }
        
        event = probing.create_probe_event(node, probe_result)
        self.assertEqual(event.event_type, "health_check")
        self.assertIn("test-node", event.message)
        self.assertEqual(event.target_id, node.id)


class TestDiscoveryPipeline(unittest.TestCase):
    """Test discovery pipeline functionality."""
    
    def test_discovery_pipeline_initialization(self):
        """Test DiscoveryPipeline initialization."""
        config = {
            "discovery_interval": 300,
            "health_check_interval": 60
        }
        
        pipeline = DiscoveryPipeline(config)
        self.assertEqual(pipeline.config, config)
        self.assertEqual(pipeline.discovery_interval, 300)
        self.assertEqual(pipeline.health_check_interval, 60)
        self.assertIsNone(pipeline.last_discovery)
    
    def test_should_run_discovery(self):
        """Test discovery scheduling logic."""
        pipeline = DiscoveryPipeline()
        
        # Should run when never run before
        self.assertTrue(pipeline.should_run_discovery())
        
        # Mock last discovery to be recent
        import datetime
        pipeline.last_discovery = datetime.datetime.utcnow() - datetime.timedelta(seconds=100)  # 100 seconds ago
        pipeline.discovery_interval = 300  # 5 minutes
        
        # Should not run if within interval
        self.assertFalse(pipeline.should_run_discovery())
        
        # Mock last discovery to be old
        pipeline.last_discovery = datetime.datetime.utcnow() - datetime.timedelta(seconds=400)  # 400 seconds ago
        
        # Should run if past interval
        self.assertTrue(pipeline.should_run_discovery())
    
    def test_get_nodes_for_probing(self):
        """Test node selection for probing."""
        pipeline = DiscoveryPipeline()
        
        # Create test nodes
        active_node = Node(
            name="active-node",
            node_type=NodeType.CONTAINER,
            host_id="test-host",
            runtime=Runtime.SYSTEMD,
            connection_method=ConnectionMethod.SSH,
            status="running",
            last_updated="2023-01-01T00:00:00Z"
        )
        
        stopped_node = Node(
            name="stopped-node",
            node_type=NodeType.CONTAINER,
            host_id="test-host",
            runtime=Runtime.SYSTEMD,
            connection_method=ConnectionMethod.SSH,
            status="stopped",
            last_updated="2023-01-01T00:00:00Z"
        )
        
        # Add nodes to inventory
        pipeline.inventory.add_node(active_node)
        pipeline.inventory.add_node(stopped_node)
        
        # Only active nodes should be selected
        nodes_to_probe = pipeline._get_nodes_for_probing()
        self.assertEqual(len(nodes_to_probe), 1)
        self.assertEqual(nodes_to_probe[0].name, "active-node")


class TestDiscoveryManager(unittest.TestCase):
    """Test discovery manager functionality."""
    
    @patch.dict('os.environ', {
        'SYSTEMMANAGER_DISCOVERY_INTERVAL': '600',
        'SYSTEMMANAGER_HEALTH_CHECK_INTERVAL': '120',
        'SYSTEMMANAGER_MAX_CONCURRENT_PROBES': '10',
        'TAILSCALE_ENABLED': 'true'
    })
    def test_load_config_from_env(self):
        """Test configuration loading from environment."""
        manager = DiscoveryManager()
        config = manager.config
        
        self.assertEqual(config["discovery_interval"], 600)
        self.assertEqual(config["health_check_interval"], 120)
        self.assertEqual(config["max_concurrent_probes"], 10)
        self.assertTrue(config["tailscale"]["enabled"])
    
    def test_get_configuration(self):
        """Test configuration retrieval."""
        manager = DiscoveryManager()
        config = manager.get_configuration()
        
        self.assertIn("intervals", config)
        self.assertIn("limits", config)
        self.assertIn("features", config)
        self.assertFalse(config["features"]["auto_register"])
    
    def test_update_configuration(self):
        """Test configuration updates."""
        manager = DiscoveryManager()
        
        new_config = {
            "discovery_interval": 900,
            "health_check_interval": 180,
            "max_concurrent_probes": 8,
            "auto_register": True
        }
        
        updated_config = manager.update_configuration(new_config)
        
        self.assertEqual(updated_config["intervals"]["discovery"], 900)
        self.assertEqual(updated_config["intervals"]["health_check"], 180)
        self.assertEqual(updated_config["limits"]["max_concurrent_probes"], 8)
        self.assertTrue(updated_config["features"]["auto_register"])


async def test_discovery_pipeline_integration():
    """Test discovery pipeline integration."""
    
    # Mock the ProxmoxDiscovery to avoid actual system calls
    with patch('src.services.proxmox_discovery.ProxmoxDiscovery.discover_proxmox_hosts') as mock_discover:
        with patch('src.services.proxmox_discovery.ProxmoxDiscovery.discover_nodes') as mock_discover_nodes:
            with patch('src.services.node_probing.NodeProbing.probe_node') as mock_probe:
                
                # Setup mocks
                mock_discover.return_value = []  # No Proxmox hosts found
                mock_discover_nodes.return_value = []  # No nodes found
                mock_probe.return_value = {
                    "connection_tests": {"ssh": {"success": True}},
                    "system_info": {"parsed": {"hostname": "test-node"}},
                    "services": [],
                    "timestamp": "2023-01-01T00:00:00Z"
                }
                
                # Create and run pipeline
                pipeline = DiscoveryPipeline()
                inventory = await pipeline.run_discovery_cycle()
                
                # Verify results
                self.assertIsNotNone(inventory)
                self.assertEqual(inventory.total_hosts, 0)
                self.assertEqual(inventory.total_nodes, 0)


async def test_discovery_manager_operations():
    """Test discovery manager operations."""
    
    with patch('src.services.discovery_pipeline.DiscoveryPipeline.run_discovery_cycle') as mock_run:
        
        # Setup mock
        mock_inventory = Mock()
        mock_inventory.to_dict.return_value = {"hosts": 0, "nodes": 0}
        mock_run.return_value = mock_inventory
        
        # Test manager operations
        manager = DiscoveryManager()
        
        # Test force discovery
        result = await manager.force_discovery()
        self.assertTrue(result["success"])
        self.assertIn("inventory", result)
        
        # Test status retrieval
        status = manager.get_discovery_status()
        self.assertIn("last_discovery", status)
        self.assertIn("inventory_stats", status)


def test_create_default_discovery_config():
    """Test default configuration creation."""
    from src.services.discovery_manager import create_default_discovery_config
    
    config = create_default_discovery_config()
    
    self.assertEqual(config["discovery_interval"], 300)
    self.assertEqual(config["health_check_interval"], 60)
    self.assertEqual(config["max_concurrent_probes"], 5)
    self.assertFalse(config["auto_register"])
    self.assertEqual(config["proxmox_api"]["username"], "root@pam")
    self.assertEqual(config["tailscale"]["ssh_user"], "root")


if __name__ == "__main__":
    # Run the tests
    unittest.main()