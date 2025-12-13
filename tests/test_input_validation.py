"""
Tests for Input Validation and Allowlisting System
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock

from src.services.input_validator import InputValidator, AllowlistManager, ParameterType, ValidationMode
from src.services.discovery_tools import DiscoveryTools
from src.services.policy_gate import PolicyGate
from src.services.target_registry import TargetRegistry
from src.utils.audit import AuditLogger
from src.utils.errors import SystemManagerError


class TestAllowlistManager:
    """Test AllowlistManager functionality."""
    
    def test_register_discovery_tool(self):
        """Test registering discovery tools."""
        manager = AllowlistManager()
        mock_tool = Mock()
        
        manager.register_discovery_tool("test_tool", mock_tool)
        
        assert "test_tool" in manager._discovery_tools
        assert manager._discovery_tools["test_tool"] == mock_tool
    
    @pytest.mark.asyncio
    async def test_populate_allowlist_success(self):
        """Test successful allowlist population."""
        manager = AllowlistManager()
        mock_tool = AsyncMock(return_value={"success": True, "data": ["value1", "value2"]})
        manager.register_discovery_tool("test_tool", mock_tool)
        
        result = await manager.populate_allowlist("test_tool", "test_target")
        
        assert result == ["value1", "value2"]
        assert "test_tool" in manager._allowlists
        assert "value1" in manager._allowlists["test_tool"]
        assert "value2" in manager._allowlists["test_tool"]
    
    @pytest.mark.asyncio
    async def test_populate_allowlist_failure(self):
        """Test allowlist population failure."""
        manager = AllowlistManager()
        mock_tool = AsyncMock(return_value={"success": False, "error": "Tool failed"})
        manager.register_discovery_tool("test_tool", mock_tool)
        
        with pytest.raises(SystemManagerError):
            await manager.populate_allowlist("test_tool", "test_target")
    
    def test_get_allowlist_empty(self):
        """Test getting empty allowlist."""
        manager = AllowlistManager()
        
        result = manager.get_allowlist("nonexistent")
        
        assert result == []
    
    def test_is_value_allowed(self):
        """Test checking if value is allowed."""
        manager = AllowlistManager()
        manager._allowlists["test_tool"] = {
            "value1": Mock(value="value1"),
            "value2": Mock(value="value2")
        }
        
        assert manager.is_value_allowed("test_tool", "value1") is True
        assert manager.is_value_allowed("test_tool", "value3") is False


class TestInputValidator:
    """Test InputValidator functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.allowlist_manager = Mock(spec=AllowlistManager)
        self.validator = InputValidator(self.allowlist_manager)
    
    @pytest.mark.asyncio
    async def test_validate_service_name_success(self):
        """Test successful service name validation."""
        self.allowlist_manager.is_value_allowed.return_value = True
        
        errors = await self.validator.validate_parameter(
            ParameterType.SERVICE_NAME, "nginx", "test_target"
        )
        
        assert errors == []
    
    @pytest.mark.asyncio
    async def test_validate_service_name_not_allowed(self):
        """Test service name not in allowlist."""
        self.allowlist_manager.is_value_allowed.return_value = False
        self.allowlist_manager.populate_allowlist = AsyncMock()
        
        errors = await self.validator.validate_parameter(
            ParameterType.SERVICE_NAME, "unknown_service", "test_target"
        )
        
        assert len(errors) == 1
        assert "not found" in errors[0]
    
    @pytest.mark.asyncio
    async def test_validate_container_name_success(self):
        """Test successful container name validation."""
        self.allowlist_manager.is_value_allowed.return_value = True
        
        errors = await self.validator.validate_parameter(
            ParameterType.CONTAINER_NAME, "web-app", "test_target"
        )
        
        assert errors == []
    
    @pytest.mark.asyncio
    async def test_validate_file_path_traversal_protection(self):
        """Test file path validation with traversal protection."""
        errors = await self.validator.validate_parameter(
            ParameterType.FILE_PATH, "../../../etc/passwd", "test_target"
        )
        
        assert len(errors) == 1
        assert "directory traversal" in errors[0]
    
    @pytest.mark.asyncio
    async def test_validate_port_number_range(self):
        """Test port number range validation."""
        # Valid port
        errors = await self.validator.validate_parameter(
            ParameterType.PORT_NUMBER, 8080, "test_target"
        )
        assert errors == []
        
        # Invalid port (too high)
        errors = await self.validator.validate_parameter(
            ParameterType.PORT_NUMBER, 70000, "test_target"
        )
        assert len(errors) == 1
        assert "above maximum" in errors[0]
        
        # Invalid port (too low)
        errors = await self.validator.validate_parameter(
            ParameterType.PORT_NUMBER, 0, "test_target"
        )
        assert len(errors) == 1
        assert "below minimum" in errors[0]
    
    @pytest.mark.asyncio
    async def test_validate_timeout_range(self):
        """Test timeout range validation."""
        # Valid timeout
        errors = await self.validator.validate_parameter(
            ParameterType.TIMEOUT, 30, "test_target"
        )
        assert errors == []
        
        # Invalid timeout (too high)
        errors = await self.validator.validate_parameter(
            ParameterType.TIMEOUT, 4000, "test_target"
        )
        assert len(errors) == 1
        assert "above maximum" in errors[0]
    
    @pytest.mark.asyncio
    async def test_validate_hostname_success(self):
        """Test successful hostname validation."""
        errors = await self.validator.validate_parameter(
            ParameterType.HOSTNAME, "example.com", "test_target"
        )
        assert errors == []
    
    @pytest.mark.asyncio
    async def test_validate_hostname_invalid(self):
        """Test invalid hostname validation."""
        errors = await self.validator.validate_parameter(
            ParameterType.HOSTNAME, "invalid..hostname", "test_target"
        )
        assert len(errors) == 1
    
    @pytest.mark.asyncio
    async def test_validate_ip_address_success(self):
        """Test successful IP address validation."""
        errors = await self.validator.validate_parameter(
            ParameterType.IP_ADDRESS, "192.168.1.1", "test_target"
        )
        assert errors == []
    
    @pytest.mark.asyncio
    async def test_validate_ip_address_invalid(self):
        """Test invalid IP address validation."""
        errors = await self.validator.validate_parameter(
            ParameterType.IP_ADDRESS, "999.999.999.999", "test_target"
        )
        assert len(errors) == 1
    
    @pytest.mark.asyncio
    async def test_validate_url_success(self):
        """Test successful URL validation."""
        errors = await self.validator.validate_parameter(
            ParameterType.URL, "https://example.com/api", "test_target"
        )
        assert errors == []
    
    @pytest.mark.asyncio
    async def test_validate_url_invalid(self):
        """Test invalid URL validation."""
        errors = await self.validator.validate_parameter(
            ParameterType.URL, "not-a-url", "test_target"
        )
        assert len(errors) == 1


class TestDiscoveryTools:
    """Test DiscoveryTools functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.discovery_tools = DiscoveryTools()
        # Mock dependencies
        self.discovery_tools.docker_manager = Mock()
        self.discovery_tools.compose_manager = Mock()
        self.discovery_tools.network_status = Mock()
        self.discovery_tools.inventory = Mock()
    
    @pytest.mark.asyncio
    async def test_list_services_success(self):
        """Test successful service discovery."""
        self.discovery_tools.inventory.list_services.return_value = {
            "nginx": {"type": "web", "status": "running"},
            "postgres": {"type": "database", "status": "running"}
        }
        
        result = await self.discovery_tools.list_services("test_target")
        
        assert result["success"] is True
        assert len(result["data"]) == 2
        assert result["target"] == "test_target"
    
    @pytest.mark.asyncio
    async def test_list_containers_success(self):
        """Test successful container discovery."""
        self.discovery_tools.docker_manager.list_containers = AsyncMock(
            return_value={
                "success": True,
                "data": [
                    {"name": "web", "status": "running"},
                    {"name": "db", "status": "stopped"}
                ]
            }
        )
        
        result = await self.discovery_tools.list_containers("test_target")
        
        assert result["success"] is True
        assert len(result["data"]) == 2
        assert result["target"] == "test_target"
    
    @pytest.mark.asyncio
    async def test_list_stacks_success(self):
        """Test successful stack discovery."""
        self.discovery_tools.inventory.list_stacks.return_value = {
            "web-stack": {"path": "/opt/stacks/web"},
            "db-stack": {"path": "/opt/stacks/db"}
        }
        
        result = await self.discovery_tools.list_stacks("test_target")
        
        assert result["success"] is True
        assert len(result["data"]) == 2
        assert result["target"] == "test_target"
    
    @pytest.mark.asyncio
    async def test_list_ports_success(self):
        """Test successful port discovery."""
        result = await self.discovery_tools.list_ports("test_target")
        
        assert result["success"] is True
        assert "data" in result
        assert result["target"] == "test_target"


class TestPolicyGateIntegration:
    """Test PolicyGate integration with input validation."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.target_registry = Mock(spec=TargetRegistry)
        self.audit_logger = Mock(spec=AuditLogger)
        self.policy_gate = PolicyGate(self.target_registry, self.audit_logger)
        
        # Mock dependencies
        self.policy_gate.allowlist_manager = Mock()
        self.policy_gate.discovery_tools = Mock()
        self.policy_gate.input_validator = Mock()
    
    @pytest.mark.asyncio
    async def test_validate_parameters_with_enhanced_validation(self):
        """Test enhanced parameter validation."""
        self.policy_gate.input_validator.validate_parameter = AsyncMock(return_value=[])
        
        parameters = {"container": "web-app", "timeout": 30}
        constraints = {"container_name": {"type": "string"}, "timeout": {"type": "int"}}
        
        errors = await self.policy_gate.validate_parameters(
            "start_container", parameters, constraints, "test_target"
        )
        
        assert errors == []
        # Verify input validator was called with correct parameters
        self.policy_gate.input_validator.validate_parameter.assert_called()
    
    @pytest.mark.asyncio
    async def test_validate_parameters_fallback_validation(self):
        """Test fallback to basic validation."""
        # Mock that parameter type mapping doesn't include this parameter
        self.policy_gate._get_parameter_type_mapping = Mock(return_value={})
        
        parameters = {"unknown_param": "value"}
        constraints = {"unknown_param": {"type": "string", "max_length": 10}}
        
        errors = await self.policy_gate.validate_parameters(
            "unknown_operation", parameters, constraints, "test_target"
        )
        
        # Should use basic validation
        assert errors == []  # "value" is valid string within length limit
    
    def test_get_parameter_type_mapping(self):
        """Test parameter type mapping."""
        mapping = self.policy_gate._get_parameter_type_mapping("start_container")
        
        assert "container" in mapping
        assert mapping["container"] == ParameterType.CONTAINER_NAME
        assert "timeout" in mapping
        assert mapping["timeout"] == ParameterType.TIMEOUT
    
    def test_basic_parameter_validation_success(self):
        """Test successful basic parameter validation."""
        errors = self.policy_gate._basic_parameter_validation(
            "test_param", "valid_string", {"type": "string", "max_length": 20}
        )
        
        assert errors == []
    
    def test_basic_parameter_validation_failure(self):
        """Test failed basic parameter validation."""
        errors = self.policy_gate._basic_parameter_validation(
            "test_param", "string_too_long", {"type": "string", "max_length": 5}
        )
        
        assert len(errors) == 1
        assert "exceeds max length" in errors[0]


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v"])