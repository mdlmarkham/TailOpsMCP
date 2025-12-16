"""Test suite for fleet management tools in Gateway mode."""

import pytest
from unittest.mock import Mock, patch, AsyncMock
from src.tools.fleet_tools import register_tools
from src.tools.fleet_policy import (
    load_fleet_management_policy,
    validate_operation_parameters,
)


class TestFleetTools:
    """Test cases for fleet management tools."""

    @pytest.fixture
    def mock_mcp(self):
        """Create a mock MCP instance."""
        mcp = Mock()
        mcp.tool = Mock(return_value=lambda func: func)
        return mcp

    @pytest.fixture
    def mock_policy_gate(self):
        """Create a mock policy gate."""
        policy_gate = Mock()
        policy_gate.authorize = AsyncMock()
        return policy_gate

    @pytest.fixture
    def mock_discovery_manager(self):
        """Create a mock discovery manager."""
        manager = Mock()
        manager.pipeline = Mock()
        manager.pipeline.run_discovery = AsyncMock()
        return manager

    @pytest.fixture
    def mock_inventory_persistence(self):
        """Create a mock inventory persistence."""
        persistence = Mock()
        persistence.load_latest = Mock()
        return persistence

    def test_register_tools(self, mock_mcp):
        """Test that fleet tools are registered correctly."""
        register_tools(mock_mcp)

        # Verify tools are registered
        assert mock_mcp.tool.call_count == 5  # 5 fleet management tools

    @pytest.mark.asyncio
    async def test_fleet_discover_success(
        self, mock_mcp, mock_policy_gate, mock_discovery_manager
    ):
        """Test successful fleet discovery."""
        with (
            patch("src.tools.fleet_tools.is_gateway_mode", return_value=True),
            patch("src.tools.fleet_tools.PolicyGate", return_value=mock_policy_gate),
            patch(
                "src.tools.fleet_tools.DiscoveryManager",
                return_value=mock_discovery_manager,
            ),
            patch("src.tools.fleet_tools.format_response") as mock_format_response,
        ):
            # Mock discovery result
            mock_discovery_result = Mock()
            mock_discovery_result.nodes = [Mock(), Mock()]
            mock_discovery_result.services = [Mock()]
            mock_discovery_result.containers = [Mock(), Mock(), Mock()]
            mock_discovery_result.to_dict = Mock(return_value={"test": "data"})
            mock_discovery_manager.pipeline.run_discovery.return_value = (
                mock_discovery_result
            )

            # Register tools and get the fleet_discover function
            register_tools(mock_mcp)
            fleet_discover = mock_mcp.tool.call_args_list[0][0][0]

            # Call the function
            result = await fleet_discover(
                targets=["node1", "node2"], force_refresh=True, format="toon"
            )

            # Verify calls
            mock_policy_gate.authorize.assert_called_once()
            mock_discovery_manager.pipeline.run_discovery.assert_called_once_with(
                targets=["node1", "node2"], force_refresh=True
            )
            mock_format_response.assert_called_once()

    @pytest.mark.asyncio
    async def test_fleet_discover_not_gateway_mode(self, mock_mcp):
        """Test fleet discovery fails when not in gateway mode."""
        with (
            patch("src.tools.fleet_tools.is_gateway_mode", return_value=False),
            patch("src.tools.fleet_tools.format_error") as mock_format_error,
        ):
            register_tools(mock_mcp)
            fleet_discover = mock_mcp.tool.call_args_list[0][0][0]

            result = await fleet_discover()

            mock_format_error.assert_called_once_with(
                "fleet_discover", "Operation only available in gateway mode"
            )

    @pytest.mark.asyncio
    async def test_fleet_inventory_get_success(
        self, mock_mcp, mock_policy_gate, mock_inventory_persistence
    ):
        """Test successful fleet inventory retrieval."""
        with (
            patch("src.tools.fleet_tools.is_gateway_mode", return_value=True),
            patch("src.tools.fleet_tools.PolicyGate", return_value=mock_policy_gate),
            patch(
                "src.tools.fleet_tools.FleetInventoryPersistence",
                return_value=mock_inventory_persistence,
            ),
            patch("src.tools.fleet_tools.format_response") as mock_format_response,
        ):
            # Mock inventory
            mock_inventory = Mock()
            mock_inventory.nodes = [Mock(), Mock(), Mock()]
            mock_inventory.services = [Mock(), Mock()]
            mock_inventory.containers = [Mock()]
            mock_inventory.last_updated = Mock()
            mock_inventory.to_dict = Mock(return_value={"inventory": "data"})
            mock_inventory_persistence.load_latest.return_value = mock_inventory

            register_tools(mock_mcp)
            fleet_inventory_get = mock_mcp.tool.call_args_list[1][0][0]

            result = await fleet_inventory_get(format="json")

            mock_policy_gate.authorize.assert_called_once()
            mock_inventory_persistence.load_latest.assert_called_once()
            mock_format_response.assert_called_once()

    @pytest.mark.asyncio
    async def test_fleet_node_health_success(
        self, mock_mcp, mock_policy_gate, mock_inventory_persistence
    ):
        """Test successful node health check."""
        with (
            patch("src.tools.fleet_tools.is_gateway_mode", return_value=True),
            patch("src.tools.fleet_tools.PolicyGate", return_value=mock_policy_gate),
            patch(
                "src.tools.fleet_tools.FleetInventoryPersistence",
                return_value=mock_inventory_persistence,
            ),
            patch("src.tools.fleet_tools.format_response") as mock_format_response,
        ):
            # Mock inventory with node
            mock_node = Mock()
            mock_node.last_seen = Mock()
            mock_inventory = Mock()
            mock_inventory.get_node = Mock(return_value=mock_node)
            mock_inventory.get_events_for_node = Mock(return_value=[])
            mock_inventory_persistence.load_latest.return_value = mock_inventory

            register_tools(mock_mcp)
            fleet_node_health = mock_mcp.tool.call_args_list[2][0][0]

            result = await fleet_node_health(node_id="test-node")

            mock_policy_gate.authorize.assert_called_once()
            mock_inventory.get_node.assert_called_once_with("test-node")
            mock_inventory.get_events_for_node.assert_called_once_with(
                "test-node", limit=10
            )
            mock_format_response.assert_called_once()

    @pytest.mark.asyncio
    async def test_fleet_operation_plan_success(self, mock_mcp, mock_policy_gate):
        """Test successful operation planning."""
        with (
            patch("src.tools.fleet_tools.is_gateway_mode", return_value=True),
            patch("src.tools.fleet_tools.PolicyGate", return_value=mock_policy_gate),
            patch("src.tools.fleet_tools.format_response") as mock_format_response,
        ):
            register_tools(mock_mcp)
            fleet_operation_plan = mock_mcp.tool.call_args_list[3][0][0]

            result = await fleet_operation_plan(
                op_name="update_packages",
                targets=["node1", "node2"],
                parameters={"update_only": True},
            )

            # Verify authorization was called for each target
            assert mock_policy_gate.authorize.call_count == 2
            mock_format_response.assert_called_once()

    @pytest.mark.asyncio
    async def test_fleet_operation_plan_invalid_operation(self, mock_mcp):
        """Test operation planning with invalid operation name."""
        with (
            patch("src.tools.fleet_tools.is_gateway_mode", return_value=True),
            patch("src.tools.fleet_tools.format_error") as mock_format_error,
        ):
            register_tools(mock_mcp)
            fleet_operation_plan = mock_mcp.tool.call_args_list[3][0][0]

            result = await fleet_operation_plan(
                op_name="invalid_operation", targets=["node1"], parameters={}
            )

            mock_format_error.assert_called_once()

    @pytest.mark.asyncio
    async def test_fleet_operation_execute_success(self, mock_mcp, mock_policy_gate):
        """Test successful operation execution."""
        with (
            patch("src.tools.fleet_tools.is_gateway_mode", return_value=True),
            patch("src.tools.fleet_tools.PolicyGate", return_value=mock_policy_gate),
            patch(
                "src.tools.fleet_tools._retrieve_operation_plan"
            ) as mock_retrieve_plan,
            patch("src.tools.fleet_tools._execute_operation_plan") as mock_execute_plan,
            patch("src.tools.fleet_tools._store_operation_plan") as mock_store_plan,
            patch("src.tools.fleet_tools.format_response") as mock_format_response,
        ):
            # Mock operation plan
            mock_plan = {
                "plan_id": "test-plan",
                "operation": "update_packages",
                "targets": ["node1", "node2"],
                "parameters": {"update_only": True},
                "status": "planned",
            }
            mock_retrieve_plan.return_value = mock_plan
            mock_execute_plan.return_value = {
                "node1": {"success": True},
                "node2": {"success": True},
            }

            register_tools(mock_mcp)
            fleet_operation_execute = mock_mcp.tool.call_args_list[4][0][0]

            result = await fleet_operation_execute(plan_id="test-plan")

            # Verify authorization was called for each target
            assert mock_policy_gate.authorize.call_count == 2
            mock_execute_plan.assert_called_once_with(mock_plan)
            mock_store_plan.assert_called_once()
            mock_format_response.assert_called_once()


class TestFleetPolicy:
    """Test cases for fleet management policy."""

    def test_load_fleet_management_policy(self):
        """Test loading fleet management policy."""
        with patch("src.tools.fleet_policy.Path") as mock_path:
            mock_path.return_value.exists.return_value = True
            mock_path.return_value.open.return_value.__enter__.return_value.read.return_value = """
            version: "1.0"
            policy_name: "test"
            operations:
              test_op:
                tier: observe
            """

            policy = load_fleet_management_policy()

            assert policy["version"] == "1.0"
            assert policy["policy_name"] == "test"

    def test_validate_operation_parameters_valid(self):
        """Test valid operation parameters."""
        errors = validate_operation_parameters("restart_service", {"service": "nginx"})

        assert len(errors) == 0

    def test_validate_operation_parameters_invalid_service(self):
        """Test invalid service parameters."""
        errors = validate_operation_parameters("restart_service", {"service": ""})

        assert len(errors) > 0
        assert "Service name is required" in errors[0]

    def test_validate_operation_parameters_unknown_operation(self):
        """Test unknown operation."""
        errors = validate_operation_parameters("unknown_operation", {"param": "value"})

        assert len(errors) > 0
        assert "Unknown operation" in errors[0]


if __name__ == "__main__":
    # Run the tests
    pytest.main([__file__, "-v"])
