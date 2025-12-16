"""
Common Operational Workflow Blueprints for TailOpsMCP.

Provides pre-built, production-ready workflow blueprints for common
operational tasks like provisioning, backup, upgrade, and recovery.
"""

import logging
from datetime import timedelta
from typing import List

from src.models.workflow_models import (
    WorkflowBlueprint,
    WorkflowCategory,
    StepType,
    WorkflowStep,
    Parameter,
    RollbackAction,
    RollbackPlan,
    RetryPolicy,
)


logger = logging.getLogger(__name__)


class EnvironmentProvisioningWorkflow(WorkflowBlueprint):
    """Set up a new Type-X environment with containers, services, and networking."""

    def __init__(
        self,
        environment_name: str,
        container_count: int = 3,
        service_type: str = "web",
        node_type: str = "standard",
    ):
        """Initialize environment provisioning workflow."""

        # Define parameters
        parameters = {
            "environment_name": Parameter(
                name="environment_name",
                type="string",
                required=True,
                description="Name of the environment to provision",
            ),
            "container_count": Parameter(
                name="container_count",
                type="integer",
                required=True,
                default=container_count,
                validation={"min": 1, "max": 100},
                description="Number of containers to create",
            ),
            "service_type": Parameter(
                name="service_type",
                type="string",
                required=True,
                choices=["web", "api", "database", "cache", "message-queue"],
                description="Type of service to deploy",
            ),
            "node_type": Parameter(
                name="node_type",
                type="string",
                required=True,
                choices=["standard", "high-memory", "high-cpu", "gpu"],
                description="Node type for containers",
            ),
            "backup_enabled": Parameter(
                name="backup_enabled",
                type="boolean",
                required=False,
                default=True,
                description="Enable automatic backups",
            ),
            "monitoring_enabled": Parameter(
                name="monitoring_enabled",
                type="boolean",
                required=False,
                default=True,
                description="Enable monitoring and alerting",
            ),
        }

        # Define workflow steps
        steps = [
            WorkflowStep(
                step_id="validate_prerequisites",
                name="Validate Prerequisites",
                description="Validate system prerequisites and resource availability",
                step_type=StepType.VALIDATION,
                timeout=timedelta(minutes=5),
                retry_policy=RetryPolicy(
                    max_attempts=3, initial_delay=timedelta(seconds=30)
                ),
            ),
            WorkflowStep(
                step_id="check_resource_availability",
                name="Check Resource Availability",
                description="Check available CPU, memory, and disk resources",
                step_type=StepType.VALIDATION,
                timeout=timedelta(minutes=10),
                dependencies=["validate_prerequisites"],
            ),
            WorkflowStep(
                step_id="allocate_resources",
                name="Allocate Resources",
                description="Allocate necessary resources for the environment",
                step_type=StepType.RESOURCE_ALLOCATION,
                timeout=timedelta(minutes=15),
                requires_approval=True,
                approvers=["operations_manager"],
                retry_policy=RetryPolicy(
                    max_attempts=2, initial_delay=timedelta(minutes=1)
                ),
            ),
            WorkflowStep(
                step_id="create_network",
                name="Create Network",
                description="Create dedicated network for the environment",
                step_type=StepType.NETWORK_CONFIGURATION,
                timeout=timedelta(minutes=10),
                dependencies=["allocate_resources"],
            ),
            WorkflowStep(
                step_id="create_containers",
                name="Create Containers",
                description="Create and configure containers based on specifications",
                step_type=StepType.CONTAINER_OPERATIONS,
                timeout=timedelta(minutes=45),
                dependencies=["create_network"],
                retry_policy=RetryPolicy(
                    max_attempts=3, initial_delay=timedelta(minutes=2)
                ),
            ),
            WorkflowStep(
                step_id="configure_storage",
                name="Configure Storage",
                description="Set up persistent storage for containers",
                step_type=StepType.CONTAINER_OPERATIONS,
                timeout=timedelta(minutes=20),
                dependencies=["create_containers"],
            ),
            WorkflowStep(
                step_id="deploy_services",
                name="Deploy Services",
                description="Deploy application services to containers",
                step_type=StepType.SERVICE_DEPLOYMENT,
                timeout=timedelta(minutes=30),
                dependencies=["configure_storage"],
                retry_policy=RetryPolicy(
                    max_attempts=2, initial_delay=timedelta(minutes=2)
                ),
            ),
            WorkflowStep(
                step_id="configure_load_balancer",
                name="Configure Load Balancer",
                description="Set up load balancer for the environment",
                step_type=StepType.NETWORK_CONFIGURATION,
                timeout=timedelta(minutes=15),
                dependencies=["deploy_services"],
            ),
            WorkflowStep(
                step_id="setup_monitoring",
                name="Setup Monitoring",
                description="Configure monitoring and alerting for the environment",
                step_type=StepType.CONFIGURATION,
                timeout=timedelta(minutes=20),
                dependencies=["configure_load_balancer"],
            ),
            WorkflowStep(
                step_id="run_health_checks",
                name="Run Health Checks",
                description="Perform comprehensive health validation",
                step_type=StepType.HEALTH_VALIDATION,
                timeout=timedelta(minutes=15),
                dependencies=["setup_monitoring"],
            ),
            WorkflowStep(
                step_id="run_integration_tests",
                name="Run Integration Tests",
                description="Run integration tests to verify functionality",
                step_type=StepType.TESTING,
                timeout=timedelta(minutes=30),
                dependencies=["run_health_checks"],
            ),
            WorkflowStep(
                step_id="create_initial_backup",
                name="Create Initial Backup",
                description="Create initial backup of the environment",
                step_type=StepType.BACKUP,
                timeout=timedelta(minutes=45),
                dependencies=["run_integration_tests"],
                requires_approval=True,
                approvers=["security_admin"],
            ),
            WorkflowStep(
                step_id="setup_automated_backups",
                name="Setup Automated Backups",
                description="Configure automated backup schedule",
                step_type=StepType.CONFIGURATION,
                timeout=timedelta(minutes=10),
                dependencies=["create_initial_backup"],
            ),
        ]

        # Define rollback plan
        rollback_actions = [
            RollbackAction(
                action_id="cleanup_containers",
                name="Cleanup Created Containers",
                step_type=StepType.CONTAINER_OPERATIONS,
                parameters={"action": "delete_all", "preserve_data": False},
            ),
            RollbackAction(
                action_id="cleanup_network",
                name="Cleanup Network",
                step_type=StepType.NETWORK_CONFIGURATION,
                parameters={"action": "delete"},
            ),
            RollbackAction(
                action_id="cleanup_storage",
                name="Cleanup Storage",
                step_type=StepType.CONTAINER_OPERATIONS,
                parameters={"action": "cleanup_volumes"},
            ),
            RollbackAction(
                action_id="cleanup_resources",
                name="Release Allocated Resources",
                step_type=StepType.RESOURCE_ALLOCATION,
                parameters={"action": "release"},
            ),
        ]

        rollback_plan = RollbackPlan(
            enabled=True,
            actions=rollback_actions,
            conditions=[
                "container_creation_failed",
                "service_deployment_failed",
                "health_check_failed",
            ],
        )

        # Initialize base workflow
        super().__init__(
            name="Environment Provisioning",
            description=f"Provision complete {service_type} environment with {container_count} containers",
            version="1.0.0",
            category=WorkflowCategory.PROVISIONING,
            parameters=parameters,
            steps=steps,
            rollback_plan=rollback_plan,
            estimated_duration=timedelta(hours=3),
            resource_requirements={
                "cpu_cores": container_count * 2,
                "memory_gb": container_count * 4,
                "disk_gb": container_count * 50,
                "network_bandwidth_mbps": 1000,
            },
            tags={"provisioning", "environment", service_type, "production-ready"},
            owner="infrastructure-team",
            documentation=f"Provisions a {service_type} environment with {container_count} containers and comprehensive monitoring",
        )


class BackupOrchestrationWorkflow(WorkflowBlueprint):
    """Backup all containers across the fleet with validation."""

    def __init__(
        self, backup_retention_days: int = 30, backup_compression: bool = True
    ):
        """Initialize backup orchestration workflow."""

        # Define parameters
        parameters = {
            "backup_retention_days": Parameter(
                name="backup_retention_days",
                type="integer",
                required=False,
                default=backup_retention_days,
                validation={"min": 1, "max": 365},
                description="Number of days to retain backups",
            ),
            "backup_compression": Parameter(
                name="backup_compression",
                type="boolean",
                required=False,
                default=backup_compression,
                description="Enable backup compression",
            ),
            "backup_destination": Parameter(
                name="backup_destination",
                type="string",
                required=False,
                default="local",
                choices=["local", "s3", "azure", "gcp"],
                description="Backup destination",
            ),
            "include_logs": Parameter(
                name="include_logs",
                type="boolean",
                required=False,
                default=False,
                description="Include container logs in backup",
            ),
            "backup_schedule": Parameter(
                name="backup_schedule",
                type="string",
                required=False,
                default="nightly",
                choices=["hourly", "daily", "weekly", "monthly"],
                description="Backup frequency",
            ),
        }

        # Define workflow steps
        steps = [
            WorkflowStep(
                step_id="discover_backup_targets",
                name="Discover Backup Targets",
                description="Discover all containers and services that need backup",
                step_type=StepType.DISCOVERY,
                timeout=timedelta(minutes=15),
            ),
            WorkflowStep(
                step_id="validate_backup_space",
                name="Validate Backup Storage",
                description="Validate available backup storage space",
                step_type=StepType.VALIDATION,
                timeout=timedelta(minutes=10),
                dependencies=["discover_backup_targets"],
            ),
            WorkflowStep(
                step_id="create_snapshots",
                name="Create Container Snapshots",
                description="Create consistent snapshots of all containers",
                step_type=StepType.SNAPSHOT,
                timeout=timedelta(minutes=90),
                dependencies=["validate_backup_space"],
                retry_policy=RetryPolicy(
                    max_attempts=3, initial_delay=timedelta(minutes=2)
                ),
            ),
            WorkflowStep(
                step_id="backup_configuration",
                name="Backup Configuration",
                description="Backup container configurations and settings",
                step_type=StepType.BACKUP,
                timeout=timedelta(minutes=30),
                dependencies=["create_snapshots"],
            ),
            WorkflowStep(
                step_id="backup_data_volumes",
                name="Backup Data Volumes",
                description="Backup persistent data volumes",
                step_type=StepType.BACKUP,
                timeout=timedelta(minutes=120),
                dependencies=["backup_configuration"],
            ),
            WorkflowStep(
                step_id="upload_backups",
                name="Upload Backups to Storage",
                description="Upload backups to external storage if configured",
                step_type=StepType.TRANSFER,
                timeout=timedelta(minutes=180),
                dependencies=["backup_data_volumes"],
                requires_approval=True,
                approvers=["security_admin"],
            ),
            WorkflowStep(
                step_id="verify_backup_integrity",
                name="Verify Backup Integrity",
                description="Verify integrity of all created backups",
                step_type=StepType.VALIDATION,
                timeout=timedelta(minutes=45),
                dependencies=["upload_backups"],
            ),
            WorkflowStep(
                step_id="cleanup_old_backups",
                name="Cleanup Old Backups",
                description="Clean up expired or old backups",
                step_type=StepType.MAINTENANCE,
                timeout=timedelta(minutes=30),
                dependencies=["verify_backup_integrity"],
            ),
            WorkflowStep(
                step_id="generate_backup_report",
                name="Generate Backup Report",
                description="Generate comprehensive backup report",
                step_type=StepType.CONFIGURATION,
                timeout=timedelta(minutes=15),
                dependencies=["cleanup_old_backups"],
            ),
        ]

        super().__init__(
            name="Fleet Backup Orchestration",
            description="Orchestrate comprehensive backup of all containers across the fleet",
            version="1.0.0",
            category=WorkflowCategory.BACKUP,
            parameters=parameters,
            steps=steps,
            estimated_duration=timedelta(hours=5),
            resource_requirements={
                "storage_gb": 1000,
                "network_bandwidth_mbps": 500,
                "cpu_cores": 4,
            },
            tags={"backup", "maintenance", "fleet", "data-protection"},
            owner="operations-team",
            documentation="Comprehensive fleet backup with integrity validation and automated cleanup",
        )


class SafeUpgradeWorkflow(WorkflowBlueprint):
    """Safely upgrade containers with rollback capability."""

    def __init__(
        self, upgrade_type: str = "rolling", maintenance_window: str = "off-hours"
    ):
        """Initialize safe upgrade workflow."""

        # Define parameters
        parameters = {
            "upgrade_type": Parameter(
                name="upgrade_type",
                type="string",
                required=True,
                choices=["rolling", "blue-green", "canary"],
                description="Type of upgrade strategy",
            ),
            "maintenance_window": Parameter(
                name="maintenance_window",
                type="string",
                required=True,
                choices=["off-hours", "scheduled", "immediate"],
                description="When to perform the upgrade",
            ),
            "max_downtime_minutes": Parameter(
                name="max_downtime_minutes",
                type="integer",
                required=False,
                default=30,
                validation={"min": 1, "max": 120},
                description="Maximum acceptable downtime in minutes",
            ),
            "rollback_on_failure": Parameter(
                name="rollback_on_failure",
                type="boolean",
                required=False,
                default=True,
                description="Automatically rollback on failure",
            ),
            "test_environment": Parameter(
                name="test_environment",
                type="string",
                required=False,
                default="staging",
                description="Test environment for validation",
            ),
        }

        # Define workflow steps
        steps = [
            WorkflowStep(
                step_id="pre_upgrade_assessment",
                name="Pre-upgrade Assessment",
                description="Assess system readiness for upgrade",
                step_type=StepType.VALIDATION,
                timeout=timedelta(minutes=20),
            ),
            WorkflowStep(
                step_id="create_pre_upgrade_snapshots",
                name="Create Pre-upgrade Snapshots",
                description="Create snapshots before upgrade",
                step_type=StepType.SNAPSHOT,
                timeout=timedelta(minutes=45),
                dependencies=["pre_upgrade_assessment"],
                requires_approval=True,
                approvers=["operations_manager", "security_admin"],
            ),
            WorkflowStep(
                step_id="backup_current_state",
                name="Backup Current State",
                description="Backup current application state",
                step_type=StepType.BACKUP,
                timeout=timedelta(minutes=60),
                dependencies=["create_pre_upgrade_snapshots"],
            ),
            WorkflowStep(
                step_id="prepare_rollback_plan",
                name="Prepare Rollback Plan",
                description="Prepare detailed rollback procedures",
                step_type=StepType.VALIDATION,
                timeout=timedelta(minutes=15),
                dependencies=["backup_current_state"],
            ),
            WorkflowStep(
                step_id="upgrade_infrastructure",
                name="Upgrade Infrastructure",
                description="Upgrade infrastructure components first",
                step_type=StepType.UPGRADE,
                timeout=timedelta(minutes=90),
                dependencies=["prepare_rollback_plan"],
                retry_policy=RetryPolicy(
                    max_attempts=2, initial_delay=timedelta(minutes=5)
                ),
            ),
            WorkflowStep(
                step_id="upgrade_containers",
                name="Upgrade Containers",
                description="Upgrade containers based on strategy",
                step_type=StepType.UPGRADE,
                timeout=timedelta(minutes=120),
                dependencies=["upgrade_infrastructure"],
                retry_policy=RetryPolicy(
                    max_attempts=2, initial_delay=timedelta(minutes=3)
                ),
            ),
            WorkflowStep(
                step_id="update_configuration",
                name="Update Configuration",
                description="Update configuration for new versions",
                step_type=StepType.CONFIGURATION,
                timeout=timedelta(minutes=30),
                dependencies=["upgrade_containers"],
            ),
            WorkflowStep(
                step_id="post_upgrade_verification",
                name="Post-upgrade Verification",
                description="Verify successful upgrade",
                step_type=StepType.VALIDATION,
                timeout=timedelta(minutes=30),
                dependencies=["update_configuration"],
            ),
            WorkflowStep(
                step_id="run_smoke_tests",
                name="Run Smoke Tests",
                description="Run smoke tests to verify basic functionality",
                step_type=StepType.TESTING,
                timeout=timedelta(minutes=45),
                dependencies=["post_upgrade_verification"],
            ),
            WorkflowStep(
                step_id="run_integration_tests",
                name="Run Integration Tests",
                description="Run integration tests",
                step_type=StepType.TESTING,
                timeout=timedelta(minutes=60),
                dependencies=["run_smoke_tests"],
            ),
            WorkflowStep(
                step_id="performance_validation",
                name="Performance Validation",
                description="Validate performance after upgrade",
                step_type=StepType.TESTING,
                timeout=timedelta(minutes=45),
                dependencies=["run_integration_tests"],
            ),
            WorkflowStep(
                step_id="update_monitoring",
                name="Update Monitoring Configuration",
                description="Update monitoring for new versions",
                step_type=StepType.CONFIGURATION,
                timeout=timedelta(minutes=20),
                dependencies=["performance_validation"],
            ),
            WorkflowStep(
                step_id="cleanup_old_versions",
                name="Cleanup Old Versions",
                description="Clean up old container versions",
                step_type=StepType.MAINTENANCE,
                timeout=timedelta(minutes=30),
                dependencies=["update_monitoring"],
            ),
        ]

        # Define rollback actions
        rollback_actions = [
            RollbackAction(
                action_id="restore_snapshots",
                name="Restore from Pre-upgrade Snapshots",
                step_type=StepType.RESTORE,
                parameters={"restore_point": "pre_upgrade", "verify_restore": True},
            ),
            RollbackAction(
                action_id="restore_configuration",
                name="Restore Previous Configuration",
                step_type=StepType.CONFIGURATION,
                parameters={"configuration_source": "backup"},
            ),
            RollbackAction(
                action_id="restart_services",
                name="Restart Services",
                step_type=StepType.CONTAINER_OPERATIONS,
                parameters={"action": "restart_all"},
            ),
        ]

        rollback_plan = RollbackPlan(
            enabled=True,
            actions=rollback_actions,
            conditions=[
                "upgrade_failed",
                "health_check_failed",
                "performance_degradation",
            ],
        )

        super().__init__(
            name="Safe Container Upgrade",
            description=f"Safely upgrade containers using {upgrade_type} strategy with rollback capability",
            version="1.0.0",
            category=WorkflowCategory.UPGRADE,
            parameters=parameters,
            steps=steps,
            rollback_plan=rollback_plan,
            estimated_duration=timedelta(hours=6),
            resource_requirements={
                "cpu_cores": 4,
                "memory_gb": 8,
                "storage_gb": 100,
                "network_bandwidth_mbps": 200,
            },
            tags={"upgrade", "safety", "rollback", upgrade_type},
            owner="platform-team",
            documentation=f"Safe {upgrade_type} upgrade with comprehensive testing and rollback capability",
        )


class DisasterRecoveryWorkflow(WorkflowBlueprint):
    """Restore container from timestamped backup with validation."""

    def __init__(
        self, recovery_type: str = "full", validation_level: str = "comprehensive"
    ):
        """Initialize disaster recovery workflow."""

        # Define parameters
        parameters = {
            "recovery_type": Parameter(
                name="recovery_type",
                type="string",
                required=True,
                choices=["full", "partial", "selective"],
                description="Type of recovery to perform",
            ),
            "backup_timestamp": Parameter(
                name="backup_timestamp",
                type="string",
                required=True,
                description="Timestamp of backup to restore from (ISO format)",
            ),
            "validation_level": Parameter(
                name="validation_level",
                type="string",
                required=True,
                choices=["basic", "comprehensive", "minimal"],
                description="Level of validation to perform",
            ),
            "target_environment": Parameter(
                name="target_environment",
                type="string",
                required=True,
                description="Target environment for recovery",
            ),
            "preserve_current_state": Parameter(
                name="preserve_current_state",
                type="boolean",
                required=False,
                default=True,
                description="Preserve current state before recovery",
            ),
        }

        # Define workflow steps
        steps = [
            WorkflowStep(
                step_id="validate_disaster_scenario",
                name="Validate Disaster Scenario",
                description="Assess the disaster and recovery requirements",
                step_type=StepType.VALIDATION,
                timeout=timedelta(minutes=15),
            ),
            WorkflowStep(
                step_id="validate_backup_availability",
                name="Validate Backup Availability",
                description="Verify backup availability and integrity",
                step_type=StepType.VALIDATION,
                timeout=timedelta(minutes=20),
                dependencies=["validate_disaster_scenario"],
            ),
            WorkflowStep(
                step_id="assess_recovery_scope",
                name="Assess Recovery Scope",
                description="Determine what needs to be recovered",
                step_type=StepType.DISCOVERY,
                timeout=timedelta(minutes=15),
                dependencies=["validate_backup_availability"],
            ),
            WorkflowStep(
                step_id="prepare_recovery_environment",
                name="Prepare Recovery Environment",
                description="Prepare environment for recovery",
                step_type=StepType.RESOURCE_ALLOCATION,
                timeout=timedelta(minutes=30),
                dependencies=["assess_recovery_scope"],
                requires_approval=True,
                approvers=["operations_manager", "security_admin"],
            ),
            WorkflowStep(
                step_id="preserve_current_state",
                name="Preserve Current State",
                description="Backup current state before recovery",
                step_type=StepType.SNAPSHOT,
                timeout=timedelta(minutes=45),
                dependencies=["prepare_recovery_environment"],
                conditions=["preserve_current_state"],
            ),
            WorkflowStep(
                step_id="stop_affected_containers",
                name="Stop Affected Containers",
                description="Stop containers that need restoration",
                step_type=StepType.CONTAINER_OPERATIONS,
                timeout=timedelta(minutes=30),
                dependencies=["preserve_current_state"],
            ),
            WorkflowStep(
                step_id="cleanup_corrupted_data",
                name="Cleanup Corrupted Data",
                description="Clean up any corrupted or damaged data",
                step_type=StepType.CONTAINER_OPERATIONS,
                timeout=timedelta(minutes=20),
                dependencies=["stop_affected_containers"],
            ),
            WorkflowStep(
                step_id="restore_infrastructure",
                name="Restore Infrastructure",
                description="Restore infrastructure components",
                step_type=StepType.RESTORE,
                timeout=timedelta(minutes=60),
                dependencies=["cleanup_corrupted_data"],
                retry_policy=RetryPolicy(
                    max_attempts=2, initial_delay=timedelta(minutes=2)
                ),
            ),
            WorkflowStep(
                step_id="restore_containers",
                name="Restore Containers",
                description="Restore containers from backup",
                step_type=StepType.RESTORE,
                timeout=timedelta(minutes=90),
                dependencies=["restore_infrastructure"],
                retry_policy=RetryPolicy(
                    max_attempts=2, initial_delay=timedelta(minutes=3)
                ),
            ),
            WorkflowStep(
                step_id="restore_data_volumes",
                name="Restore Data Volumes",
                description="Restore persistent data volumes",
                step_type=StepType.RESTORE,
                timeout=timedelta(minutes=120),
                dependencies=["restore_containers"],
                retry_policy=RetryPolicy(
                    max_attempts=2, initial_delay=timedelta(minutes=5)
                ),
            ),
            WorkflowStep(
                step_id="restore_configuration",
                name="Restore Configuration",
                description="Restore configuration settings",
                step_type=StepType.RESTORE,
                timeout=timedelta(minutes=30),
                dependencies=["restore_data_volumes"],
            ),
            WorkflowStep(
                step_id="verify_restoration",
                name="Verify Restoration",
                description="Verify successful restoration",
                step_type=StepType.VALIDATION,
                timeout=timedelta(minutes=45),
                dependencies=["restore_configuration"],
            ),
            WorkflowStep(
                step_id="update_network_configuration",
                name="Update Network Configuration",
                description="Update network settings if needed",
                step_type=StepType.NETWORK_CONFIGURATION,
                timeout=timedelta(minutes=20),
                dependencies=["verify_restoration"],
            ),
            WorkflowStep(
                step_id="update_dns_records",
                name="Update DNS Records",
                description="Update DNS records if required",
                step_type=StepType.NETWORK_CONFIGURATION,
                timeout=timedelta(minutes=15),
                dependencies=["update_network_configuration"],
            ),
            WorkflowStep(
                step_id="run_health_checks",
                name="Run Health Checks",
                description="Perform comprehensive health validation",
                step_type=StepType.HEALTH_VALIDATION,
                timeout=timedelta(minutes=30),
                dependencies=["update_dns_records"],
            ),
            WorkflowStep(
                step_id="run_functionality_tests",
                name="Run Functionality Tests",
                description="Test critical functionality",
                step_type=StepType.TESTING,
                timeout=timedelta(minutes=60),
                dependencies=["run_health_checks"],
            ),
            WorkflowStep(
                step_id="update_monitoring",
                name="Update Monitoring",
                description="Update monitoring for recovered systems",
                step_type=StepType.CONFIGURATION,
                timeout=timedelta(minutes=20),
                dependencies=["run_functionality_tests"],
            ),
            WorkflowStep(
                step_id="generate_recovery_report",
                name="Generate Recovery Report",
                description="Generate disaster recovery report",
                step_type=StepType.CONFIGURATION,
                timeout=timedelta(minutes=15),
                dependencies=["update_monitoring"],
            ),
        ]

        super().__init__(
            name="Disaster Recovery",
            description=f"Recover {recovery_type} environment from backup with {validation_level} validation",
            version="1.0.0",
            category=WorkflowCategory.RECOVERY,
            parameters=parameters,
            steps=steps,
            estimated_duration=timedelta(hours=8),
            resource_requirements={
                "cpu_cores": 8,
                "memory_gb": 16,
                "storage_gb": 500,
                "network_bandwidth_mbps": 1000,
            },
            tags={"recovery", "disaster", "restoration", recovery_type},
            owner="operations-team",
            documentation=f"{recovery_type.title()} disaster recovery with {validation_level} validation",
        )


class SecurityComplianceWorkflow(WorkflowBlueprint):
    """Perform security compliance checks and remediation."""

    def __init__(
        self,
        compliance_standard: str = "iso27001",
        remediation_level: str = "automated",
    ):
        """Initialize security compliance workflow."""

        # Define parameters
        parameters = {
            "compliance_standard": Parameter(
                name="compliance_standard",
                type="string",
                required=True,
                choices=["iso27001", "nist", "sox", "gdpr", "hipaa", "custom"],
                description="Compliance standard to validate against",
            ),
            "remediation_level": Parameter(
                name="remediation_level",
                type="string",
                required=True,
                choices=["automated", "manual", "hybrid"],
                description="Level of automated remediation",
            ),
            "scan_scope": Parameter(
                name="scan_scope",
                type="string",
                required=False,
                default="full",
                choices=["full", "critical", "configurations", "vulnerabilities"],
                description="Scope of compliance scan",
            ),
            "generate_report": Parameter(
                name="generate_report",
                type="boolean",
                required=False,
                default=True,
                description="Generate comprehensive compliance report",
            ),
        }

        # Define workflow steps
        steps = [
            WorkflowStep(
                step_id="prepare_compliance_scan",
                name="Prepare Compliance Scan",
                description="Prepare system for compliance scanning",
                step_type=StepType.VALIDATION,
                timeout=timedelta(minutes=15),
            ),
            WorkflowStep(
                step_id="scan_security_configurations",
                name="Scan Security Configurations",
                description="Scan security configurations against standards",
                step_type=StepType.VALIDATION,
                timeout=timedelta(minutes=30),
                dependencies=["prepare_compliance_scan"],
            ),
            WorkflowStep(
                step_id="scan_vulnerabilities",
                name="Scan Vulnerabilities",
                description="Scan for security vulnerabilities",
                step_type=StepType.VALIDATION,
                timeout=timedelta(minutes=60),
                dependencies=["scan_security_configurations"],
            ),
            WorkflowStep(
                step_id="scan_access_controls",
                name="Scan Access Controls",
                description="Validate access controls and permissions",
                step_type=StepType.VALIDATION,
                timeout=timedelta(minutes=45),
                dependencies=["scan_vulnerabilities"],
            ),
            WorkflowStep(
                step_id="scan_data_protection",
                name="Scan Data Protection",
                description="Check data protection measures",
                step_type=StepType.VALIDATION,
                timeout=timedelta(minutes=30),
                dependencies=["scan_access_controls"],
            ),
            WorkflowStep(
                step_id="analyze_compliance_results",
                name="Analyze Compliance Results",
                description="Analyze all compliance scan results",
                step_type=StepType.VALIDATION,
                timeout=timedelta(minutes=30),
                dependencies=["scan_data_protection"],
            ),
            WorkflowStep(
                step_id="generate_compliance_gaps",
                name="Generate Compliance Gaps",
                description="Identify compliance gaps and violations",
                step_type=StepType.VALIDATION,
                timeout=timedelta(minutes=20),
                dependencies=["analyze_compliance_results"],
            ),
            WorkflowStep(
                step_id="automated_remediation",
                name="Automated Remediation",
                description="Perform automated remediation of issues",
                step_type=StepType.CONFIGURATION,
                timeout=timedelta(minutes=90),
                dependencies=["generate_compliance_gaps"],
                conditions=["remediation_level_automated"],
            ),
            WorkflowStep(
                step_id="validate_remediation",
                name="Validate Remediation",
                description="Validate effectiveness of remediation",
                step_type=StepType.VALIDATION,
                timeout=timedelta(minutes=45),
                dependencies=["automated_remediation"],
            ),
            WorkflowStep(
                step_id="update_security_policies",
                name="Update Security Policies",
                description="Update security policies based on findings",
                step_type=StepType.CONFIGURATION,
                timeout=timedelta(minutes=30),
                dependencies=["validate_remediation"],
            ),
            WorkflowStep(
                step_id="generate_compliance_report",
                name="Generate Compliance Report",
                description="Generate comprehensive compliance report",
                step_type=StepType.CONFIGURATION,
                timeout=timedelta(minutes=30),
                dependencies=["update_security_policies"],
            ),
            WorkflowStep(
                step_id="schedule_follow_up",
                name="Schedule Follow-up",
                description="Schedule follow-up compliance checks",
                step_type=StepType.CONFIGURATION,
                timeout=timedelta(minutes=15),
                dependencies=["generate_compliance_report"],
            ),
        ]

        super().__init__(
            name="Security Compliance",
            description=f"Perform {compliance_standard} compliance validation with {remediation_level} remediation",
            version="1.0.0",
            category=WorkflowCategory.COMPLIANCE,
            parameters=parameters,
            steps=steps,
            estimated_duration=timedelta(hours=5),
            resource_requirements={"cpu_cores": 4, "memory_gb": 8, "storage_gb": 50},
            tags={"compliance", "security", compliance_standard, remediation_level},
            owner="security-team",
            documentation=f"{compliance_standard.upper()} compliance validation and remediation",
        )


class MonitoringSetupWorkflow(WorkflowBlueprint):
    """Setup comprehensive monitoring and alerting for environment."""

    def __init__(
        self, monitoring_tools: List[str] = None, alert_levels: List[str] = None
    ):
        """Initialize monitoring setup workflow."""

        if monitoring_tools is None:
            monitoring_tools = ["prometheus", "grafana", "alertmanager"]

        if alert_levels is None:
            alert_levels = ["critical", "warning", "info"]

        # Define parameters
        parameters = {
            "monitoring_tools": Parameter(
                name="monitoring_tools",
                type="list",
                required=True,
                default=monitoring_tools,
                choices=[
                    "prometheus",
                    "grafana",
                    "alertmanager",
                    "datadog",
                    "newrelic",
                ],
                description="Monitoring tools to deploy",
            ),
            "alert_levels": Parameter(
                name="alert_levels",
                type="list",
                required=True,
                default=alert_levels,
                choices=["critical", "warning", "info", "debug"],
                description="Alert severity levels to configure",
            ),
            "retention_period_days": Parameter(
                name="retention_period_days",
                type="integer",
                required=False,
                default=30,
                validation={"min": 1, "max": 365},
                description="Data retention period in days",
            ),
            "sla_targets": Parameter(
                name="sla_targets",
                type="dict",
                required=False,
                default={"availability": "99.9%", "response_time": "100ms"},
                description="SLA targets to monitor",
            ),
        }

        # Define workflow steps
        steps = [
            WorkflowStep(
                step_id="assess_monitoring_requirements",
                name="Assess Monitoring Requirements",
                description="Assess monitoring requirements and scope",
                step_type=StepType.DISCOVERY,
                timeout=timedelta(minutes=15),
            ),
            WorkflowStep(
                step_id="deploy_monitoring_infrastructure",
                name="Deploy Monitoring Infrastructure",
                description="Deploy monitoring tools and infrastructure",
                step_type=StepType.SERVICE_DEPLOYMENT,
                timeout=timedelta(minutes=60),
                dependencies=["assess_monitoring_requirements"],
            ),
            WorkflowStep(
                step_id="configure_metrics_collection",
                name="Configure Metrics Collection",
                description="Configure metrics collection from all services",
                step_type=StepType.CONFIGURATION,
                timeout=timedelta(minutes=45),
                dependencies=["deploy_monitoring_infrastructure"],
            ),
            WorkflowStep(
                step_id="setup_log_collection",
                name="Setup Log Collection",
                description="Configure centralized log collection",
                step_type=StepType.CONFIGURATION,
                timeout=timedelta(minutes=30),
                dependencies=["configure_metrics_collection"],
            ),
            WorkflowStep(
                step_id="configure_alerting_rules",
                name="Configure Alerting Rules",
                description="Configure alerting rules and thresholds",
                step_type=StepType.CONFIGURATION,
                timeout=timedelta(minutes=45),
                dependencies=["setup_log_collection"],
            ),
            WorkflowStep(
                step_id="setup_dashboards",
                name="Setup Dashboards",
                description="Create monitoring dashboards",
                step_type=StepType.CONFIGURATION,
                timeout=timedelta(minutes=60),
                dependencies=["configure_alerting_rules"],
            ),
            WorkflowStep(
                step_id="configure_sla_monitoring",
                name="Configure SLA Monitoring",
                description="Configure SLA monitoring and reporting",
                step_type=StepType.CONFIGURATION,
                timeout=timedelta(minutes=30),
                dependencies=["setup_dashboards"],
            ),
            WorkflowStep(
                step_id="setup_notification_channels",
                name="Setup Notification Channels",
                description="Configure notification channels for alerts",
                step_type=StepType.CONFIGURATION,
                timeout=timedelta(minutes=30),
                dependencies=["configure_sla_monitoring"],
            ),
            WorkflowStep(
                step_id="test_monitoring_system",
                name="Test Monitoring System",
                description="Test monitoring system functionality",
                step_type=StepType.TESTING,
                timeout=timedelta(minutes=45),
                dependencies=["setup_notification_channels"],
            ),
            WorkflowStep(
                step_id="validate_alerts",
                name="Validate Alerts",
                description="Validate alert delivery and escalation",
                step_type=StepType.TESTING,
                timeout=timedelta(minutes=30),
                dependencies=["test_monitoring_system"],
            ),
            WorkflowStep(
                step_id="setup_monitoring_backups",
                name="Setup Monitoring Backups",
                description="Configure backup of monitoring configuration",
                step_type=StepType.BACKUP,
                timeout=timedelta(minutes=20),
                dependencies=["validate_alerts"],
            ),
            WorkflowStep(
                step_id="document_monitoring_setup",
                name="Document Monitoring Setup",
                description="Create documentation for monitoring setup",
                step_type=StepType.CONFIGURATION,
                timeout=timedelta(minutes=30),
                dependencies=["setup_monitoring_backups"],
            ),
        ]

        super().__init__(
            name="Monitoring Setup",
            description=f"Setup comprehensive monitoring with {', '.join(monitoring_tools)}",
            version="1.0.0",
            category=WorkflowCategory.MONITORING,
            parameters=parameters,
            steps=steps,
            estimated_duration=timedelta(hours=6),
            resource_requirements={"cpu_cores": 2, "memory_gb": 4, "storage_gb": 100},
            tags={"monitoring", "alerting", "observability"}.union(
                set(monitoring_tools)
            ),
            owner="operations-team",
            documentation=f"Comprehensive monitoring setup with {', '.join(monitoring_tools)} and {', '.join(alert_levels)} alerting",
        )


# Workflow factory functions for easy instantiation
def create_production_environment_workflow(
    environment_name: str, service_type: str = "web"
) -> EnvironmentProvisioningWorkflow:
    """Create production environment workflow."""
    return EnvironmentProvisioningWorkflow(
        environment_name=environment_name,
        container_count=5,
        service_type=service_type,
        node_type="high-memory",
    )


def create_staging_environment_workflow(
    environment_name: str, service_type: str = "api"
) -> EnvironmentProvisioningWorkflow:
    """Create staging environment workflow."""
    return EnvironmentProvisioningWorkflow(
        environment_name=environment_name,
        container_count=3,
        service_type=service_type,
        node_type="standard",
    )


def create_daily_backup_workflow() -> BackupOrchestrationWorkflow:
    """Create daily backup workflow."""
    return BackupOrchestrationWorkflow(
        backup_retention_days=30, backup_compression=True
    )


def create_weekly_backup_workflow() -> BackupOrchestrationWorkflow:
    """Create weekly backup workflow."""
    return BackupOrchestrationWorkflow(
        backup_retention_days=90, backup_compression=True
    )


def create_rolling_upgrade_workflow() -> SafeUpgradeWorkflow:
    """Create rolling upgrade workflow."""
    return SafeUpgradeWorkflow(upgrade_type="rolling", maintenance_window="off-hours")


def create_canary_upgrade_workflow() -> SafeUpgradeWorkflow:
    """Create canary upgrade workflow."""
    return SafeUpgradeWorkflow(upgrade_type="canary", maintenance_window="scheduled")


def create_full_disaster_recovery_workflow() -> DisasterRecoveryWorkflow:
    """Create full disaster recovery workflow."""
    return DisasterRecoveryWorkflow(
        recovery_type="full", validation_level="comprehensive"
    )


def create_iso27001_compliance_workflow() -> SecurityComplianceWorkflow:
    """Create ISO 27001 compliance workflow."""
    return SecurityComplianceWorkflow(
        compliance_standard="iso27001", remediation_level="automated"
    )


def create_nist_compliance_workflow() -> SecurityComplianceWorkflow:
    """Create NIST compliance workflow."""
    return SecurityComplianceWorkflow(
        compliance_standard="nist", remediation_level="hybrid"
    )


def create_prometheus_monitoring_workflow() -> MonitoringSetupWorkflow:
    """Create Prometheus monitoring workflow."""
    return MonitoringSetupWorkflow(
        monitoring_tools=["prometheus", "grafana", "alertmanager"],
        alert_levels=["critical", "warning"],
    )


def create_datadog_monitoring_workflow() -> MonitoringSetupWorkflow:
    """Create Datadog monitoring workflow."""
    return MonitoringSetupWorkflow(
        monitoring_tools=["datadog"], alert_levels=["critical", "warning", "info"]
    )
