#!/usr/bin/env bash
# TailOpsMCP EC2/Cloud Installer
# Optimized for cloud environments (AWS, GCP, Azure, etc.)
# Copyright (c) 2024 TailOpsMCP Contributors
# License: MIT

set -euo pipefail

#######################################
# Cloud-Specific Optimizations
#######################################

function apply_cloud_optimizations() {
    msg_info "Applying cloud environment optimizations"

    case "$CLOUD_PROVIDER" in
        aws)
            apply_aws_optimizations
            ;;
        gcp)
            apply_gcp_optimizations
            ;;
        azure)
            apply_azure_optimizations
            ;;
        digitalocean)
            apply_digitalocean_optimizations
            ;;
        *)
            msg_info "No specific optimizations for: $CLOUD_PROVIDER"
            ;;
    esac

    msg_ok "Cloud optimizations applied"
}

function apply_aws_optimizations() {
    msg_info "Applying AWS EC2 optimizations"

    # Install AWS CLI if not present (optional)
    if ! command -v aws &>/dev/null; then
        msg_info "AWS CLI not found (optional)"
    fi

    # Configure CloudWatch logs (optional, requires IAM permissions)
    if [ "$NON_INTERACTIVE" != "true" ]; then
        if confirm_action "Configure CloudWatch logs?" "N"; then
            setup_cloudwatch_logs
        fi
    fi

    # Optimize for EC2 metadata service
    if [ -f /etc/systemd/system/systemmanager-mcp.service ]; then
        # Ensure service waits for network
        if ! grep -q "After=cloud-final.service" /etc/systemd/system/systemmanager-mcp.service; then
            sed -i 's/After=network-online.target/After=network-online.target cloud-final.service/' \
                /etc/systemd/system/systemmanager-mcp.service || true
        fi
    fi

    msg_ok "AWS optimizations applied"
}

function apply_gcp_optimizations() {
    msg_info "Applying GCP optimizations"

    # Install gcloud SDK if not present (optional)
    if ! command -v gcloud &>/dev/null; then
        msg_info "gcloud SDK not found (optional)"
    fi

    msg_ok "GCP optimizations applied"
}

function apply_azure_optimizations() {
    msg_info "Applying Azure optimizations"

    # Install Azure CLI if not present (optional)
    if ! command -v az &>/dev/null; then
        msg_info "Azure CLI not found (optional)"
    fi

    msg_ok "Azure optimizations applied"
}

function apply_digitalocean_optimizations() {
    msg_info "Applying DigitalOcean optimizations"

    # Install doctl if not present (optional)
    if ! command -v doctl &>/dev/null; then
        msg_info "doctl not found (optional)"
    fi

    msg_ok "DigitalOcean optimizations applied"
}

function setup_cloudwatch_logs() {
    msg_info "Setting up CloudWatch logs..."
    msg_warn "This feature requires IAM permissions"
    msg_info "Skipping CloudWatch setup (implement if needed)"
}

#######################################
# Cloud Security Configuration
#######################################

function configure_cloud_security() {
    msg_info "Configuring cloud security settings"

    # Ensure firewall allows port
    case "$OS_ID" in
        ubuntu|debian)
            if command -v ufw &>/dev/null; then
                if ufw status | grep -q "Status: active"; then
                    msg_info "UFW is active"
                    if [ "$NON_INTERACTIVE" != "true" ]; then
                        if confirm_action "Allow port $SYSTEMMANAGER_PORT through UFW?" "y"; then
                            ufw allow "$SYSTEMMANAGER_PORT/tcp"
                            msg_ok "Port $SYSTEMMANAGER_PORT allowed through UFW"
                        fi
                    fi
                fi
            fi
            ;;
        rhel|centos|rocky|almalinux|fedora)
            if command -v firewall-cmd &>/dev/null; then
                if firewall-cmd --state 2>/dev/null | grep -q "running"; then
                    msg_info "firewalld is active"
                    if [ "$NON_INTERACTIVE" != "true" ]; then
                        if confirm_action "Allow port $SYSTEMMANAGER_PORT through firewalld?" "y"; then
                            firewall-cmd --permanent --add-port="$SYSTEMMANAGER_PORT/tcp"
                            firewall-cmd --reload
                            msg_ok "Port $SYSTEMMANAGER_PORT allowed through firewalld"
                        fi
                    fi
                fi
            fi
            ;;
    esac

    msg_ok "Cloud security configured"
}

function display_cloud_security_notes() {
    print_separator
    echo -e "${YELLOW}⚠️  Cloud Security Checklist:${NC}"
    echo ""

    case "$CLOUD_PROVIDER" in
        aws)
            echo "  AWS EC2 Security:"
            echo "  • Update Security Group to allow port $SYSTEMMANAGER_PORT"
            echo "  • Or use Tailscale for secure access (recommended)"
            echo "  • Consider using AWS Systems Manager Session Manager"
            echo ""
            echo "  Security Group rule:"
            echo "    Type: Custom TCP"
            echo "    Port: $SYSTEMMANAGER_PORT"
            echo "    Source: Your IP or 0.0.0.0/0 (if using Tailscale)"
            ;;
        gcp)
            echo "  GCP Compute Engine Security:"
            echo "  • Update firewall rules to allow port $SYSTEMMANAGER_PORT"
            echo "  • Or use Tailscale for secure access (recommended)"
            echo ""
            echo "  Firewall rule:"
            echo "    gcloud compute firewall-rules create allow-systemmanager \\"
            echo "      --allow=tcp:$SYSTEMMANAGER_PORT \\"
            echo "      --source-ranges=0.0.0.0/0"
            ;;
        azure)
            echo "  Azure VM Security:"
            echo "  • Update Network Security Group to allow port $SYSTEMMANAGER_PORT"
            echo "  • Or use Tailscale for secure access (recommended)"
            echo ""
            echo "  NSG rule:"
            echo "    Priority: 1000"
            echo "    Port: $SYSTEMMANAGER_PORT"
            echo "    Protocol: TCP"
            echo "    Source: Any (if using Tailscale)"
            ;;
        digitalocean)
            echo "  DigitalOcean Droplet Security:"
            echo "  • Update Firewall to allow port $SYSTEMMANAGER_PORT"
            echo "  • Or use Tailscale for secure access (recommended)"
            ;;
        *)
            echo "  Generic Cloud Security:"
            echo "  • Ensure firewall allows port $SYSTEMMANAGER_PORT"
            echo "  • Use Tailscale for secure access (strongly recommended)"
            echo "  • Never expose without authentication!"
            ;;
    esac

    echo ""
    echo -e "${GREEN}  Recommended: Use Tailscale${NC}"
    echo "    Tailscale provides encrypted, authenticated access"
    echo "    without exposing ports to the internet."
    echo "    Install: curl -fsSL https://tailscale.com/install.sh | sh"
    echo ""
    print_separator
}

#######################################
# Cloud Instance Metadata
#######################################

function detect_cloud_metadata() {
    msg_info "Detecting cloud instance metadata"

    case "$CLOUD_PROVIDER" in
        aws)
            get_aws_metadata
            ;;
        gcp)
            get_gcp_metadata
            ;;
        azure)
            get_azure_metadata
            ;;
    esac
}

function get_aws_metadata() {
    # Try to get instance ID
    INSTANCE_ID=$(curl -sf -m 2 http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null || echo "unknown")
    INSTANCE_TYPE=$(curl -sf -m 2 http://169.254.169.254/latest/meta-data/instance-type 2>/dev/null || echo "unknown")
    REGION=$(curl -sf -m 2 http://169.254.169.254/latest/meta-data/placement/region 2>/dev/null || echo "unknown")

    if [ "$INSTANCE_ID" != "unknown" ]; then
        msg_info "AWS Instance ID: $INSTANCE_ID"
        msg_info "Instance Type: $INSTANCE_TYPE"
        msg_info "Region: $REGION"

        export INSTANCE_ID INSTANCE_TYPE REGION
    fi
}

function get_gcp_metadata() {
    INSTANCE_ID=$(curl -sf -H "Metadata-Flavor: Google" -m 2 \
        http://metadata.google.internal/computeMetadata/v1/instance/id 2>/dev/null || echo "unknown")
    INSTANCE_NAME=$(curl -sf -H "Metadata-Flavor: Google" -m 2 \
        http://metadata.google.internal/computeMetadata/v1/instance/name 2>/dev/null || echo "unknown")

    if [ "$INSTANCE_ID" != "unknown" ]; then
        msg_info "GCP Instance: $INSTANCE_NAME ($INSTANCE_ID)"
        export INSTANCE_ID INSTANCE_NAME
    fi
}

function get_azure_metadata() {
    local metadata=$(curl -sf -H "Metadata:true" -m 2 \
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01" 2>/dev/null)

    if [ -n "$metadata" ]; then
        msg_info "Azure VM metadata retrieved"
    fi
}

#######################################
# Main Cloud Installation
#######################################

# Detect script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source the standalone installer
if [ -f "$SCRIPT_DIR/install-standalone.sh" ]; then
    # Just source functions, don't run main
    source "$SCRIPT_DIR/install-standalone.sh" --help >/dev/null 2>&1 || true

    # Load libraries manually
    load_libraries

    # Run cloud-specific installation
    print_banner
    init_state
    setup_error_handling

    # Load config if provided
    load_config_file

    # Platform detection
    run_platform_detection

    # Cloud metadata detection
    detect_cloud_metadata

    # Run pre-flight checks
    run_preflight_checks || exit 1

    # Check for upgrade mode
    if [ "$UPGRADE_MODE" = "true" ]; then
        perform_upgrade
        display_installation_summary "$SYSTEMMANAGER_PORT"
        display_cloud_security_notes
        cleanup_state
        exit 0
    fi

    # Fresh installation
    print_separator
    msg_info "Starting TailOpsMCP installation (Cloud Environment: $CLOUD_PROVIDER)"
    print_separator

    # Install dependencies
    install_dependencies

    # Setup installation
    setup_installation_directory
    setup_python_environment
    setup_service_user

    # Configure authentication
    configure_authentication || exit 1

    # Setup and start service
    setup_systemd_service
    start_systemmanager_service

    # Apply cloud optimizations
    apply_cloud_optimizations
    configure_cloud_security

    # Validate installation
    print_separator
    if run_post_install_validation; then
        # Display success summary
        display_installation_summary "$SYSTEMMANAGER_PORT"
        display_cloud_security_notes

        cleanup_state
        exit 0
    else
        msg_error "Installation validation failed"
        msg_info "Check logs: journalctl -u systemmanager-mcp -n 100"
        exit 1
    fi
else
    echo "ERROR: install-standalone.sh not found in $SCRIPT_DIR"
    exit 1
fi
