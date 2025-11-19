#!/bin/bash
set -euo pipefail

# TailOpsMCP Multi-Container Installation Script
# Deploy TailOpsMCP from a Proxmox host to multiple LXC containers
#
# Usage:
#   ./install-proxmox-multi.sh [--config /path/to/config.conf] [--containers 101,102,103]
#
# Examples:
#   # Use configuration file
#   ./install-proxmox-multi.sh --config /root/my-deployment.conf
#
#   # Quick deploy to specific containers (interactive)
#   ./install-proxmox-multi.sh --containers 101,102,103
#
#   # Create new containers and deploy
#   ./install-proxmox-multi.sh --create --containers 201,202,203

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Source library functions
# shellcheck source=scripts/install/lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
# shellcheck source=scripts/install/lib/proxmox-api.sh
source "$SCRIPT_DIR/lib/proxmox-api.sh"
# shellcheck source=scripts/install/lib/platform-detect.sh
source "$SCRIPT_DIR/lib/platform-detect.sh"

# Default configuration
CONFIG_FILE=""
CONTAINERS=""
CONTAINER_NAMES=""
CREATE_CONTAINERS=false
CONTAINER_TEMPLATE="debian-12-standard"
CONTAINER_STORAGE="local-lvm"
CONTAINER_DISK_SIZE="8G"
CONTAINER_MEMORY=2048
CONTAINER_CORES=2
CONTAINER_NETWORK_BRIDGE="vmbr0"
CONTAINER_IP_MODE="dhcp"
HOSTNAME_PREFIX="tailops"

INSTALL_MODE="standalone"
SYSTEMMANAGER_INSTALL_DIR="/opt/systemmanager"
SYSTEMMANAGER_REPO="${SYSTEMMANAGER_REPO:-https://github.com/mdlmarkham/TailOpsMCP.git}"
SYSTEMMANAGER_REPO_BRANCH="${SYSTEMMANAGER_REPO_BRANCH:-main}"
SKIP_DOCKER=false

AUTH_MODE="oidc"
SYSTEMMANAGER_SHARED_SECRET=""
TSIDP_URL=""
TSIDP_CLIENT_ID=""
TSIDP_CLIENT_SECRET=""

DEPLOYMENT_STRATEGY="sequential"
MAX_PARALLEL=3
AUTO_FIX_FEATURES=true
CONTINUE_ON_FAILURE=true
RUN_VALIDATION=true
FORCE_REINSTALL=false
BACKUP_BEFORE_INSTALL=true

LOG_LEVEL="info"
LOG_DIR="/var/log/systemmanager-install"
CONTAINER_START_TIMEOUT=30
INSTALL_TIMEOUT=600
NON_INTERACTIVE=false

# Deployment tracking
declare -A DEPLOYMENT_STATUS
declare -A DEPLOYMENT_IPS
declare -A DEPLOYMENT_ERRORS

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            --containers)
                CONTAINERS="$2"
                shift 2
                ;;
            --create)
                CREATE_CONTAINERS=true
                shift
                ;;
            --auth)
                AUTH_MODE="$2"
                shift 2
                ;;
            --parallel)
                DEPLOYMENT_STRATEGY="parallel"
                shift
                ;;
            --sequential)
                DEPLOYMENT_STRATEGY="sequential"
                shift
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

show_help() {
    cat << EOF
TailOpsMCP Multi-Container Installation Script

Deploy TailOpsMCP from a Proxmox host to multiple LXC containers.

Usage:
    $0 [OPTIONS]

Options:
    --config FILE           Path to configuration file
    --containers IDs        Comma-separated container IDs (e.g., 101,102,103)
    --create                Create new containers (requires --containers)
    --auth MODE             Authentication mode: oidc, token, none
    --parallel              Deploy to all containers in parallel
    --sequential            Deploy to containers one at a time (default)
    -h, --help              Show this help message

Examples:
    # Deploy to existing containers using config file
    $0 --config /root/deployment.conf

    # Quick deploy to specific containers
    $0 --containers 101,102,103 --auth token

    # Create 3 new containers and deploy
    $0 --create --containers 201,202,203

    # Parallel deployment for speed
    $0 --config deployment.conf --parallel

Configuration:
    Create a config file from the template:
    cp $SCRIPT_DIR/templates/proxmox-multi.conf /root/my-deployment.conf

    Edit the file and run:
    $0 --config /root/my-deployment.conf

Documentation:
    See docs/installation/proxmox-multi-container.md for detailed documentation
EOF
}

# Load configuration file
load_config() {
    if [ -n "$CONFIG_FILE" ]; then
        if [ ! -f "$CONFIG_FILE" ]; then
            log_error "Configuration file not found: $CONFIG_FILE"
            exit 1
        fi

        log_info "Loading configuration from $CONFIG_FILE"
        # shellcheck source=/dev/null
        source "$CONFIG_FILE"
        log_success "Configuration loaded"
    fi
}

# Validate configuration
validate_config() {
    log_section "Validating Configuration"

    if [ -z "$CONTAINERS" ] && [ -z "$CONTAINER_NAMES" ]; then
        log_error "No containers specified. Use --containers or set CONTAINERS in config file"
        return 1
    fi

    if [ "$CREATE_CONTAINERS" = true ] && [ -z "$CONTAINER_TEMPLATE" ]; then
        log_error "CREATE_CONTAINERS is true but no template specified"
        return 1
    fi

    if [ "$AUTH_MODE" = "oidc" ]; then
        if [ -z "$TSIDP_URL" ] || [ -z "$TSIDP_CLIENT_ID" ] || [ -z "$TSIDP_CLIENT_SECRET" ]; then
            if [ "$NON_INTERACTIVE" = true ]; then
                log_error "OIDC mode requires TSIDP_URL, TSIDP_CLIENT_ID, and TSIDP_CLIENT_SECRET"
                return 1
            fi
            log_warning "OIDC credentials not fully configured"
        fi
    fi

    log_success "Configuration validated"
    return 0
}

# Convert container names to IDs
resolve_container_ids() {
    local resolved_ids=()

    if [ -n "$CONTAINER_NAMES" ]; then
        log_info "Resolving container names to IDs..."

        IFS=',' read -ra NAMES <<< "$CONTAINER_NAMES"
        for name in "${NAMES[@]}"; do
            name=$(echo "$name" | xargs)  # Trim whitespace
            local ctid
            ctid=$(pct list | awk -v name="$name" '$3 == name {print $1}')

            if [ -n "$ctid" ]; then
                resolved_ids+=("$ctid")
                log_info "  $name -> $ctid"
            else
                log_error "Container not found: $name"
                return 1
            fi
        done

        # Merge with CONTAINERS if specified
        if [ -n "$CONTAINERS" ]; then
            CONTAINERS="$CONTAINERS,${resolved_ids[*]}"
        else
            CONTAINERS=$(IFS=,; echo "${resolved_ids[*]}")
        fi
    fi

    # Remove duplicates and sort
    CONTAINERS=$(echo "$CONTAINERS" | tr ',' '\n' | sort -u | tr '\n' ',' | sed 's/,$//')

    log_info "Target containers: $CONTAINERS"
    return 0
}

# Prepare single container
prepare_container() {
    local ctid="$1"

    log_section "Preparing Container $ctid"

    # Check if container exists
    if ! container_exists "$ctid"; then
        if [ "$CREATE_CONTAINERS" = true ]; then
            log_info "Container $ctid does not exist, creating..."

            # Download template if needed
            download_template "$CONTAINER_TEMPLATE" "$CONTAINER_STORAGE" || return 1

            # Create container
            create_container "$ctid" "$CONTAINER_TEMPLATE" "$CONTAINER_STORAGE" \
                "$CONTAINER_DISK_SIZE" "$CONTAINER_MEMORY" "$CONTAINER_CORES" \
                "${HOSTNAME_PREFIX}-${ctid}" || return 1
        else
            log_error "Container $ctid does not exist and CREATE_CONTAINERS=false"
            return 1
        fi
    fi

    # Ensure container is running
    ensure_container_running "$ctid" || return 1

    # Check and fix features if needed
    if ! check_container_features "$ctid"; then
        if [ "$AUTO_FIX_FEATURES" = true ]; then
            log_info "Auto-fixing container features..."
            fix_container_features "$ctid" || return 1
        else
            log_error "Container $ctid is missing required features. Set AUTO_FIX_FEATURES=true to fix automatically"
            return 1
        fi
    fi

    # Validate requirements
    validate_container_requirements "$ctid" 1024 5 || {
        log_warning "Container $ctid does not meet recommended requirements"
        if [ "$CONTINUE_ON_FAILURE" != true ]; then
            return 1
        fi
    }

    log_success "Container $ctid is ready for installation"
    return 0
}

# Get per-container configuration value
get_container_override() {
    local ctid="$1"
    local key="$2"
    local default="$3"
    local varname="CONTAINER_CONFIG_${ctid}_${key}"

    # Use indirect expansion to get the value
    local value="${!varname:-}"

    if [ -n "$value" ]; then
        echo "$value"
    else
        echo "$default"
    fi
}

# Install TailOpsMCP on a single container
install_on_container() {
    local ctid="$1"

    log_section "Installing TailOpsMCP on Container $ctid"

    # Get container-specific configuration
    local port=$(get_container_override "$ctid" "PORT" "8080")
    local auth_mode=$(get_container_override "$ctid" "AUTH_MODE" "$AUTH_MODE")
    local shared_secret=$(get_container_override "$ctid" "SHARED_SECRET" "$SYSTEMMANAGER_SHARED_SECRET")

    # Create temporary directory for installation files
    local temp_dir="/tmp/tailops-install-$ctid"
    mkdir -p "$temp_dir"

    # Create container-specific config file
    local container_config="$temp_dir/install.conf"
    cat > "$container_config" << EOF
# Auto-generated configuration for container $ctid
SYSTEMMANAGER_INSTALL_DIR="$SYSTEMMANAGER_INSTALL_DIR"
SYSTEMMANAGER_PORT=$port
SYSTEMMANAGER_AUTH_MODE=$auth_mode
SYSTEMMANAGER_REPO="$SYSTEMMANAGER_REPO"
SYSTEMMANAGER_REPO_BRANCH="$SYSTEMMANAGER_REPO_BRANCH"
NON_INTERACTIVE=true
SKIP_DOCKER=$SKIP_DOCKER
FORCE_REINSTALL=$FORCE_REINSTALL
EOF

    # Add auth-specific configuration
    if [ "$auth_mode" = "token" ]; then
        if [ -z "$shared_secret" ]; then
            shared_secret=$(openssl rand -base64 32)
            log_info "Generated shared secret for container $ctid"
        fi
        echo "SYSTEMMANAGER_SHARED_SECRET=\"$shared_secret\"" >> "$container_config"
    elif [ "$auth_mode" = "oidc" ]; then
        cat >> "$container_config" << EOF
TSIDP_URL="$TSIDP_URL"
TSIDP_CLIENT_ID="$TSIDP_CLIENT_ID"
TSIDP_CLIENT_SECRET="$TSIDP_CLIENT_SECRET"
EOF
    fi

    # Copy installation files to container
    log_info "Copying installation files to container..."

    # Copy the entire project directory
    exec_in_container "$ctid" "rm -rf /tmp/tailops-install" || true
    exec_in_container "$ctid" "mkdir -p /tmp/tailops-install"

    # Create tarball and copy
    local tarball="$temp_dir/tailops.tar.gz"
    (cd "$PROJECT_ROOT" && tar czf "$tarball" \
        --exclude='.git' \
        --exclude='*.pyc' \
        --exclude='__pycache__' \
        --exclude='venv' \
        --exclude='.env' \
        .)

    copy_to_container "$ctid" "$tarball" "/tmp/tailops.tar.gz" || return 1
    exec_in_container "$ctid" "cd /tmp/tailops-install && tar xzf /tmp/tailops.tar.gz" || return 1

    # Copy configuration
    copy_to_container "$ctid" "$container_config" "/tmp/tailops-install/install.conf" || return 1

    # Run installation
    log_info "Running installation inside container..."
    local install_cmd="cd /tmp/tailops-install && bash scripts/install/install-standalone.sh --config /tmp/tailops-install/install.conf"

    if exec_in_container "$ctid" "$install_cmd"; then
        log_success "Installation completed successfully on container $ctid"

        # Get container IP
        local ip
        ip=$(get_container_ip "$ctid")
        DEPLOYMENT_IPS[$ctid]="$ip"

        # Store auth info for summary
        if [ "$auth_mode" = "token" ]; then
            DEPLOYMENT_ERRORS[$ctid]="Token: $shared_secret"
        fi

        DEPLOYMENT_STATUS[$ctid]="success"

        # Clean up
        exec_in_container "$ctid" "rm -rf /tmp/tailops-install /tmp/tailops.tar.gz"
        rm -rf "$temp_dir"

        return 0
    else
        log_error "Installation failed on container $ctid"
        DEPLOYMENT_STATUS[$ctid]="failed"
        DEPLOYMENT_ERRORS[$ctid]="Installation script failed"

        # Keep files for debugging
        log_info "Installation files kept in container:/tmp/tailops-install for debugging"

        return 1
    fi
}

# Validate installation on container
validate_installation() {
    local ctid="$1"

    log_info "Validating installation on container $ctid..."

    # Check if service is running
    if ! exec_in_container "$ctid" "systemctl is-active systemmanager-mcp" >/dev/null 2>&1; then
        log_error "Service is not running on container $ctid"
        return 1
    fi

    # Check if port is listening
    local port=$(get_container_override "$ctid" "PORT" "8080")
    if ! exec_in_container "$ctid" "ss -tlnp | grep -q :$port" >/dev/null 2>&1; then
        log_error "Service is not listening on port $port on container $ctid"
        return 1
    fi

    log_success "Installation validated on container $ctid"
    return 0
}

# Deploy to single container (wrapper for parallel execution)
deploy_container() {
    local ctid="$1"

    {
        if prepare_container "$ctid" && \
           install_on_container "$ctid" && \
           ( [ "$RUN_VALIDATION" != true ] || validate_installation "$ctid" ); then
            return 0
        else
            return 1
        fi
    } 2>&1 | sed "s/^/[CT$ctid] /"
}

# Deploy to all containers
deploy_all() {
    log_section "Starting Multi-Container Deployment"

    IFS=',' read -ra CTIDS <<< "$CONTAINERS"
    local total=${#CTIDS[@]}
    local current=0
    local failed=0

    log_info "Deploying to $total containers..."
    log_info "Strategy: $DEPLOYMENT_STRATEGY"

    if [ "$DEPLOYMENT_STRATEGY" = "parallel" ]; then
        log_info "Running parallel deployment (max $MAX_PARALLEL at a time)..."

        # Deploy in batches
        local batch_size=$MAX_PARALLEL
        local pids=()

        for ctid in "${CTIDS[@]}"; do
            ctid=$(echo "$ctid" | xargs)  # Trim whitespace

            deploy_container "$ctid" &
            pids+=($!)

            # Wait if we've hit the batch size
            if [ ${#pids[@]} -ge $batch_size ]; then
                for pid in "${pids[@]}"; do
                    if wait "$pid"; then
                        ((current++))
                    else
                        ((failed++))
                    fi
                done
                pids=()
            fi
        done

        # Wait for remaining processes
        for pid in "${pids[@]}"; do
            if wait "$pid"; then
                ((current++))
            else
                ((failed++))
            fi
        done

    else
        # Sequential deployment
        for ctid in "${CTIDS[@]}"; do
            ctid=$(echo "$ctid" | xargs)  # Trim whitespace
            ((current++))

            log_info "[$current/$total] Processing container $ctid..."

            if deploy_container "$ctid"; then
                log_success "Container $ctid deployed successfully"
            else
                log_error "Container $ctid deployment failed"
                ((failed++))

                if [ "$CONTINUE_ON_FAILURE" != true ]; then
                    log_error "Stopping deployment due to failure (CONTINUE_ON_FAILURE=false)"
                    break
                fi
            fi

            echo ""
        done
    fi

    log_section "Deployment Complete"
    log_info "Total: $total | Success: $((total - failed)) | Failed: $failed"

    if [ $failed -gt 0 ]; then
        return 1
    fi

    return 0
}

# Show deployment summary
show_summary() {
    log_section "Deployment Summary"

    echo ""
    echo "╔════════════════════════════════════════════════════════════════════╗"
    echo "║          TailOpsMCP Multi-Container Deployment Summary             ║"
    echo "╚════════════════════════════════════════════════════════════════════╝"
    echo ""

    printf "%-12s %-10s %-20s %s\n" "Container" "Status" "IP Address" "Notes"
    printf "%-12s %-10s %-20s %s\n" "----------" "--------" "------------" "-----"

    IFS=',' read -ra CTIDS <<< "$CONTAINERS"
    for ctid in "${CTIDS[@]}"; do
        ctid=$(echo "$ctid" | xargs)
        local status="${DEPLOYMENT_STATUS[$ctid]:-unknown}"
        local ip="${DEPLOYMENT_IPS[$ctid]:-N/A}"
        local notes="${DEPLOYMENT_ERRORS[$ctid]:-}"

        if [ "$status" = "success" ]; then
            printf "%-12s \e[32m%-10s\e[0m %-20s %s\n" "$ctid" "✓ Success" "$ip" "$notes"
        else
            printf "%-12s \e[31m%-10s\e[0m %-20s %s\n" "$ctid" "✗ Failed" "$ip" "$notes"
        fi
    done

    echo ""

    # Show next steps
    echo "Next Steps:"
    echo ""
    echo "1. Access your TailOpsMCP instances:"
    for ctid in "${CTIDS[@]}"; do
        ctid=$(echo "$ctid" | xargs)
        if [ "${DEPLOYMENT_STATUS[$ctid]:-}" = "success" ]; then
            local ip="${DEPLOYMENT_IPS[$ctid]:-}"
            local port=$(get_container_override "$ctid" "PORT" "8080")
            if [ -n "$ip" ]; then
                echo "   Container $ctid: http://$ip:$port"
            fi
        fi
    done
    echo ""

    echo "2. Check service status:"
    echo "   pct exec <CTID> -- systemctl status systemmanager-mcp"
    echo ""

    echo "3. View logs:"
    echo "   pct exec <CTID> -- journalctl -u systemmanager-mcp -f"
    echo ""

    echo "4. Configure Claude Desktop to use your instances"
    echo "   See: docs/getting-started.md"
    echo ""

    if [ "$AUTH_MODE" = "token" ]; then
        echo "5. Save your authentication tokens (shown in Notes column above)"
        echo ""
    fi

    echo "═══════════════════════════════════════════════════════════════════════"
}

# Main execution
main() {
    echo "╔════════════════════════════════════════════════════════════════════╗"
    echo "║     TailOpsMCP Multi-Container Installation for Proxmox LXC        ║"
    echo "╚════════════════════════════════════════════════════════════════════╝"
    echo ""

    # Parse arguments
    parse_args "$@"

    # Check we're on Proxmox host
    check_proxmox_host || exit 1

    # Load configuration
    load_config

    # Validate configuration
    validate_config || exit 1

    # Resolve container IDs from names if needed
    resolve_container_ids || exit 1

    # Show configuration summary
    log_section "Configuration Summary"
    log_info "Target containers: $CONTAINERS"
    log_info "Create new containers: $CREATE_CONTAINERS"
    log_info "Authentication mode: $AUTH_MODE"
    log_info "Deployment strategy: $DEPLOYMENT_STRATEGY"
    log_info "Auto-fix features: $AUTO_FIX_FEATURES"
    log_info "Continue on failure: $CONTINUE_ON_FAILURE"
    echo ""

    # Confirm if interactive
    if [ "$NON_INTERACTIVE" != true ]; then
        read -p "Continue with deployment? (y/N) " -n 1 -r
        echo ""
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "Deployment cancelled"
            exit 0
        fi
    fi

    # Execute deployment
    if deploy_all; then
        show_summary
        log_success "Multi-container deployment completed successfully!"
        exit 0
    else
        show_summary
        log_error "Multi-container deployment completed with errors"
        exit 1
    fi
}

# Run main function
main "$@"
