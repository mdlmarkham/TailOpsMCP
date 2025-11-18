#!/bin/bash
# Proxmox API Helper Library
# Functions for managing LXC containers from the Proxmox host

# Source common functions if not already loaded
if [ -z "$SYSTEMMANAGER_COMMON_LOADED" ]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    # shellcheck source=scripts/install/lib/common.sh
    source "$SCRIPT_DIR/common.sh"
fi

# Check if running on Proxmox host
check_proxmox_host() {
    if ! command -v pct >/dev/null 2>&1; then
        log_error "This script must be run on a Proxmox VE host"
        log_error "The 'pct' command is not available"
        return 1
    fi

    if [ ! -d "/etc/pve" ]; then
        log_error "Proxmox VE configuration directory not found"
        return 1
    fi

    log_success "Running on Proxmox VE host"
    return 0
}

# Check if container exists
container_exists() {
    local ctid="$1"
    pct status "$ctid" >/dev/null 2>&1
    return $?
}

# Get container status
get_container_status() {
    local ctid="$1"
    pct status "$ctid" 2>/dev/null | awk '{print $2}'
}

# Start container if not running
ensure_container_running() {
    local ctid="$1"
    local status

    status=$(get_container_status "$ctid")

    if [ "$status" = "running" ]; then
        log_info "Container $ctid is already running"
        return 0
    fi

    log_info "Starting container $ctid..."
    if pct start "$ctid"; then
        # Wait for container to fully start
        sleep 3
        log_success "Container $ctid started successfully"
        return 0
    else
        log_error "Failed to start container $ctid"
        return 1
    fi
}

# Stop container
stop_container() {
    local ctid="$1"
    local timeout="${2:-30}"

    log_info "Stopping container $ctid..."
    if pct stop "$ctid" --timeout "$timeout"; then
        log_success "Container $ctid stopped successfully"
        return 0
    else
        log_error "Failed to stop container $ctid"
        return 1
    fi
}

# Check if container has required features
check_container_features() {
    local ctid="$1"
    local config_file="/etc/pve/lxc/${ctid}.conf"
    local issues=()

    log_info "Checking container $ctid features..."

    # Check for nesting (required for Docker)
    if ! grep -q "^features:.*nesting=1" "$config_file"; then
        issues+=("nesting=1 not enabled (required for Docker)")
    fi

    # Check for keyctl (recommended for Docker)
    if ! grep -q "^features:.*keyctl=1" "$config_file"; then
        issues+=("keyctl=1 not enabled (recommended for Docker)")
    fi

    # Check for TUN device (required for Tailscale)
    if ! grep -q "^lxc.cgroup2.devices.allow:.*c 10:200 rwm" "$config_file" && \
       ! grep -q "^lxc.cgroup.devices.allow:.*c 10:200 rwm" "$config_file"; then
        issues+=("TUN device not enabled (required for Tailscale)")
    fi

    if [ ${#issues[@]} -gt 0 ]; then
        log_warning "Container $ctid has configuration issues:"
        for issue in "${issues[@]}"; do
            log_warning "  - $issue"
        done
        return 1
    else
        log_success "Container $ctid has all required features"
        return 0
    fi
}

# Fix container features
fix_container_features() {
    local ctid="$1"
    local config_file="/etc/pve/lxc/${ctid}.conf"
    local needs_restart=false

    log_info "Configuring container $ctid features..."

    # Stop container if running
    if [ "$(get_container_status "$ctid")" = "running" ]; then
        stop_container "$ctid" || return 1
        needs_restart=true
    fi

    # Enable nesting and keyctl
    if ! grep -q "^features:" "$config_file"; then
        echo "features: nesting=1,keyctl=1" >> "$config_file"
    else
        # Update existing features line
        sed -i 's/^features:.*/&,nesting=1,keyctl=1/' "$config_file"
        # Remove duplicate features
        sed -i 's/nesting=1,nesting=1/nesting=1/g' "$config_file"
        sed -i 's/keyctl=1,keyctl=1/keyctl=1/g' "$config_file"
    fi

    # Enable TUN device for Tailscale
    if ! grep -q "^lxc.cgroup2.devices.allow:.*c 10:200 rwm" "$config_file"; then
        echo "lxc.cgroup2.devices.allow: c 10:200 rwm" >> "$config_file"
        echo "lxc.mount.entry: /dev/net dev/net none bind,create=dir" >> "$config_file"
    fi

    # Set AppArmor to unconfined (recommended for nested containers)
    if ! grep -q "^lxc.apparmor.profile:" "$config_file"; then
        echo "lxc.apparmor.profile: unconfined" >> "$config_file"
    fi

    log_success "Container $ctid features configured"

    # Restart if it was running
    if [ "$needs_restart" = true ]; then
        ensure_container_running "$ctid" || return 1
    fi

    return 0
}

# Execute command in container
exec_in_container() {
    local ctid="$1"
    shift
    local cmd="$*"

    pct exec "$ctid" -- bash -c "$cmd"
    return $?
}

# Copy file to container
copy_to_container() {
    local ctid="$1"
    local source="$2"
    local dest="$3"

    log_info "Copying $source to container $ctid:$dest"

    # Use pct push
    if pct push "$ctid" "$source" "$dest"; then
        log_success "File copied successfully"
        return 0
    else
        log_error "Failed to copy file"
        return 1
    fi
}

# Get container IP address
get_container_ip() {
    local ctid="$1"
    local ip

    # Try to get IP from container's network interface
    ip=$(pct exec "$ctid" -- ip -4 addr show eth0 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1)

    if [ -n "$ip" ]; then
        echo "$ip"
        return 0
    fi

    # Fallback: try hostname -I inside container
    ip=$(pct exec "$ctid" -- hostname -I 2>/dev/null | awk '{print $1}')

    if [ -n "$ip" ]; then
        echo "$ip"
        return 0
    fi

    return 1
}

# Create new LXC container
create_container() {
    local ctid="$1"
    local template="$2"
    local storage="${3:-local-lvm}"
    local disk_size="${4:-8}"
    local memory="${5:-2048}"
    local cores="${6:-2}"
    local hostname="${7:-tailops-$ctid}"

    log_info "Creating container $ctid from template $template..."

    # Check if template exists
    if ! pveam list "$storage" | grep -q "$template"; then
        log_error "Template $template not found in storage $storage"
        log_info "Available templates:"
        pveam list "$storage"
        return 1
    fi

    # Create container
    if pct create "$ctid" "$storage:vztmpl/$template" \
        --hostname "$hostname" \
        --memory "$memory" \
        --cores "$cores" \
        --rootfs "$storage:$disk_size" \
        --net0 name=eth0,bridge=vmbr0,ip=dhcp \
        --features nesting=1,keyctl=1 \
        --unprivileged 1 \
        --start 1; then

        log_success "Container $ctid created successfully"

        # Wait for container to fully start
        sleep 5

        # Configure TUN device
        local config_file="/etc/pve/lxc/${ctid}.conf"
        echo "lxc.cgroup2.devices.allow: c 10:200 rwm" >> "$config_file"
        echo "lxc.mount.entry: /dev/net dev/net none bind,create=dir" >> "$config_file"
        echo "lxc.apparmor.profile: unconfined" >> "$config_file"

        # Restart to apply changes
        pct stop "$ctid"
        sleep 2
        pct start "$ctid"
        sleep 3

        log_success "Container $ctid fully configured and started"
        return 0
    else
        log_error "Failed to create container $ctid"
        return 1
    fi
}

# List all containers
list_containers() {
    pct list
}

# Get container configuration value
get_container_config() {
    local ctid="$1"
    local key="$2"
    local config_file="/etc/pve/lxc/${ctid}.conf"

    grep "^${key}:" "$config_file" | cut -d':' -f2- | xargs
}

# Set container configuration value
set_container_config() {
    local ctid="$1"
    local key="$2"
    local value="$3"
    local config_file="/etc/pve/lxc/${ctid}.conf"

    if grep -q "^${key}:" "$config_file"; then
        sed -i "s|^${key}:.*|${key}: ${value}|" "$config_file"
    else
        echo "${key}: ${value}" >> "$config_file"
    fi
}

# Get container resource usage
get_container_resources() {
    local ctid="$1"

    echo "=== Container $ctid Resource Usage ==="
    pct status "$ctid"
    echo
    pct config "$ctid" | grep -E "^(memory|cores|rootfs)"
    echo
    if [ "$(get_container_status "$ctid")" = "running" ]; then
        echo "Current usage:"
        pct exec "$ctid" -- free -h 2>/dev/null || true
        pct exec "$ctid" -- df -h / 2>/dev/null || true
    fi
}

# Download template if not exists
download_template() {
    local template="$1"
    local storage="${2:-local}"

    log_info "Checking for template $template in storage $storage..."

    if pveam list "$storage" | grep -q "$template"; then
        log_success "Template $template already exists"
        return 0
    fi

    log_info "Downloading template $template..."
    if pveam download "$storage" "$template"; then
        log_success "Template downloaded successfully"
        return 0
    else
        log_error "Failed to download template"
        return 1
    fi
}

# Validate container meets minimum requirements
validate_container_requirements() {
    local ctid="$1"
    local min_memory="${2:-1024}"
    local min_disk="${3:-5}"
    local issues=()

    log_info "Validating container $ctid requirements..."

    # Check memory
    local memory
    memory=$(get_container_config "$ctid" "memory")
    if [ -n "$memory" ] && [ "$memory" -lt "$min_memory" ]; then
        issues+=("Memory ($memory MB) is less than minimum ($min_memory MB)")
    fi

    # Check disk space
    local rootfs
    rootfs=$(get_container_config "$ctid" "rootfs")
    if [ -n "$rootfs" ]; then
        local disk_size
        disk_size=$(echo "$rootfs" | grep -oP 'size=\K\d+' || echo "0")
        if [ "$disk_size" -gt 0 ] && [ "$disk_size" -lt "$min_disk" ]; then
            issues+=("Disk space ($disk_size GB) is less than minimum ($min_disk GB)")
        fi
    fi

    if [ ${#issues[@]} -gt 0 ]; then
        log_warning "Container $ctid resource issues:"
        for issue in "${issues[@]}"; do
            log_warning "  - $issue"
        done
        return 1
    else
        log_success "Container $ctid meets minimum requirements"
        return 0
    fi
}

export -f check_proxmox_host
export -f container_exists
export -f get_container_status
export -f ensure_container_running
export -f stop_container
export -f check_container_features
export -f fix_container_features
export -f exec_in_container
export -f copy_to_container
export -f get_container_ip
export -f create_container
export -f list_containers
export -f get_container_config
export -f set_container_config
export -f get_container_resources
export -f download_template
export -f validate_container_requirements
