#!/usr/bin/env bash

# Shell Script Linter and Security Validator
# Usage: bash scripts/lint-shell-scripts.sh [file1] [file2] ...
# Lints and validates shell scripts for quality and security issues

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
EXIT_CODE=0

# Files to check (default)
FILES=("$@")
if [[ ${#FILES[@]} -eq 0 ]]; then
    # Default to all shell scripts in ct/ and scripts/
    mapfile -t FILES < <(find "$PROJECT_ROOT/ct" "$PROJECT_ROOT/scripts" -name "*.sh" -type f 2>/dev/null || true)
fi

# Security checks
check_shebang() {
    local file="$1"
    local first_line

    if [[ ! -f "$file" ]]; then
        log_error "File not found: $file"
        return 1
    fi

    first_line=$(head -n1 "$file")

    # Check for proper shebang
    if [[ "$first_line" != "#!/usr/bin/env bash" ]] && [[ "$first_line" != "#!/bin/bash" ]]; then
        log_error "$file: Missing or invalid shebang. Expected '#!/usr/bin/env bash' or '#!/bin/bash'"
        EXIT_CODE=1
    fi
}

check_error_handling() {
    local file="$1"

    # Check for set -euo pipefail
    if ! grep -q "set -euo pipefail" "$file"; then
        log_warning "$file: Missing 'set -euo pipefail' for error handling"
    fi

    # Check for proper error handling patterns
    if grep -q "command_not_found_handle\|return.*\?\|true\|:" "$file"; then
        log_warning "$file: Potential error handling issues detected"
    fi
}

check_input_validation() {
    local file="$1"

    # Check for potential injection vulnerabilities
    if grep -q '\$(' "$file"; then
        log_warning "$file: Command substitution found - ensure proper quoting"
    fi

    # Check for unsafe variable usage
    if grep -q 'eval\s' "$file"; then
        log_error "$file: 'eval' usage detected - potential security risk"
        EXIT_CODE=1
    fi

    # Check for proper quoting
    if grep -E '\$[A-Z_][A-Z0-9_]*\s+=' "$file" | grep -v '"' | grep -v "'" >/dev/null; then
        log_warning "$file: Unquoted variable assignments detected"
    fi
}

check_network_security() {
    local file="$1"

    # Check for curl without security options
    if grep -E "curl.*http://" "$file" | grep -v -- "--insecure\|--silent\|--fail\|--show-error" >/dev/null; then
        log_warning "$file: curl usage without security options (use --fail --silent --show-error)"
    fi

    # Check for wget without security options
    if grep -E "wget.*http://" "$file" | grep -v -- "--no-check-certificate\|--quiet" >/dev/null; then
        log_warning "$file: wget usage without security options (use --quiet)"
    fi

    # Check for potential SSRF vulnerabilities
    if grep -E "\$(curl\|curl\s+\$[A-Z_]" "$file" >/dev/null; then
        log_warning "$file: curl usage with variables - ensure input validation"
    fi
}

check_file_operations() {
    local file="$1"

    # Check for dangerous file operations
    if grep -q "rm -rf\|rm -f" "$file"; then
        log_warning "$file: Dangerous rm operations detected - ensure proper safety checks"
    fi

    # Check for proper temp file handling
    if grep -q "\/tmp\/" "$file" && ! grep -q "trap.*EXIT" "$file"; then
        log_warning "$file: Temp file usage without cleanup trap"
    fi

    # Check for proper file permissions
    if grep -q "chmod" "$file"; then
        log_info "$file: chmod operations found"
    fi
}

check_system_commands() {
    local file="$1"

    # Check for system command usage
    local dangerous_commands=("pct\|qm\|pveam\|pvesh\|pvesm\|pve-firewall")
    for cmd in "${dangerous_commands[@]}"; do
        if grep -q "$cmd" "$file"; then
            log_info "$file: Proxmox commands found: $cmd"
        fi
    done
}

check_git_operations() {
    local file="$1"

    # Check for git clone operations
    if grep -q "git clone" "$file"; then
        log_info "$file: Git clone operations found"

        # Check for pinned versions
        if grep -q "git clone.*@.*:" "$file"; then
            log_success "$file: Pinned git reference found"
        else
            log_warning "$file: Git clone without pinned version"
        fi
    fi
}

check_container_security() {
    local file="$1"

    # Check for container operations
    if grep -q "pct\|lxc" "$file"; then
        log_info "$file: Container operations found"

        # Check for security features
        if grep -q "unprivileged.*1" "$file"; then
            log_success "$file: Unprivileged container configuration found"
        fi

        # Check for device access
        if grep -q "cgroup2.devices.allow" "$file"; then
            log_success "$file: Device access controls found"
        fi
    fi
}

check_logging() {
    local file="$1"

    # Check for proper logging
    if ! grep -q "log_\(info\|success\|warning\|error\)" "$file" && [[ $(wc -l < "$file") -gt 20 ]]; then
        log_warning "$file: Missing structured logging functions"
    fi

    # Check for proper logging patterns
    if grep -q "echo.*INFO\|echo.*ERROR\|echo.*WARNING" "$file"; then
        log_warning "$file: Basic echo logging detected - consider using structured logging"
    fi
}

check_dependencies() {
    local file="$1"

    # Check for external dependencies
    local external_commands=("curl\|wget\|git\|apt-get\|yum\|dnf")
    for cmd in "${external_commands[@]}"; do
        if grep -q "$cmd" "$file"; then
            log_info "$file: External dependency found: $cmd"
        fi
    done

    # Check for version pinning
    if grep -q "@.*:" "$file"; then
        log_success "$file: Version pinning found"
    fi
}

run_syntax_check() {
    local file="$1"

    # Basic syntax check using bash -n
    if bash -n "$file" 2>/dev/null; then
        log_success "$file: Syntax check passed"
    else
        log_error "$file: Syntax check failed"
        bash -n "$file" 2>&1 | head -5
        EXIT_CODE=1
    fi
}

run_shellcheck() {
    local file="$1"

    # Try to run shellcheck if available
    if command -v shellcheck &>/dev/null; then
        if shellcheck "$file" 2>/dev/null; then
            log_success "$file: shellcheck passed"
        else
            log_warning "$file: shellcheck found issues"
            shellcheck "$file" 2>&1 | head -10
        fi
    else
        log_info "$file: shellcheck not available (optional)"
    fi
}

generate_report() {
    echo
    echo "═══════════════════════════════════════════════════════════════"
    echo "              Shell Script Quality Report"
    echo "═══════════════════════════════════════════════════════════════"
    echo
    echo "Files analyzed: ${#FILES[@]}"
    echo "Report generated at: $(date)"

    if [[ $EXIT_CODE -eq 0 ]]; then
        echo "Status: All checks passed ✅"
    else
        echo "Status: Issues found ❌"
    fi
    echo "═══════════════════════════════════════════════════════════════"
}

# Main execution
main() {
    echo "Shell Script Linter and Security Validator"
    echo "=========================================="
    echo

    if [[ ${#FILES[@]} -eq 0 ]]; then
        log_error "No shell scripts found to analyze"
        exit 1
    fi

    log_info "Analyzing ${#FILES[@]} file(s)..."
    echo

    for file in "${FILES[@]}"; do
        echo "─────────────────────────────────────────────────────────────"
        echo "Analyzing: $file"
        echo "─────────────────────────────────────────────────────────────"

        # Run all checks
        check_shebang "$file"
        run_syntax_check "$file"
        check_error_handling "$file"
        check_input_validation "$file"
        check_network_security "$file"
        check_file_operations "$file"
        check_system_commands "$file"
        check_git_operations "$file"
        check_container_security "$file"
        check_logging "$file"
        check_dependencies "$file"
        run_shellcheck "$file"

        echo
    done

    generate_report

    if [[ $EXIT_CODE -eq 0 ]]; then
        log_success "All script validation checks passed!"
    else
        log_error "Script validation found issues that need attention"
    fi

    exit $EXIT_CODE
}

# Show usage if called with --help
if [[ "${1:-}" == "--help" ]]; then
    cat << EOF
Shell Script Linter and Security Validator

Usage: bash scripts/lint-shell-scripts.sh [file1] [file2] ...]

Arguments:
  file1, file2, ...    Specific files to lint (optional)
                      If no files specified, analyzes all .sh files
                      in ct/ and scripts/ directories

Checks performed:
- Shebang validation
- Syntax checking (bash -n)
- Error handling (set -euo pipefail)
- Input validation and injection prevention
- Network security (curl/wget options)
- File operation safety
- System command usage
- Git operation security
- Container security features
- Logging implementation
- Dependency management
- shellcheck (if available)

Security checks:
- Command injection prevention
- Safe variable usage
- Network security options
- Temporary file handling
- Dangerous operation warnings

Exit codes:
  0 - All checks passed
  1 - Issues found

Examples:
  # Lint all shell scripts
  bash scripts/lint-shell-scripts.sh

  # Lint specific files
  bash scripts/lint-shell-scripts.sh ct/tailops-gateway.sh ct/install.sh

  # Lint with verbose output
  bash scripts/lint-shell-scripts.sh ct/*.sh
EOF
    exit 0
fi

# Check for immediate failure conditions
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
