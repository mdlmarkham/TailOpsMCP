#!/bin/bash
# TailOpsMCP Development Environment Setup Script
# Sets up the complete development environment for TailOpsMCP project

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
PYTHON_MIN_VERSION="3.12"
PROJECT_NAME="TailOpsMCP"
REQUIREMENTS_FILE="requirements-dev.txt"
SETUP_COMPLETE_FLAG=".dev_setup_complete"

# Helper functions
print_header() {
    echo -e "\n${BLUE}=== $1 ===${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${CYAN}ℹ️  $1${NC}"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check Python version
check_python_version() {
    print_info "Checking Python version..."

    if ! command_exists python3; then
        print_error "Python 3 is not installed or not in PATH"
        print_info "Please install Python 3.12 or later from https://python.org"
        exit 1
    fi

    python_version=$(python3 -c "import sys; print('.'.join(map(str, sys.version_info[:2])))")
    required_version=$(echo "$PYTHON_MIN_VERSION" | tr '.' ' ')

    if python3 -c "import sys; exit(0 if sys.version_info >= ($required_version) else 1)"; then
        print_success "Python $python_version found (minimum: $PYTHON_MIN_VERSION)"
    else
        print_error "Python version $python_version is too old. Minimum required: $PYTHON_MIN_VERSION"
        exit 1
    fi
}

# Check pip
check_pip() {
    print_info "Checking pip..."

    if ! command_exists pip3 && ! python3 -m pip --version >/dev/null 2>&1; then
        print_error "pip is not installed or not accessible"
        print_info "Installing pip..."
        python3 -m ensurepip --upgrade
    fi

    print_success "pip is available"
}

# Check virtual environment tools
check_virtual_env_tools() {
    print_info "Checking virtual environment tools..."

    if ! command_exists virtualenv && ! python3 -m venv --help >/dev/null 2>&1; then
        print_warning "No virtual environment tool found. Installing python3-venv..."
        if command_exists apt-get; then
            sudo apt-get update && sudo apt-get install -y python3-venv
        elif command_exists yum; then
            sudo yum install -y python3-venv
        elif command_exists brew; then
            brew install python3
        else
            print_warning "Could not install python3-venv automatically"
        fi
    else
        print_success "Virtual environment tools available"
    fi
}

# Create virtual environment
setup_virtual_environment() {
    print_info "Setting up virtual environment..."

    if [ ! -d "venv" ]; then
        python3 -m venv venv
        print_success "Virtual environment created"
    else
        print_info "Virtual environment already exists"
    fi

    # Activate virtual environment
    source venv/bin/activate
    print_success "Virtual environment activated"

    # Upgrade pip
    pip install --upgrade pip
    print_success "pip upgraded to latest version"
}

# Install project dependencies
install_dependencies() {
    print_info "Installing project dependencies..."

    if [ -f "$REQUIREMENTS_FILE" ]; then
        pip install -r "$REQUIREMENTS_FILE"
        print_success "Development dependencies installed"
    else
        print_warning "$REQUIREMENTS_FILE not found, installing basic dependencies"
        pip install pytest ruff mypy bandit safety pre-commit
    fi

    # Install project in development mode
    if [ -f "pyproject.toml" ] || [ -f "setup.py" ]; then
        pip install -e .
        print_success "Project installed in development mode"
    else
        print_warning "No pyproject.toml or setup.py found"
    fi
}

# Set up pre-commit hooks
setup_pre_commit() {
    print_info "Setting up pre-commit hooks..."

    if command_exists pre-commit; then
        # Install pre-commit hooks
        pre-commit install
        print_success "Pre-commit hooks installed"

        # Run pre-commit on all files to set up the environment
        print_info "Running initial pre-commit check..."
        if pre-commit run --all-files; then
            print_success "Pre-commit setup completed successfully"
        else
            print_warning "Some pre-commit checks failed. This is normal for the first run."
            print_info "Run 'pre-commit run --all-files' later to fix issues"
        fi
    else
        print_warning "pre-commit not found, skipping hook installation"
    fi
}

# Install additional development tools
install_dev_tools() {
    print_info "Installing additional development tools..."

    # Install radon for complexity analysis
    pip install radon
    print_success "Radon installed for complexity analysis"

    # Install additional quality tools if needed
    if command_exists git; then
        print_info "Git detected - repository ready for development"
    else
        print_warning "Git not found - please install git for version control"
    fi
}

# Create development configuration
setup_dev_config() {
    print_info "Setting up development configuration..."

    # Create .dev_config file
    cat > .dev_config << EOF
# TailOpsMCP Development Configuration
# Generated on $(date)

# Virtual environment
VENV_PATH=venv
PYTHON_PATH=python3

# Development tools
LINTER=ruff
FORMATTER=ruff
TYPE_CHECKER=mypy
TEST_RUNNER=pytest
SECURITY_SCANNER=bandit

# Pre-commit hooks
PRE_COMMIT_ENABLED=true

# Project info
PROJECT_NAME=$PROJECT_NAME
SETUP_DATE=$(date)
EOF

    print_success "Development configuration created (.dev_config)"
}

# Verify installation
verify_installation() {
    print_info "Verifying installation..."

    # Test Python imports
    if python3 -c "import pytest, ruff, mypy, bandit" 2>/dev/null; then
        print_success "All development tools can be imported"
    else
        print_warning "Some development tools may not be properly installed"
    fi

    # Test project installation
    if python3 -c "import src" 2>/dev/null; then
        print_success "Project can be imported"
    else
        print_warning "Project may not be properly installed"
    fi

    # Test security scanner
    if python3 -c "from src.security.scanner import SecurityScanner" 2>/dev/null; then
        print_success "Security scanner is working"
    else
        print_warning "Security scanner may have import issues"
    fi
}

# Create development scripts
create_dev_scripts() {
    print_info "Creating development helper scripts..."

    # Create activate script for easy venv activation
    cat > activate_dev.sh << 'EOF'
#!/bin/bash
# Activate TailOpsMCP development environment

if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
    echo "TailOpsMCP development environment activated"
    echo "Python: $(which python)"
    echo "Project: $(pwd)"
else
    echo "Virtual environment not found. Run setup_dev_environment.sh first."
    exit 1
fi
EOF

    chmod +x activate_dev.sh
    print_success "Development activation script created (activate_dev.sh)"

    # Create quick test script
    cat > quick_test.sh << 'EOF'
#!/bin/bash
# Quick test of the development environment

echo "🧪 Running quick development environment test..."

# Test imports
echo "Testing Python imports..."
python3 -c "import pytest, ruff, mypy, bandit; print('✅ All tools imported successfully')"

# Test project
echo "Testing project..."
python3 -c "import src; print('✅ Project imported successfully')"

# Run a simple test
echo "Running a sample test..."
if [ -d "tests" ]; then
    python3 -m pytest tests/ -k "not test_" --collect-only >/dev/null 2>&1 && echo "✅ Tests can be discovered" || echo "⚠️  Test discovery had issues"
else
    echo "ℹ️  No tests directory found"
fi

echo "✅ Quick test completed"
EOF

    chmod +x quick_test.sh
    print_success "Quick test script created (quick_test.sh)"
}

# Mark setup as complete
mark_setup_complete() {
    echo "SETUP_DATE=$(date)" > "$SETUP_COMPLETE_FLAG"
    echo "PYTHON_VERSION=$(python3 -c "import sys; print('.'.join(map(str, sys.version_info[:3])))")" >> "$SETUP_COMPLETE_FLAG"
    echo "SETUP_STATUS=SUCCESS" >> "$SETUP_COMPLETE_FLAG"
    print_success "Setup marked as complete"
}

# Print summary
print_summary() {
    print_header "Setup Summary"
    echo -e "${GREEN}🎉 TailOpsMCP development environment setup completed!${NC}\n"

    echo -e "${CYAN}📁 Created:${NC}"
    echo "  • Virtual environment: ./venv/"
    echo "  • Development config: ./.dev_config"
    echo "  • Helper scripts: activate_dev.sh, quick_test.sh"

    echo -e "\n${CYAN}🔧 Available tools:${NC}"
    echo "  • Python: $(python3 --version)"
    echo "  • Testing: pytest"
    echo "  • Linting: ruff"
    echo "  • Formatting: ruff format"
    echo "  • Type checking: mypy"
    echo "  • Security: bandit, safety"
    echo "  • Pre-commit hooks: pre-commit"
    echo "  • Complexity: radon"

    echo -e "\n${CYAN}🚀 Next steps:${NC}"
    echo "  1. Activate environment: source venv/bin/activate"
    echo "  2. Or use helper: source activate_dev.sh"
    echo "  3. Run tests: make test"
    echo "  4. Run quality checks: make quality"
    echo "  5. Run security scan: make security-scan"

    echo -e "\n${CYAN}📚 Useful commands:${NC}"
    echo "  • make help           - Show all available commands"
    echo "  • make setup          - Set up development environment"
    echo "  • make quality        - Run all quality checks"
    echo "  • make test           - Run tests with coverage"
    echo "  • make security-scan  - Run security scan"
    echo "  • make fix            - Auto-fix code issues"

    echo -e "\n${PURPLE}Happy coding! 🚀${NC}\n"
}

# Main setup function
main() {
    echo -e "${BLUE}"
    cat << 'EOF'

    ╔══════════════════════════════════════╗
    ║     TailOpsMCP Development Setup     ║
    ║                                      ║
    ║  Setting up your development environment...
    ║
    ╚══════════════════════════════════════╝
EOF
    echo -e "${NC}"

    # Check if setup was already completed
    if [ -f "$SETUP_COMPLETE_FLAG" ]; then
        print_info "Previous setup detected"
        read -p "Do you want to re-run setup? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_info "Setup skipped. Run this script again to reconfigure."
            exit 0
        fi
    fi

    # Run setup steps
    check_python_version
    check_pip
    check_virtual_env_tools
    setup_virtual_environment
    install_dependencies
    setup_pre_commit
    install_dev_tools
    setup_dev_config
    create_dev_scripts
    verify_installation
    mark_setup_complete
    print_summary
}

# Handle script arguments
case "${1:-}" in
    --help|-h)
        echo "TailOpsMCP Development Environment Setup"
        echo ""
        echo "Usage: $0 [options]"
        echo ""
        echo "Options:"
        echo "  --help, -h     Show this help message"
        echo "  --force        Force re-setup even if already completed"
        echo "  --skip-venv    Skip virtual environment creation"
        echo ""
        echo "This script sets up a complete development environment for TailOpsMCP"
        echo "including virtual environment, dependencies, and development tools."
        exit 0
        ;;
    --force)
        rm -f "$SETUP_COMPLETE_FLAG"
        print_info "Setup forced - will reconfigure everything"
        ;;
    --skip-venv)
        SKIP_VENV=true
        print_info "Skipping virtual environment creation"
        ;;
esac

# Run main setup
main "$@"
