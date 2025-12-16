# TailOpsMCP Development Automation Scripts

This directory contains comprehensive automation scripts for the TailOpsMCP project development workflow. These scripts provide automated setup, quality checks, security scanning, and code fixing capabilities.

## 🚀 Quick Start

1. **Set up development environment:**
   ```bash
   bash scripts/setup_dev_environment.sh
   ```

2. **Run all quality checks:**
   ```bash
   python scripts/run_quality_checks.py --all
   ```

3. **Auto-fix code issues:**
   ```bash
   python scripts/fix_code_quality.py --all
   ```

4. **Run security scan:**
   ```bash
   python scripts/scan.py --quick
   ```

## 📁 Available Scripts

### 1. `setup_dev_environment.sh` - Development Environment Setup

**Purpose:** Sets up a complete development environment with all necessary tools and dependencies.

**Usage:**
```bash
bash scripts/setup_dev_environment.sh [options]
```

**Options:**
- `--help, -h` - Show help message
- `--force` - Force re-setup even if already completed
- `--skip-venv` - Skip virtual environment creation

**What it does:**
- ✅ Checks Python version (requires 3.12+)
- ✅ Creates and activates virtual environment
- ✅ Installs all development dependencies
- ✅ Sets up pre-commit hooks
- ✅ Installs additional development tools (radon, etc.)
- ✅ Creates development configuration files
- ✅ Creates helper scripts for development

**Output:**
- Virtual environment in `./venv/`
- Development config in `.dev_config`
- Helper scripts: `activate_dev.sh`, `quick_test.sh`

**Example:**
```bash
# Full setup
bash scripts/setup_dev_environment.sh

# Force re-setup
bash scripts/setup_dev_environment.sh --force
```

---

### 2. `scan.py` - Security Scanning Tool

**Purpose:** Comprehensive security scanning using the existing TailOpsMCP security scanner.

**Usage:**
```bash
python scripts/scan.py [OPTIONS] [TARGET_PATH]
```

**Options:**

**Scan Types:**
- `--quick` - Quick scan (vulnerabilities + secrets)
- `--full` - Full comprehensive scan
- `--secrets` - Scan for exposed secrets and credentials
- `--vulnerabilities` - Scan for known vulnerabilities
- `--compliance` - Scan for compliance violations
- `--interactive` - Run in interactive mode

**Output Options:**
- `--output, -o` - Output file for detailed report
- `--format` - Output format (json, yaml)
- `--verbose, -v` - Verbose output
- `--quiet, -q` - Quiet mode (minimal output)

**Examples:**
```bash
# Quick security scan
python scripts/scan.py --quick

# Full scan with report
python scripts/scan.py --full --output security-report.json

# Scan for secrets only
python scripts/scan.py --secrets --output secrets-report.json

# Interactive mode
python scripts/scan.py --interactive

# Verbose vulnerability scan
python scripts/scan.py --vulnerabilities --verbose
```

**Features:**
- 🔍 Uses existing TailOpsMCP security scanner
- 📊 Generates detailed JSON/YAML reports
- 🚨 Identifies critical security issues
- 🔐 Scans for exposed secrets and credentials
- 📈 Calculates risk scores
- 💡 Provides security recommendations

---

### 3. `run_quality_checks.py` - Quality Assurance Runner

**Purpose:** Orchestrates all quality assurance tools and generates comprehensive reports.

**Usage:**
```bash
python scripts/run_quality_checks.py [OPTIONS]
```

**Options:**

**Quality Checks:**
- `--all` - Run all quality checks (default)
- `--lint` - Run linting checks (ruff)
- `--format` - Run formatting checks
- `--typecheck` - Run type checking (mypy)
- `--security` - Run security checks (bandit, safety)
- `--complexity` - Run complexity analysis (radon)
- `--tests` - Run tests (pytest)

**Output Options:**
- `--verbose, -v` - Verbose output
- `--report-dir` - Directory to save reports
- `--output, -o` - Output file for comprehensive report
- `--no-summary` - Skip printing summary

**Examples:**
```bash
# Run all quality checks
python scripts/run_quality_checks.py --all

# Run only linting and formatting
python scripts/run_quality_checks.py --lint --format

# Run with verbose output and custom report directory
python scripts/run_quality_checks.py --all --verbose --report-dir reports/

# Run tests only with coverage report
python scripts/run_quality_checks.py --tests --output test-report.json
```

**Features:**
- 🔧 Runs ruff, mypy, bandit, safety, radon, pytest
- 📊 Generates comprehensive reports
- 📈 Calculates overall quality score
- 📁 Creates detailed coverage reports
- ⏱️ Tracks execution time
- 🎯 Provides actionable recommendations

---

### 4. `fix_code_quality.py` - Auto-Fix Code Issues

**Purpose:** Automatically fixes common code quality issues using various tools.

**Usage:**
```bash
python scripts/fix_code_quality.py [OPTIONS]
```

**Options:**

**Fix Types:**
- `--all` - Fix all auto-fixable issues (default)
- `--imports` - Fix import sorting and organization
- `--format` - Fix code formatting
- `--lint` - Fix linting issues
- `--type-annotations` - Fix missing type annotations
- `--docstrings` - Fix missing docstrings
- `--security` - Fix security-related issues
- `--performance` - Fix performance-related issues
- `--complexity` - Fix complexity-related issues

**Options:**
- `--dry-run` - Preview changes without applying them
- `--verbose, -v` - Verbose output
- `--no-backup` - Skip creating backup before making changes
- `--no-verify` - Skip verification after applying fixes

**Examples:**
```bash
# Auto-fix all issues
python scripts/fix_code_quality.py --all

# Fix only imports and formatting
python scripts/fix_code_quality.py --imports --format

# Preview changes without applying
python scripts/fix_code_quality.py --all --dry-run

# Fix security and performance issues only
python scripts/fix_code_quality.py --security --performance
```

**Features:**
- 🔧 Uses ruff, isort, and other tools for auto-fixing
- 💾 Creates automatic backups before changes
- ✅ Verifies fixes after application
- 🔍 Provides detailed change summaries
- ⚠️ Safe dry-run mode for preview
- 📝 Suggests next steps after fixing

---

## 🛠️ Makefile Integration

These scripts are integrated with the main Makefile for easy access:

```bash
# Development environment setup
make setup

# Quality checks
make quality          # Run all quality checks
make lint             # Run ruff lint
make format           # Run ruff format
make typecheck        # Run mypy
make security         # Run bandit and safety
make complexity       # Run radon analysis

# Security scanning
make security-scan    # Run comprehensive security scan
make security-quick   # Run quick security scan

# Testing
make test             # Run tests with coverage
make test-verbose     # Run tests with verbose output
make test-fast        # Run fast tests without coverage

# Development workflows
make dev              # Quick dev workflow (fix + test)
make ci               # CI pipeline (quality + test)
make pre-push         # Pre-push checks

# Auto-fixing
make fix              # Auto-fix code issues

# Utility commands
make clean            # Clean up generated files
make help             # Show all available commands
```

## 📊 Integration with Existing Security Scanner

All scripts utilize the existing comprehensive security scanner from `src.security.scanner`:

- **quick_security_scan** - Fast security assessment
- **scan_for_secrets** - Detects exposed credentials
- **scan_vulnerabilities** - Identifies known vulnerabilities
- **SecurityScanner class** - Full-featured security scanning engine

The security scanning capabilities include:
- 🔍 Vulnerability detection and assessment
- 🔐 Secrets and credential scanning
- 📋 Security policy compliance checking
- 📊 Integration with security monitoring systems
- 📈 Automated security reporting

## 🔧 Development Workflow Integration

### Daily Development Workflow:
1. **Start of day:**
   ```bash
   make setup
   source activate_dev.sh
   ```

2. **During development:**
   ```bash
   # Auto-fix issues as you code
   make fix
   
   # Quick quality check
   make test-fast
   
   # Security scan for changes
   make security-quick
   ```

3. **Before committing:**
   ```bash
   make pre-push  # Run all quality checks + security + tests
   ```

4. **CI/CD Integration:**
   ```bash
   make ci  # Run comprehensive quality pipeline
   ```

### Advanced Usage:
- **Custom security scans:** Use `scripts/scan.py` with specific options
- **Detailed quality reports:** Use `scripts/run_quality_checks.py --output report.json`
- **Selective fixing:** Use `scripts/fix_code_quality.py --imports --format`
- **Interactive scanning:** Use `scripts/scan.py --interactive`

## 📝 Requirements

All scripts require the development dependencies to be installed:

```bash
pip install -r requirements-dev.txt
```

Or run the setup script:
```bash
bash scripts/setup_dev_environment.sh
```

## 🚨 Exit Codes

All scripts return appropriate exit codes for CI/CD integration:

- `0` - Success, no issues found
- `1` - Warnings or minor issues found
- `2` - Critical issues found (security scans)

## 🔍 Troubleshooting

### Common Issues:

1. **Python not found:**
   - Ensure Python 3.12+ is installed
   - Check PATH environment variable

2. **Permission denied (Linux/Mac):**
   ```bash
   chmod +x scripts/*.py
   chmod +x scripts/*.sh
   ```

3. **Dependencies not found:**
   ```bash
   pip install -r requirements-dev.txt
   ```

4. **Virtual environment issues:**
   ```bash
   bash scripts/setup_dev_environment.sh --force
   ```

5. **Security scanner import errors:**
   - Ensure project is installed: `pip install -e .`
   - Check PYTHONPATH includes src directory

### Getting Help:

- Run any script with `--help` for detailed usage
- Use `--verbose` flag for detailed output
- Check generated reports for specific issues
- Review the Makefile help: `make help`

## 📈 Quality Metrics

The quality check runner provides comprehensive metrics:

- **Overall Quality Score** (0-100)
- **Code Coverage** percentage
- **Security Risk Score**
- **Complexity Analysis**
- **Performance Metrics**
- **Compliance Status**

## 🔄 Continuous Integration

For CI/CD pipelines, recommended commands:

```bash
# Full CI pipeline
make ci

# Security-focused pipeline
make security-scan
make quality

# Quick validation
make lint
make test-fast
```

## 📚 Additional Resources

- [TailOpsMCP Security Framework Documentation](../SECURITY_REVIEW_REPORT.md)
- [Quality Standards Guide](../docs/quality-standards.md)
- [Development Workflow Guide](../docs/development-workflow.md)
- [Pre-commit Hooks Configuration](../.pre-commit-config.yaml)

---

**Happy coding! 🚀**

*These scripts are designed to make TailOpsMCP development efficient, secure, and maintainable. They integrate seamlessly with the project's existing security framework and provide comprehensive automation for all development tasks.*