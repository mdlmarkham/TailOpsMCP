# Quality Tools Reference

This is the comprehensive technical reference for all code quality tools, configurations, and automation in TailOpsMCP.

---

## 📋 Table of Contents

1. [Configuration Files](#configuration-files)
2. [Makefile Reference](#makefile-reference)
3. [Command-Line Tools](#command-line-tools)
4. [Automation Scripts](#automation-scripts)
5. [CI/CD Workflows](#cicd-workflows)
6. [Customization Options](#customization-options)
7. [Integration Guide](#integration-guide)

---

## Configuration Files

### **[pyproject.toml](pyproject.toml)** - Main Project Configuration

The central configuration file for all Python tools and project metadata.

#### **Project Metadata**
```toml
[project]
name = "systemmanager-mcp-server"
version = "1.0.0"
description = "MCP Server for remote system management..."
requires-python = ">=3.12"
```

#### **Development Dependencies**
```toml
[project.optional-dependencies]
dev = [
    # Testing
    "pytest>=7.4.0",
    "pytest-asyncio>=0.21.0",

    # Code formatting and linting
    "black>=23.0.0",
    "isort>=5.12.0",
    "ruff>=0.6.0",
    "flake8>=6.0.0",

    # Type checking
    "mypy>=1.7.0",
    "types-psutil>=5.9.0",

    # Security scanning
    "bandit[toml]>=1.7.10",
    "safety>=3.0.0",

    # Pre-commit hooks
    "pre-commit>=3.5.0",
]
```

#### **Black Configuration**
```toml
[tool.black]
line-length = 88                    # Line length limit
target-version = ['py311']         # Target Python version
include = '\.pyi?$'                # File patterns to format
exclude = '''
/(
    \.git
  | \.mypy_cache
  | \.pytest_cache
  | \.ruff_cache
  | build
  | dist
)/
'''
```

#### **MyPy Configuration**
```toml
[tool.mypy]
python_version = "3.11"            # Python version for type checking
warn_return_any = true             # Warn about returning Any
warn_unused_configs = true         # Warn about unused config
disallow_untyped_defs = true       # Disallow functions without type hints
disallow_incomplete_defs = true    # Disallow incomplete function definitions
check_untyped_defs = true          # Check type hints for functions without annotations
disallow_untyped_decorators = true # Disallow decorators without type hints
no_implicit_optional = true        # Disallow implicit Optional types
warn_redundant_casts = true        # Warn about redundant type casts
warn_unused_ignores = true         # Warn about unused ignore comments
warn_no_return = true              # Warn about functions that don't return
warn_unreachable = true            # Warn about unreachable code
strict_equality = true             # Enable strict equality checking
show_error_codes = true            # Show error codes in messages
show_column_numbers = true         # Show column numbers in errors
```

#### **Ruff Configuration** (via pyproject.toml)
```toml
[tool.ruff]
target-version = "py311"           # Target Python version
line-length = 88                   # Line length limit
select = [                         # Enabled linting rules
    "E",    # pycodestyle errors
    "W",    # pycodestyle warnings
    "F",    # pyflakes
    "I",    # isort
    "B",    # flake8-bugbear
    "C4",   # flake8-comprehensions
    "UP",   # pyupgrade
    "N",    # pep8-naming
    "D",    # pydocstyle
    "ANN",  # flake8-annotations
    "S",    # flake8-bandit
    "SIM",  # flake8-simplify
    "TCH",  # flake8-type-checking
    "PTH",  # flake8-use-pathlib
    "ERA",  # eradicate
    "RUF",  # ruff-specific rules
]
ignore = [                         # Ignored linting rules
    "ANN101",  # missing-type-self
    "ANN102",  # missing-type-cls
    "D100",    # missing-docstring-in-public-module
    "D104",    # missing-docstring-in-public-package
    "D107",    # missing-docstring-in-__init__
    "S101",    # use-of-assert (for test files)
]

[tool.ruff.per-file-ignores]
"tests/**/*.py" = [                # Test file specific ignores
    "S101",    # allow assert in tests
    "ANN",     # allow missing type hints in tests
    "D",       # allow missing docstrings in tests
]

[tool.ruff.mccabe]                 # Complexity settings
max-complexity = 10                # Maximum cyclomatic complexity

[tool.ruff.isort]
known-first-party = ["src"]       # Known first-party packages
required-imports = ["from __future__ import annotations"]
force-sort-within-sections = true # Force sorting within sections
combine-as-imports = true         # Combine as imports

[tool.ruff.pydocstyle]
convention = "google"             # Docstring convention
```

### **[.pre-commit-config.yaml](.pre-commit-config.yaml)** - Git Hook Configuration

Pre-commit hooks that run before each commit to ensure code quality.

#### **Ruff Hooks**
```yaml
# Ruff - Fast Python linter and formatter
- repo: https://github.com/astral-sh/ruff-pre-commit
  rev: v0.6.4                      # Hook version
  hooks:
    - id: ruff                     # Linting hook
      args: [--fix]               # Auto-fix issues
    - id: ruff-format             # Code formatting hook
```

#### **Type Checking Hook**
```yaml
# MyPy - Static type checking
- repo: https://github.com/pre-commit/mirrors-mypy
  rev: v1.11.2
  hooks:
    - id: mypy
      additional_dependencies: [types-psutil]  # Type stubs
      args: [--ignore-missing-imports]         # Ignore missing imports
```

#### **Security Hooks**
```yaml
# Bandit - Security linting
- repo: https://github.com/PyCQA/bandit
  rev: 1.7.10
  hooks:
    - id: bandit
      args: ["-c", "pyproject.toml"]  # Use pyproject.toml config
      additional_dependencies: ["bandit[toml]"]

# Safety - Dependency vulnerability checking
- repo: https://github.com/Lucas-C/pre-commit-hooks-safety
  rev: v1.3.2
  hooks:
    - id: python-safety-dependencies-check
```

#### **File System Hooks**
```yaml
# Basic file checks
- repo: https://github.com/pre-commit/pre-commit-hooks
  rev: v5.0.0
  hooks:
    - id: trailing-whitespace      # Remove trailing whitespace
    - id: end-of-file-fixer       # Ensure files end with newline
    - id: check-yaml              # Validate YAML files
    - id: check-added-large-files
      args: ['--maxkb=1000']      # Prevent large file commits
    - id: check-merge-conflict    # Check for merge conflict markers
    - id: check-json              # Validate JSON files
    - id: check-toml              # Validate TOML files
    - id: debug-statements        # Check for debug statements
    - id: check-docstring-first   # Ensure docstrings are first
    - id: requirements-txt-fixer  # Sort requirements.txt

# Shell script linting
- repo: https://github.com/shellcheck-py/shellcheck-py
  rev: v0.9.0.6
  hooks:
    - id: shellcheck             # Shell script linting
```

#### **Pre-commit Configuration**
```yaml
# Configure default language version
default_language_version:
  python: python3.12              # Default Python version

# Configure default stages
default_stages: [commit, push]    # When to run hooks
```

### **[pytest.ini](pytest.ini)** - Testing Configuration

Test framework configuration and settings.

```ini
[tool:pytest]
minversion = 6.0                   # Minimum pytest version
testpaths = tests                  # Test directory
python_files = test_*.py *_test.py # Test file patterns
python_classes = Test*            # Test class patterns
python_functions = test_*         # Test function patterns
addopts =                          # Default command-line options
    -ra                            # Show all test outcomes
    --strict-markers              # Strict marker checking
    --strict-config               # Strict configuration
    --disable-warnings            # Disable warnings
    --tb=short                    # Traceback format
    --durations=10                # Show 10 slowest tests
markers =                          # Custom test markers
    slow: marks tests as slow
    integration: marks tests as integration tests
    unit: marks tests as unit tests
    security: marks tests as security tests
filterwarnings =                   # Warning filters
    ignore::UserWarning
    ignore::DeprecationWarning
```

---

## Makefile Reference

The Makefile provides convenient commands for all development tasks. Run `make help` to see available commands.

### **Setup & Installation Commands**

#### **`make setup`**
Complete development environment setup.
```bash
make setup
```
**What it does:**
- Checks Python version
- Creates virtual environment (`venv/`)
- Installs development dependencies
- Installs project in development mode
- Sets up pre-commit hooks
- Verifies installation

#### **`make install-deps`**
Install all dependencies (including dev dependencies).
```bash
make install-deps
```

#### **`make pre-commit`**
Set up pre-commit hooks.
```bash
make pre-commit
```

### **Quality Check Commands**

#### **`make lint`**
Run ruff linting on source and test code.
```bash
make lint
ruff check src tests
```

#### **`make format`**
Format code with ruff and isort.
```bash
make format
ruff format src tests
isort src tests
```

#### **`make typecheck`**
Run mypy type checking.
```bash
make typecheck
mypy src --ignore-missing-imports --show-error-codes
```

#### **`make security`**
Run security scans (bandit and safety).
```bash
make security
bandit -r src -f json -o security-report.json
safety check --json --output safety-report.json
```

#### **`make complexity`**
Run complexity analysis using radon.
```bash
make complexity
radon cc src --json > complexity-report.json
radon mi src > maintainability-report.txt
```

#### **`make quality`**
Run all quality checks.
```bash
make quality
# Runs: lint → typecheck → security → complexity
```

### **Testing Commands**

#### **`make test`**
Run pytest with coverage.
```bash
make test
pytest tests/ -v --cov=src --cov-report=html --cov-report=term-missing
```

#### **`make test-verbose`**
Run tests with verbose output.
```bash
make test-verbose
pytest tests/ -v --tb=short --durations=10
```

#### **`make test-fast`**
Run tests without coverage (faster).
```bash
make test-fast
pytest tests/ -x -q
```

### **Fix Commands**

#### **`make fix`**
Auto-fix code issues with ruff and isort.
```bash
make fix
ruff check --fix src tests
ruff format src tests
isort --profile black src tests
```

### **Security Commands**

#### **`make security-scan`**
Run comprehensive security scan using custom scanner.
```bash
make security-scan
python scripts/scan.py --full
```

#### **`make security-quick`**
Run quick security scan.
```bash
make security-quick
python scripts/scan.py --quick
```

### **Development Workflow Commands**

#### **`make dev`**
Quick development workflow: fix code and run tests.
```bash
make dev
# Runs: fix → test
```

#### **`make ci`**
CI pipeline: run all quality checks and tests.
```bash
make ci
# Runs: quality → test
```

#### **`make pre-push`**
Run before pushing to repository.
```bash
make pre-push
# Runs: quality → security → test
```

### **Utility Commands**

#### **`make clean`**
Clean up generated files and caches.
```bash
make clean
# Removes: *.pyc, __pycache__, *.egg-info, build/, dist/, .coverage, htmlcov/, .pytest_cache/, .mypy_cache/, .ruff_cache/, *.log, report files
```

#### **`make docs`**
Generate documentation (placeholder for future docs tool).
```bash
make docs
```

#### **`make version`**
Show project version.
```bash
make version
python -c "import src; print('TailOpsMCP version:', getattr(src, '__version__', '1.0.0'))"
```

#### **`make info`**
Show project information.
```bash
make info
# Shows: Python version, Project root, Source directory, Test directory, Development dependencies count
```

#### **`make help`**
Show help message with categorized commands.
```bash
make help
# Displays all available commands organized by category
```

---

## Command-Line Tools

### **Ruff** - Python Linter and Formatter

Ruff is our primary linting and formatting tool, replacing multiple tools with a single fast implementation.

#### **Basic Usage**
```bash
# Check for linting issues
ruff check src tests

# Auto-fix linting issues
ruff check --fix src tests

# Format code
ruff format src tests

# Check formatting without changing files
ruff format --check src tests
```

#### **Advanced Usage**
```bash
# Check specific files
ruff check src/inventory.py src/mcp_server.py

# Check with output format
ruff check src tests --output-format=json --output-file=ruff-report.json

# Check specific rule sets
ruff check src tests --select=E,W,F --ignore=E501

# Show rule explanations
ruff check src tests --show-source --show-fixes

# Check only changed files (useful for large codebases)
ruff check --diff HEAD~1

# Disable specific rules inline
import os  # noqa: S102
```

#### **Rule Categories**
- **E, W**: pycodestyle errors and warnings
- **F**: pyflakes rules
- **I**: isort compatibility
- **B**: flake8-bugbear
- **C4**: flake8-comprehensions
- **UP**: pyupgrade
- **N**: pep8-naming
- **D**: pydocstyle (docstring conventions)
- **ANN**: flake8-annotations (type annotations)
- **S**: flake8-bandit (security)
- **SIM**: flake8-simplify (code simplification)
- **TCH**: flake8-type-checking
- **PTH**: flake8-use-pathlib
- **ERA**: eradicate (dead code)
- **RUF**: ruff-specific rules

### **MyPy** - Static Type Checker

MyPy performs static type checking to catch type-related errors.

#### **Basic Usage**
```bash
# Type check source code
mypy src

# Type check with missing imports ignored
mypy src --ignore-missing-imports

# Show error codes
mypy src --show-error-codes

# Pretty output
mypy src --pretty
```

#### **Advanced Usage**
```bash
# Type check specific file
mypy src/inventory.py --show-error-codes

# Type check with strict settings
mypy src --strict

# Type check with custom config
mypy src --config-file=custom-mypy.ini

# Incremental checking
mypy src --incremental

# Save cache to specific directory
mypy src --cache-dir=/tmp/mypy-cache

# Show column numbers
mypy src --show-column-numbers

# Disable specific error codes
mypy src --disable-error-code=attr-defined

# Follow imports
mypy src --follow-imports=normal

# Check untyped definitions
mypy src --check-untyped-defs

# Disallow dynamic typing
mypy src --disallow-dynamic-typing
```

#### **Common Options**
- `--ignore-missing-imports`: Don't error on missing imports
- `--show-error-codes`: Show error codes in output
- `--show-column-numbers`: Show column numbers in errors
- `--pretty`: Pretty-print error messages
- `--incremental`: Use incremental type checking
- `--strict`: Enable all error checking flags

### **Bandit** - Security Linter

Bandit scans Python code for common security issues.

#### **Basic Usage**
```bash
# Scan source code
bandit -r src

# Scan with JSON output
bandit -r src -f json

# Scan with specific severity
bandit -r src -ll  # Only high severity

# Scan with specific confidence
bandit -r src -i   # Only high confidence
```

#### **Advanced Usage**
```bash
# Scan and save report
bandit -r src -f json -o security-report.json

# Scan with custom config
bandit -r src -c pyproject.toml

# Scan excluding directories
bandit -r src -x tests,scripts

# Scan with specific tests
bandit -r src -t B105,B106,B107  # Hardcoded password tests

# Scan with baseline file
bandit -r src -b baseline.json

# Scan with message template
bandit -r src -f custom -o bandit-output.txt
```

#### **Security Test IDs**
- **B101**: Use of `assert` statements
- **B102**: Use of `exec()` built-in
- **B103**: Setting insecure file permissions
- **B104**: Hardcoded bind on all interfaces
- **B105**: Hardcoded password string
- **B106**: Hardcoded password as function argument
- **B107**: Hardcoded password as default argument
- **B108**: Hardcoded `/tmp` directory
- **B110**: Use of `try_except_pass`
- **B112**: Use of `try_except_continue`

### **Safety** - Dependency Security Scanner

Safety checks Python dependencies for known security vulnerabilities.

#### **Basic Usage**
```bash
# Check dependencies
safety check

# Check with JSON output
safety check --json

# Check specific package
safety check requests==2.25.1
```

#### **Advanced Usage**
```bash
# Check and save report
safety check --json --output safety-report.json

# Check with full report
safety check --full-report

# Check only production dependencies
safety check --prod

# Check with short output
safety check --short-report

# Check with specific vulnerability database
safety check --db=https://pyup.io/api/v1/safety/db/

# Check with proxy
safety check --proxy-host=proxy.company.com --proxy-port=8080

# Check with authentication
safety check --api-key=your-api-key
```

### **Pytest** - Testing Framework

Pytest is our testing framework with comprehensive features.

#### **Basic Usage**
```bash
# Run all tests
pytest tests/

# Run with verbose output
pytest tests/ -v

# Run specific test file
pytest tests/test_inventory.py

# Run specific test function
pytest tests/test_inventory.py::test_target_discovery
```

#### **Advanced Usage**
```bash
# Run with coverage
pytest tests/ --cov=src --cov-report=html --cov-report=term-missing

# Run with coverage and fail on low coverage
pytest tests/ --cov=src --cov-fail-under=80

# Run with markers
pytest tests/ -m "not slow"

# Run with markers (multiple)
pytest tests/ -m "unit or integration"

# Run without markers
pytest tests/ -m "not slow and not integration"

# Run with output capture disabled
pytest tests/ -s

# Run with traceback on failure
pytest tests/ --tb=long

# Run with first failure
pytest tests/ -x

# Run with specific test order
pytest tests/ --lf  # Last failed first

# Run parallel tests
pytest tests/ -n auto

# Run with timeout
pytest tests/ --timeout=300

# Run with junit XML output
pytest tests/ --junitxml=test-results.xml

# Run with specific markers
pytest tests/ -m "security and not slow"

# Run with fixtures
pytest tests/ --setup-show

# Run with coverage for specific module
pytest tests/ --cov=src.inventory

# Run with custom test paths
pytest tests/unit/ tests/integration/

# Run with specific Python path
pytest tests/ --import-mode=importlib

# Run with coverage for specific modules
pytest tests/ --cov=src --cov=src.auth --cov=src.models
```

#### **Pytest Fixtures**
```python
import pytest
from src.inventory import TargetRegistry

@pytest.fixture
def target_registry():
    """Create a target registry for testing."""
    return TargetRegistry()

@pytest.fixture
def sample_target_config():
    """Sample target configuration for testing."""
    return {
        "id": "test-target",
        "type": "ssh",
        "host": "192.168.1.100",
        "port": 22,
        "username": "testuser"
    }

@pytest.fixture
def mock_ssh_connection(mocker):
    """Mock SSH connection for testing."""
    mock_conn = mocker.MagicMock()
    mock_conn.execute_command.return_value = {
        "exit_code": 0,
        "stdout": "command output",
        "stderr": ""
    }
    mocker.patch('src.connectors.ssh_connector.create_connection', return_value=mock_conn)
    return mock_conn
```

### **Radon** - Code Complexity Analysis

Radon analyzes code complexity and maintainability.

#### **Cyclomatic Complexity**
```bash
# Basic complexity analysis
radon cc src

# JSON output
radon cc src --json

# Minimum complexity threshold
radon cc src --min=B

# Show average complexity
radon cc src --show-average

# Include docstrings and comments
radon cc src --include-docstrings

# Exclude specific directories
radon cc src --exclude tests,scripts

# Output to file
radon cc src --json > complexity-report.json
```

#### **Maintainability Index**
```bash
# Maintainability analysis
radon mi src

# JSON output
radon mi src --json

# Minimum maintainability
radon mi src --min=B

# Include documentation
radon mi src --include-docstrings

# Output to file
radon mi src > maintainability-report.txt
```

#### **Raw Metrics**
```bash
# Raw metrics for all files
radon raw src

# Specific metrics
radon raw src --average

# JSON output
radon raw src --json
```

#### **Halstead Metrics**
```bash
# Halstead complexity
radon hal src

# JSON output
radon hal src --json
```

### **isort** - Import Sorting

isort organizes and sorts Python imports.

#### **Basic Usage**
```bash
# Sort imports
isort src tests

# Check import sorting
isort --check-only src tests

# Show differences
isort --diff src tests
```

#### **Advanced Usage**
```bash
# Profile-based sorting (Black compatible)
isort --profile black src tests

# Skip specific files
isort --skip tests/fixtures.py src tests

# Only process changed files
isort --diff HEAD~1

# Atomic operation (revert if fails)
isort --atomic src tests

# Multi-threaded processing
isort --jobs 4 src tests

# Line length
isort --line-length 88 src tests

# Force single line imports
isort --force-single-line src tests

# Combine star imports
isort --combine-star src tests

# Show statistics
isort --check-only --verbose src tests

# Skip gitignore patterns
isort --skip-glob="*/migrations/*" src tests
```

---

## Automation Scripts

### **[scripts/run_quality_checks.py](scripts/run_quality_checks.py)** - Comprehensive Quality Checker

A Python script that orchestrates all quality assurance tools and generates comprehensive reports.

#### **Usage**
```bash
# Run all quality checks
python scripts/run_quality_checks.py --all

# Run specific checks
python scripts/run_quality_checks.py --lint --format

# Verbose output
python scripts/run_quality_checks.py --all --verbose

# Custom report directory
python scripts/run_quality_checks.py --all --report-dir custom-reports/
```

#### **Options**
```bash
--all                Run all quality checks
--lint              Run linting checks (ruff)
--format            Run formatting checks
--typecheck         Run type checking (mypy)
--security          Run security scans (bandit, safety)
--complexity        Run complexity analysis (radon)
--tests             Run tests (pytest)
--verbose, -v       Verbose output
--report-dir DIR    Directory for reports (default: quality-reports)
--help, -h          Show help message
```

#### **Features**
- **Unified Interface**: Single command to run all quality tools
- **Comprehensive Reporting**: JSON reports with metrics and summaries
- **Performance Metrics**: Timing for each quality check
- **Error Handling**: Graceful handling of tool failures
- **Configurable Output**: Customizable report directories and formats
- **Quality Scoring**: Overall quality score calculation
- **Human-readable Summary**: Console output with clear status indicators

#### **Output**
```bash
$ python scripts/run_quality_checks.py --all --report-dir reports/

[INFO] Starting comprehensive quality checks...
[INFO] Running ruff lint...
[INFO] Linting completed: 0 issues found
[INFO] Running ruff format...
[INFO] Formatting check completed: 0 files need formatting
[INFO] Running type checks...
[INFO] Type checking completed: 0 type errors found
[INFO] Running security scans...
[INFO] Security checks completed: 0 issues found
[INFO] Running complexity analysis...
[INFO] Complexity analysis completed: 0 high-complexity functions found
[INFO] Running tests...
[INFO] Tests completed: 142 passed, 0 failed, 0 skipped
[INFO] Coverage: 94.2%
[INFO] All quality checks completed in 47.23s

============================================================
📊 QUALITY CHECKS SUMMARY
============================================================

LINTING: ✅ PASS
  Duration: 8.45s
  Issues found: 0

FORMATTING: ✅ PASS
  Duration: 2.17s
  Files need formatting: 0

TYPE_CHECKING: ✅ PASS
  Duration: 12.33s
  Type errors: 0

SECURITY: ✅ PASS
  Duration: 15.78s
  Total security issues: 0
    - Bandit: 0
    - Safety: 0

COMPLEXITY: ✅ PASS
  Duration: 3.12s
  High-complexity functions: 0

TESTS: ✅ PASS
  Duration: 5.38s
  Tests passed: 142, Tests failed: 0, Tests skipped: 0
  Coverage: 94.2%

OVERALL QUALITY SCORE: 100.0/100
```

### **[scripts/fix_code_quality.py](scripts/fix_code_quality.py)** - Auto-Fix Code Issues

Automatically fixes common code quality issues using various tools.

#### **Usage**
```bash
# Auto-fix all issues
python scripts/fix_code_quality.py --all

# Fix specific issues
python scripts/fix_code_quality.py --lint --imports --format

# Preview changes without applying
python scripts/fix_code_quality.py --all --dry-run

# Skip backup creation
python scripts/fix_code_quality.py --all --no-backup
```

#### **Options**
```bash
--all                Fix all auto-fixable issues (default)
--imports            Fix import sorting and organization
--format             Fix code formatting
--lint               Fix linting issues
--type-annotations   Fix missing type annotations
--docstrings         Fix missing docstrings
--security           Fix security-related issues
--performance        Fix performance-related issues
--complexity         Fix complexity-related issues
--dry-run            Preview changes without applying them
--verbose, -v        Verbose output
--no-backup          Skip creating backup before making changes
--help, -h           Show help message
```

#### **Features**
- **Auto-fixing**: Automatically fixes common issues without manual intervention
- **Backup Creation**: Creates backups before making changes
- **Dry Run Mode**: Preview changes without applying them
- **Tool Integration**: Uses ruff, isort, and other tools for fixing
- **Verification**: Verifies fixes after applying
- **Human-readable Output**: Clear progress and result reporting
- **Error Handling**: Graceful handling of tool failures

#### **Output**
```bash
$ python scripts/fix_code_quality.py --all

[INFO] Starting comprehensive code quality fixes...
[INFO] Fixing import sorting...
[INFO] Import sorting fixed successfully
[INFO] Fixing code formatting...
[INFO] Code formatting fixed successfully
[INFO] Fixing linting issues...
[INFO] Linting issues fixed successfully
[INFO] Checking and fixing type annotations...
[INFO] Type annotations fixed successfully
[INFO] Checking and fixing docstrings...
[INFO] Docstrings fixed successfully
[INFO] Checking and fixing security issues...
[INFO] Security issues fixed successfully
[INFO] Checking and fixing performance issues...
[INFO] Performance issues fixed successfully
[INFO] Checking and fixing complexity issues...
[INFO] Complexity issues fixed successfully

============================================================
🔧 CODE QUALITY FIX SUMMARY
============================================================

✅ FIXES APPLIED:
   • Import Sorting
   • Code Formatting
   • Linting Issues
   • Type Annotations
   • Docstrings
   • Security Issues
   • Performance Issues
   • Complexity Issues

⏱️  Total time: 23.45s

📝 NEXT STEPS:
1. Review the changes made to your code
2. Run tests to ensure everything still works: make test
3. Run quality checks to verify improvements: make quality
4. Consider committing changes if satisfied
```

### **[scripts/setup_dev_environment.sh](scripts/setup_dev_environment.sh)** - Development Environment Setup

Bash script that sets up the complete development environment automatically.

#### **Usage**
```bash
# Standard setup
./scripts/setup_dev_environment.sh

# Force re-setup
./scripts/setup_dev_environment.sh --force

# Skip virtual environment creation
./scripts/setup_dev_environment.sh --skip-venv

# Show help
./scripts/setup_dev_environment.sh --help
```

#### **Features**
- **Python Version Check**: Validates Python 3.12+ requirement
- **Dependency Installation**: Installs all required dependencies
- **Virtual Environment**: Creates and activates virtual environment
- **Pre-commit Setup**: Configures git hooks automatically
- **Development Tools**: Installs additional quality and testing tools
- **Configuration Creation**: Generates development configuration files
- **Verification**: Tests installation and creates helper scripts
- **Progress Reporting**: Color-coded progress indicators
- **Error Handling**: Comprehensive error checking and reporting

#### **What It Creates**
- **Virtual Environment**: `venv/` directory with all dependencies
- **Development Config**: `.dev_config` file with settings
- **Helper Scripts**:
  - `activate_dev.sh` - Easy environment activation
  - `quick_test.sh` - Environment verification script
- **Completion Flag**: `.dev_setup_complete` to track setup status

### **[scripts/scan.py](scripts/scan.py)** - Security Scanner

Custom security scanning script with comprehensive reporting.

#### **Usage**
```bash
# Full security scan
python scripts/scan.py --full

# Quick security scan
python scripts/scan.py --quick

# Custom scan with output
python scripts/scan.py --full --output security-report.json

# Scan specific directories
python scripts/scan.py --quick --dirs src,config
```

#### **Features**
- **Multiple Scanning Engines**: Integrates bandit, safety, and custom checks
- **Configurable Scans**: Full vs quick scanning modes
- **Custom Rule Engine**: TailOpsMCP-specific security checks
- **Vulnerability Tracking**: Tracks and reports vulnerability trends
- **Compliance Reporting**: Generates compliance reports
- **Integration Ready**: Designed for CI/CD integration

---

## CI/CD Workflows

### **[.github/workflows/quality-checks.yml](.github/workflows/quality-checks.yml)** - Quality Checks Pipeline

GitHub Actions workflow that runs comprehensive quality checks on every push and pull request.

#### **Trigger Events**
```yaml
on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]
  schedule:
    - cron: '0 6 * * 1'  # Weekly on Monday at 6 AM UTC
```

#### **Workflow Steps**
```yaml
jobs:
  quality-checks:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ['3.11', '3.12']

    steps:
    - uses: actions/checkout@v4

    - name: Set up Python ${{ matrix.python-version }}
      uses: actions/setup-python@v4
      with:
        python-version: ${{ matrix.python-version }}

    - name: Cache pip dependencies
      uses: actions/cache@v3
      with:
        path: ~/.cache/pip
        key: ${{ runner.os }}-pip-${{ hashFiles('**/requirements-dev.txt') }}
        restore-keys: |
          ${{ runner.os }}-pip-

    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r requirements-dev.txt
        pip install -e .

    - name: Run ruff linting
      run: ruff check src tests

    - name: Check code formatting
      run: ruff format --check src tests

    - name: Run type checking
      run: mypy src --ignore-missing-imports

    - name: Run security scan
      run: bandit -r src -f json -o bandit-report.json || true

    - name: Check dependencies
      run: safety check --json --output safety-report.json || true

    - name: Run complexity analysis
      run: |
        radon cc src --json > complexity-report.json || true
        radon mi src > maintainability-report.txt || true

    - name: Run tests with coverage
      run: pytest tests/ --cov=src --cov-report=xml --cov-report=html

    - name: Upload coverage reports
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage.xml
        flags: unittests

    - name: Upload security reports
      uses: actions/upload-artifact@v3
      if: always()
      with:
        name: security-reports-python-${{ matrix.python-version }}
        path: |
          bandit-report.json
          safety-report.json
          complexity-report.json
          maintainability-report.txt

    - name: Comment PR with results
      uses: actions/github-script@v6
      if: github.event_name == 'pull_request'
      with:
        script: |
          const fs = require('fs');
          const coverage = fs.readFileSync('coverage.xml', 'utf8');
          const coverageMatch = coverage.match(/line-rate="([^"]+)"/);
          const coveragePercent = coverageMatch ? (parseFloat(coverageMatch[1]) * 100).toFixed(1) : '0.0';

          github.rest.issues.createComment({
            issue_number: context.issue.number,
            owner: context.repo.owner,
            repo: context.repo.repo,
            body: `## 📊 Quality Check Results
            \n**Python Version:** ${{ matrix.python-version }}
            \n**Test Coverage:** ${coveragePercent}%
            \n**Status:** ✅ All quality checks passed!
            \n\n[View detailed reports](${context.payload.pull_request.html_url}/checks)`
          });
```

### **[.github/workflows/security-scan.yml](.github/workflows/security-scan.yml)** - Security Scanning Pipeline

Dedicated security scanning workflow with comprehensive security checks.

#### **Features**
- **Scheduled Scans**: Daily security vulnerability scans
- **Comprehensive Coverage**: Code security, dependency vulnerabilities, and compliance
- **Security Reporting**: Detailed security reports with remediation guidance
- **Alert Integration**: Integration with security alerting systems
- **Baseline Tracking**: Security metrics baseline and trend analysis

### **[.github/workflows/test.yml](.github/workflows/test.yml)** - Testing Pipeline

Comprehensive testing pipeline with multiple Python versions and test configurations.

#### **Test Matrix**
```yaml
strategy:
  matrix:
    os: [ubuntu-latest, windows-latest, macos-latest]
    python-version: ['3.11', '3.12', '3.13']
    test-type: [unit, integration, security]
```

#### **Test Configurations**
- **Unit Tests**: Fast, isolated component testing
- **Integration Tests**: End-to-end functionality testing
- **Security Tests**: Security-focused test scenarios
- **Performance Tests**: Performance and load testing
- **Compatibility Tests**: Cross-platform and version compatibility

### **[.github/workflows/pre-commit.yml](.github/workflows/pre-commit.yml)** - Pre-commit Validation

Validates pre-commit hook configuration and ensures consistent quality across all contributions.

---

## Customization Options

### **Tool Configuration Customization**

#### **Ruff Configuration**
Modify `pyproject.toml` to customize ruff behavior:

```toml
[tool.ruff]
target-version = "py311"
line-length = 88
select = [
    "E",    # pycodestyle errors
    "W",    # pycodestyle warnings
    "F",    # pyflakes
    "I",    # isort
    # Add or remove rule categories as needed
    "B",    # flake8-bugbear
    "C4",   # flake8-comprehensions
]
ignore = [
    "E501",  # Line too long (handled by formatter)
    "W503",  # Line break before binary operator
    # Add specific rules to ignore
]

# Per-file ignores
[tool.ruff.per-file-ignores]
"tests/**/*.py" = [
    "S101",  # Allow assert in tests
    "ANN",   # Allow missing type hints in tests
]
"scripts/*.py" = [
    "T201",  # Allow print statements in scripts
]
```

#### **MyPy Configuration**
Customize type checking strictness:

```toml
[tool.mypy]
python_version = "3.11"
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = true

# Additional strictness options
disallow_incomplete_defs = true
check_untyped_defs = true
disallow_untyped_decorators = true
no_implicit_optional = true
warn_redundant_casts = true
warn_unused_ignores = true
warn_no_return = true
warn_unreachable = true
strict_equality = true

# Disable specific checks for certain modules
[[tool.mypy.overrides]]
module = [
    "tests.*",
    "scripts.*",
]
disallow_untyped_defs = false
disallow_incomplete_defs = false
```

#### **Pre-commit Hook Customization**
Add or modify pre-commit hooks in `.pre-commit-config.yaml`:

```yaml
repos:
  # Existing hooks...

  # Add new repository
  - repo: https://github.com/pre-commit/mirrors-prettier
    rev: v3.0.0-alpha.9-for-vscode
    hooks:
      - id: prettier
        types: [yaml]

  # Modify existing hook
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.6.4
    hooks:
      - id: ruff
        args: [--fix, --exit-non-zero-on-fix]
      - id: ruff-format
        args: [--check]
```

### **Quality Threshold Customization**

#### **Test Coverage Thresholds**
Modify coverage requirements in `pytest.ini`:

```ini
[tool:pytest]
addopts =
    -ra
    --strict-markers
    --strict-config
    --cov=src
    --cov-fail-under=85    # Change from 80 to 85
    --cov-report=term-missing:skip-covered
    --cov-report=html:htmlcov
    --cov-report=xml:coverage.xml
```

#### **Complexity Thresholds**
Adjust complexity limits in Makefile:

```makefile
complexity: ## Run complexity analysis using radon
	@echo "$(BLUE)Running complexity analysis...$(RESET)"
	@radon cc $(SRC_DIR) --min=B --json > complexity-report.json || true  # Change from C to B
	@radon mi $(SRC_DIR) --min=B > maintainability-report.txt || true     # Change from C to B
	@echo "$(GREEN)Complexity analysis completed!$(RESET)"
```

### **Workflow Customization**

#### **CI/CD Pipeline Customization**
Modify GitHub Actions workflows to add new checks:

```yaml
- name: Custom Security Check
  run: |
    # Add custom security validation
    python scripts/custom_security_check.py --report custom-security.json

- name: Performance Benchmark
  run: |
    # Add performance testing
    python scripts/performance_benchmark.py --threshold 100ms

- name: Documentation Check
  run: |
    # Validate documentation
    python scripts/check_documentation.py --validate-all
```

#### **Makefile Customization**
Add custom commands to Makefile:

```makefile
# Custom quality command
custom-quality: lint typecheck security
	@echo "$(GREEN)Custom quality checks completed!$(RESET)"

# Performance testing
performance-test:
	@echo "$(BLUE)Running performance tests...$(RESET)"
	@pytest tests/ -m "performance" -v
	@echo "$(GREEN)Performance tests completed!$(RESET)"

# Documentation generation
docs-build:
	@echo "$(BLUE)Building documentation...$(RESET)"
	sphinx-build -b html docs/ docs/_build/html
	@echo "$(GREEN)Documentation built successfully!$(RESET)"
```

### **IDE Integration Customization**

#### **VS Code Settings**
Customize `.vscode/settings.json`:

```json
{
  "python.defaultInterpreterPath": "./venv/bin/python",
  "python.linting.enabled": true,
  "python.linting.ruffEnabled": true,
  "python.linting.mypyEnabled": true,
  "python.linting.banditEnabled": true,
  "python.formatting.provider": "none",
  "[python]": {
    "editor.defaultFormatter": "charliermarsh.ruff",
    "editor.formatOnSave": true,
    "editor.codeActionsOnSave": {
      "source.organizeImports": true,
      "source.fixAll": true
    }
  },
  // Add custom settings
  "python.linting.ruffArgs": [
    "--config=pyproject.toml",
    "--fix"
  ],
  "python.testing.pytestEnabled": true,
  "python.testing.pytestArgs": [
    "tests",
    "--cov=src",
    "--cov-report=html"
  ]
}
```

#### **Custom Editor Integration**
Add support for additional editors:

```bash
# Vim/Neovim configuration
cat > .vimrc.local << 'EOF'
" Add to your .vimrc for TailOpsMCP development
Plug 'charliermarsh/vim-ruff'
Plug 'psf/black', { 'branch': 'main' }

" Ruff configuration
let g:ruff_lsp_config = {
    \ 'settings': {
        \ 'ruff': {
            \ 'lineLength': 88,
            \ 'exclude': ['tests/', 'scripts/']
        \ }
    \ }
}

" Black configuration
let g:black_virtualenv = expand('~/TailOpsMCP/venv')
EOF

# Emacs configuration
cat > .emacs.local << 'EOF'
;; Add to your .emacs for TailOpsMCP development
(use-package python
  :ensure t
  :custom
  (python-shell-interpreter "~/TailOpsMCP/venv/bin/python")
  (python-black-command "~/TailOpsMCP/venv/bin/black")
  :config
  (add-hook 'python-mode-hook 'blacken-mode)
  (add-hook 'python-mode-hook 'lsp))
EOF
```

---

## Integration Guide

### **IDE Integration**

#### **VS Code Complete Setup**
1. **Install Required Extensions**
   ```bash
   code --install-extension ms-python.python
   code --install-extension charliermarsh.ruff
   code --install-extension ms-python.mypy-type-checker
   code --install-extension eamodio.gitlens
   ```

2. **Configure Settings**
   - Copy `.vscode/settings.json` from this reference
   - Restart VS Code to apply changes

3. **Configure Tasks**
   - Copy `.vscode/tasks.json` from this reference
   - Use Ctrl+Shift+P → "Tasks: Run Task" to run quality checks

4. **Configure Debugging**
   - Copy `.vscode/launch.json` from this reference
   - Set breakpoints and debug tests

#### **PyCharm/IntelliJ Setup**
1. **Configure Python Interpreter**
   - File → Settings → Project → Python Interpreter
   - Add Interpreter → System Interpreter → `./venv/bin/python`

2. **Configure Code Style**
   - File → Settings → Editor → Code Style → Python
   - Set line length to 88
   - Enable Black formatter integration

3. **Configure Testing**
   - File → Settings → Tools → Python Integrated Tools
   - Set default test runner to pytest
   - Configure coverage settings

### **CI/CD Integration**

#### **GitHub Actions Setup**
1. **Add Workflow Files**
   - Copy workflow files from `.github/workflows/`
   - Commit to repository
   - Workflows will run automatically on push/PR

2. **Configure Secrets** (if needed)
   - Add API keys to repository secrets
   - Use secrets in workflows with `${{ secrets.SECRET_NAME }}`

3. **Configure Branch Protection**
   - Require status checks to pass before merging
   - Require review from code owners

#### **GitLab CI Integration**
```yaml
# .gitlab-ci.yml
stages:
  - quality
  - test
  - security

variables:
  PIP_CACHE_DIR: "$CI_PROJECT_DIR/.cache/pip"

cache:
  paths:
    - .cache/pip/
    - venv/

quality:
  stage: quality
  image: python:3.12
  script:
    - python -m venv venv
    - source venv/bin/activate
    - pip install -r requirements-dev.txt
    - make quality
  artifacts:
    reports:
      junit: quality-reports/*.xml
    paths:
      - quality-reports/

test:
  stage: test
  image: python:3.12
  script:
    - python -m venv venv
    - source venv/bin/activate
    - pip install -r requirements-dev.txt
    - make test
  coverage: '/TOTAL.*\s+(\d+%)$/'
  artifacts:
    reports:
      coverage_report:
        coverage_format: cobertura
        path: coverage.xml
```

### **Local Development Integration**

#### **Shell Integration**
```bash
# Add to ~/.bashrc or ~/.zshrc for enhanced development experience

# TailOpsMCP development environment
alias tailops-dev="source $(pwd)/venv/bin/activate"
alias tailops-quality="make quality"
alias tailops-test="make test"
alias tailops-fix="make fix"
alias tailops-setup="make setup"

# Function to run quality checks with fallback
tailops-check() {
    if command -v make >/dev/null 2>&1; then
        make quality
    else
        python scripts/run_quality_checks.py --all
    fi
}

# Function to run tests with coverage
tailops-test-cov() {
    pytest tests/ --cov=src --cov-report=html --cov-report=term-missing
    if command -v open >/dev/null 2>&1; then
        open htmlcov/index.html  # macOS
    elif command -v xdg-open >/dev/null 2>&1; then
        xdg-open htmlcov/index.html  # Linux
    fi
}
```

#### **Editor Integration Scripts**
```bash
#!/bin/bash
# scripts/editor-integration.sh - Setup editor integration

echo "Setting up editor integration for TailOpsMCP..."

# VS Code integration
if command -v code >/dev/null 2>&1; then
    echo "Configuring VS Code..."
    mkdir -p .vscode
    cp -n .vscode/settings.json .vscode/settings.json.bak 2>/dev/null || true
    # VS Code settings are configured via the reference above
fi

# Vim/Neovim integration
if command -v nvim >/dev/null 2>&1 || command -v vim >/dev/null 2>&1; then
    echo "Configuring Vim/Neovim..."
    mkdir -p ~/.vim/pack/plugins/start
    # Add vim-ruff plugin
fi

echo "Editor integration setup complete!"
echo "For detailed IDE configuration, see QUALITY_TOOLS_REFERENCE.md"
```

### **Security Integration**

#### **Security Monitoring Integration**
```bash
#!/bin/bash
# scripts/security-monitor.sh - Continuous security monitoring

# Add to crontab for continuous monitoring
# 0 */6 * * * /path/to/TailOpsMCP/scripts/security-monitor.sh

set -e

REPORT_DIR="security-reports/$(date +%Y-%m-%d)"
mkdir -p "$REPORT_DIR"

echo "Running security monitoring - $(date)"

# Run comprehensive security scan
python scripts/run_quality_checks.py --security --report-dir "$REPORT_DIR"

# Check for new vulnerabilities
python scripts/check_new_vulnerabilities.py --baseline security-baseline.json

# Generate security metrics
python scripts/security_metrics.py --output "$REPORT_DIR/metrics.json"

# Alert on critical issues
if grep -q "CRITICAL" "$REPORT_DIR/security-report.json"; then
    echo "CRITICAL security issues detected!"
    # Send alert (configure with your alerting system)
    curl -X POST "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK" \
         -H 'Content-type: application/json' \
         --data '{"text":"🚨 CRITICAL security issues detected in TailOpsMCP!"}'
fi

echo "Security monitoring completed"
```

This comprehensive reference provides detailed technical documentation for all code quality tools and configurations in TailOpsMCP. Use this as your go-to guide for tool configuration, customization, and integration.
