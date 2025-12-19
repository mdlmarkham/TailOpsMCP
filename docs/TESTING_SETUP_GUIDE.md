# TailOpsMCP Testing Setup & VSCode Configuration Guide

## Table of Contents
1. [The Problem: VSCode Pytest Discovery Failure](#the-problem-vscode-pytest-discovery-failure)
2. [The Solution: VSCode Workspace Configuration](#the-solution-vscode-workspace-configuration)
3. [Testing Setup Overview](#testing-setup-overview)
4. [VSCode Configuration Details](#vscode-configuration-details)
5. [Usage Instructions](#usage-instructions)
6. [Troubleshooting Guide](#troubleshooting-guide)
7. [Development Workflow](#development-workflow)

---

## The Problem: VSCode Pytest Discovery Failure

### Root Cause Analysis

The TailOpsMCP project experienced pytest discovery failures in VSCode due to a **Python interpreter mismatch**. Here's what happened:

#### Symptoms
- VSCode showed "No tests discovered" despite having a comprehensive test suite
- Test files were present in the `tests/` directory
- Command-line pytest worked correctly
- VSCode's test panel remained empty or showed error messages

#### Technical Root Cause
VSCode was configured to use the **system Python interpreter** instead of the project's **virtual environment**. This caused several issues:

1. **Missing Dependencies**: System Python didn't have project-specific packages installed
2. **Module Import Failures**: Tests couldn't import modules from `src/` due to missing packages
3. **Configuration Conflicts**: VSCode used system-wide pytest settings instead of project-specific configuration

#### Impact
- **Developer Productivity**: Developers couldn't run tests directly from VSCode
- **Test-Driven Development**: TDD workflow was disrupted
- **Debugging**: Breakpoints and debugging tools didn't work properly
- **Code Coverage**: VSCode's coverage integration was non-functional

---

## The Solution: VSCode Workspace Configuration

### Implementation Strategy

The solution involved creating a comprehensive.json` file `.vscode/settings that:

1. **Explicitly Configures Python Interpreter**: Points to the project virtual environment
2. **Enables Pytest Testing**: Configures VSCode's built-in testing framework
3. **Integrates Terminal Environment**: Ensures consistent environment across VSCode and terminal
4. **Optimizes Performance**: Configures file exclusions and indexing for better performance

### Key Configuration Components

#### Python Interpreter Path
```json
"python.defaultInterpreterPath": "c:/Users/mdlma/Documents/Projects/TailOpsMCP/venv/Scripts/python.exe"
```

#### Testing Framework Configuration
```json
"python.testing.pytestEnabled": true,
"python.testing.pytestArgs": ["tests"],
"python.testing.autoTestDiscoverOnSaveEnabled": true
```

#### Terminal Environment Integration
```json
"terminal.integrated.env.windows": {
    "VIRTUAL_ENV": "c:/Users/mdlma/Documents/Projects/TailOpsMCP/venv",
    "PATH": "c:/Users/mdlma/Documents/Projects/TailOpsMCP/venv/Scripts;${env:PATH}"
}
```

---

## Testing Setup Overview

### Test Infrastructure Architecture

The TailOpsMCP testing infrastructure is built on multiple layers:

```
┌─────────────────────────────────────────────────────────────┐
│                    Test Discovery Layer                      │
├─────────────────────────────────────────────────────────────┤
│  pytest.ini  │  pyproject.toml  │  .vscode/settings.json   │
├─────────────────────────────────────────────────────────────┤
│                    Test Execution Layer                     │
├─────────────────────────────────────────────────────────────┤
│  pytest >=7.4.0  │  pytest-asyncio >=0.21.0               │
├─────────────────────────────────────────────────────────────┤
│                    Test Infrastructure Layer                │
├─────────────────────────────────────────────────────────────┤
│  Mock Executors  │  Test Fixtures  │  Assertion Helpers    │
├─────────────────────────────────────────────────────────────┤
│                    Test Suites Layer                        │
├─────────────────────────────────────────────────────────────┤
│  Unit Tests  │  Integration  │  Security  │  Performance   │
└─────────────────────────────────────────────────────────────┘
```

### Configuration Files

#### `pytest.ini` - Core Testing Configuration
- **Test Discovery**: Defines test paths, file patterns, and function naming conventions
- **Coverage Requirements**: Minimum 80% code coverage with detailed reporting
- **Test Markers**: Categorizes tests by type and execution characteristics
- **Warning Filters**: Suppresses non-critical warnings for cleaner output

#### `requirements.txt` - Development Dependencies
- **Testing Framework**: pytest 7.4.0+ with asyncio support
- **Code Quality**: black, mypy, flake8, and pre-commit
- **Coverage Tools**: Built-in pytest coverage with multiple output formats

#### `pyproject.toml` - Project Configuration
- **Build System**: Setuptools-based build configuration
- **Tool Settings**: Black formatting, MyPy type checking
- **Package Discovery**: Automatic package detection in `src/` directory

### Test Organization

#### Directory Structure
```
tests/
├── __init__.py                 # Test infrastructure and fixtures
├── mock_executors.py          # Mock implementations for external services
├── fixtures/                  # Reusable test fixtures
├── test_*.py                  # Individual test suites
└── test_utils.py              # Assertion helpers and utilities
```

#### Test Categories

| Marker | Purpose | Execution Time | Dependencies |
|--------|---------|----------------|--------------|
| `unit` | Unit tests (fast, no external dependencies) | < 5 seconds | None |
| `integration` | Integration tests (may need Docker) | 5-60 seconds | Docker, External Services |
| `security` | Security-focused tests | 10-30 seconds | Security Models |
| `performance` | Performance and load tests | 30-300 seconds | Load Testing Tools |
| `edge_case` | Edge case and failure scenarios | 5-15 seconds | Mock Failures |
| `orchestration` | Workflow and policy tests | 15-45 seconds | Policy Engine |
| `slow` | Tests that take longer to run | > 60 seconds | Variable |
| `smoke` | Quick smoke tests for basic functionality | < 10 seconds | Minimal |
| `regression` | Regression tests for bug fixes | 10-30 seconds | Specific Scenarios |
| `compliance` | Compliance and regulatory tests | 20-60 seconds | Compliance Framework |

---

## VSCode Configuration Details

### Comprehensive Configuration Breakdown

The `.vscode/settings.json` file contains 97 lines of carefully configured settings across multiple categories:

#### 1. Python Interpreter Configuration
```json
{
    "python.defaultInterpreterPath": "c:/Users/mdlma/Documents/Projects/TailOpsMCP/venv/Scripts/python.exe",
    "python.terminal.activateEnvironment": true
}
```

**Purpose**: Ensures VSCode uses the correct Python interpreter with virtual environment activation.

#### 2. Testing Configuration
```json
{
    "python.testing.pytestEnabled": true,
    "python.testing.unittestEnabled": false,
    "python.testing.pytestArgs": ["tests"],
    "python.testing.autoTestDiscoverOnSaveEnabled": true
}
```

**Purpose**: Configures VSCode's built-in testing framework to use pytest exclusively with automatic discovery.

#### 3. Terminal Environment Integration
```json
{
    "terminal.integrated.env.windows": {
        "VIRTUAL_ENV": "c:/Users/mdlma/Documents/Projects/TailOpsMCP/venv",
        "PATH": "c:/Users/mdlma/Documents/Projects/TailOpsMCP/venv/Scripts;${env:PATH}"
    },
    "terminal.integrated.shellArgs.windows": [
        "/K",
        "c:/Users/mdlma/Documents/Projects/TailOpsMCP/venv/Scripts/activate.bat"
    ]
}
```

**Purpose**: Ensures the integrated terminal uses the same virtual environment as the Python interpreter.

#### 4. Python Path Configuration
```json
{
    "python.analysis.extraPaths": ["./src"],
    "python.envFile": "${workspaceFolder}/.env"
}
```

**Purpose**: Configures module resolution and environment variable loading.

#### 5. Code Quality and Formatting
```json
{
    "python.formatting.provider": "black",
    "python.linting.enabled": true,
    "python.linting.mypyEnabled": true,
    "python.linting.flake8Enabled": true,
    "editor.formatOnSave": true,
    "editor.codeActionsOnSave": {
        "source.organizeImports": true,
        "source.fixAll": true
    }
}
```

**Purpose**: Enables automatic code formatting and linting for consistent code quality.

#### 6. Performance Optimizations
```json
{
    "files.exclude": {
        "**/__pycache__": true,
        "**/*.pyc": true,
        "**/.pytest_cache": true,
        "**/htmlcov": true,
        "**/.coverage": true,
        "**/.mypy_cache": true,
        "**/node_modules": true,
        "**/.git": true
    },
    "search.exclude": {
        // Similar patterns for search exclusions
    },
    "python.analysis.indexing": true,
    "python.analysis.memory.keepLibraryAst": true
}
```

**Purpose**: Improves VSCode performance by excluding unnecessary files from indexing and search.

### Configuration Validation

To verify the configuration is working correctly:

1. **Check Python Interpreter**: Command Palette → "Python: Select Interpreter"
2. **Verify Test Discovery**: Test Explorer should show all test files
3. **Test Terminal Integration**: New terminal should activate virtual environment automatically

---

## Usage Instructions

### Running Tests from Command Line

#### Basic Test Execution
```bash
# Activate virtual environment
source venv/Scripts/activate  # Windows
# source venv/bin/activate    # Linux/macOS

# Run all tests
pytest

# Run specific test file
pytest tests/test_security_framework_comprehensive.py

# Run tests with specific marker
pytest -m "unit"
pytest -m "security"
pytest -m "integration"

# Run with coverage
pytest --cov=src --cov-report=html

# Run with verbose output
pytest -v

# Run only failed tests (after initial run)
pytest --lf
```

#### Advanced Test Execution
```bash
# Run tests in parallel (requires pytest-xdist)
pytest -n auto

# Run tests with specific markers and timeout
pytest -m "not slow" --timeout=30

# Run tests and generate JUnit XML for CI
pytest --junitxml=test-results.xml

# Run tests with specific output format
pytest --tb=short    # Short traceback
pytest --tb=long     # Detailed traceback
pytest --tb=line     # One-line traceback
```

### Running Tests from VSCode

#### Using Test Explorer
1. **Open Test Explorer**: View → Testing → Test Explorer
2. **Discover Tests**: Tests should auto-discover on file save
3. **Run Tests**: Click the play button next to test names
4. **Run Test Suites**: Use context menu to run entire test files
5. **Debug Tests**: Use debug button for step-through debugging

#### Using Test Commands
1. **Command Palette**: Ctrl+Shift+P (Cmd+Shift+P on Mac)
2. **Run All Tests**: "Python: Run All Tests"
3. **Run Current Test File**: "Python: Run Current Test File"
4. **Run Test at Cursor**: "Python: Run Test at Cursor"

#### Using Test Status Indicators
- **Green Checkmark**: Test passed
- **Red X**: Test failed
- **Yellow Circle**: Test skipped
- **Blue Play Button**: Test not yet run

### Test Development Workflow

#### 1. Writing New Tests
```python
import pytest
from src.your_module import YourClass

class TestYourClass:
    """Test suite for YourClass."""

    @pytest.mark.unit
    def test_basic_functionality(self):
        """Test basic functionality."""
        instance = YourClass()
        result = instance.method()
        assert result == expected_value

    @pytest.mark.security
    def test_security_validation(self):
        """Test security validation."""
        # Security-specific test logic
        pass
```

#### 2. Using Test Fixtures
```python
def test_with_fixtures(mock_policy_gate, basic_test_target):
    """Test using predefined fixtures."""
    # Test logic using fixtures
    pass
```

#### 3. Running Tests During Development
```bash
# Continuous testing (watch for changes)
ptw  # pytest-watch

# Run tests on file save (VSCode auto-test discovery)
# Already configured in .vscode/settings.json
```

---

## Troubleshooting Guide

### Common Issues and Solutions

#### Issue 1: "No Tests Discovered" in VSCode

**Symptoms**:
- Test Explorer shows "No tests discovered"
- VSCode status bar shows "Pytest not found"

**Diagnosis**:
```bash
# Check if pytest is installed in virtual environment
pip list | grep pytest

# Check Python interpreter path in VSCode
# Command: "Python: Select Interpreter"
```

**Solutions**:
1. **Verify Virtual Environment Path**:
   ```json
   // In .vscode/settings.json
   "python.defaultInterpreterPath": "./venv/Scripts/python.exe"
   ```

2. **Install Development Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Reload VSCode Window**: Ctrl+Shift+P → "Developer: Reload Window"

#### Issue 2: Import Errors in Tests

**Symptoms**:
- "ModuleNotFoundError" when running tests
- Tests fail with import-related errors

**Diagnosis**:
```bash
# Check if src is in Python path
python -c "import sys; print('\n'.join(sys.path))"

# Verify project structure
ls -la src/
```

**Solutions**:
1. **Check Python Path Configuration**:
   ```json
   // In .vscode/settings.json
   "python.analysis.extraPaths": ["./src"]
   ```

2. **Add src to Python Path in pytest.ini**:
   ```ini
   [pytest]
   pythonpath = src
   ```

3. **Use sys.path.insert in test files**:
   ```python
   import sys
   from pathlib import Path
   project_root = Path(__file__).parent.parent
   sys.path.insert(0, str(project_root))
   ```

#### Issue 3: Test Discovery Works But Tests Don't Run

**Symptoms**:
- Tests appear in Test Explorer
- Running tests shows "Test failed with exit code 1"
- No detailed error output

**Diagnosis**:
```bash
# Run pytest manually to see detailed errors
pytest -v --tb=long
```

**Solutions**:
1. **Check Test Markers**: Ensure required markers are defined in pytest.ini
2. **Verify Test Fixtures**: Check if fixture dependencies are available
3. **Check Resource Dependencies**: Ensure Docker, external services are available for integration tests

#### Issue 4: Coverage Reports Not Generated

**Symptoms**:
- Coverage reports missing from test output
- HTML coverage report not created

**Diagnosis**:
```bash
# Check if coverage is installed
pip list | grep pytest-cov

# Run coverage manually
pytest --cov=src --cov-report=html --cov-report=term
```

**Solutions**:
1. **Install Coverage Dependencies**:
   ```bash
   pip install pytest-cov
   ```

2. **Check pytest.ini Coverage Configuration**:
   ```ini
   [pytest]
   addopts =
       --cov=src
       --cov-report=html
       --cov-report=xml
   ```

#### Issue 5: Virtual Environment Not Activated in Terminal

**Symptoms**:
- Terminal shows system Python version
- pip install affects system Python
- Python packages not found

**Diagnosis**:
```bash
# Check which Python is being used
which python  # Linux/macOS
where python  # Windows

# Check virtual environment
echo $VIRTUAL_ENV  # Linux/macOS
echo %VIRTUAL_ENV% # Windows
```

**Solutions**:
1. **Verify Terminal Configuration**:
   ```json
   // In .vscode/settings.json
   "terminal.integrated.shellArgs.windows": [
       "/K",
       "./venv/Scripts/activate.bat"
   ]
   ```

2. **Manually Activate Virtual Environment**:
   ```bash
   # Windows
   venv\Scripts\activate

   # Linux/macOS
   source venv/bin/activate
   ```

3. **Check .env File**: Ensure virtual environment path is correct

### Debug Configuration

#### VSCode Debug Configuration for Tests
Create `.vscode/launch.json`:

```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Pytest: Current Test File",
            "type": "python",
            "request": "launch",
            "module": "pytest",
            "args": ["${file}"],
            "console": "integratedTerminal",
            "justMyCode": false
        },
        {
            "name": "Pytest: All Tests",
            "type": "python",
            "request": "launch",
            "module": "pytest",
            "args": ["tests"],
            "console": "integratedTerminal",
            "justMyCode": false
        }
    ]
}
```

#### Debugging Test Failures
1. **Set Breakpoints**: Click in the gutter next to line numbers
2. **Run in Debug Mode**: Use debug button in Test Explorer
3. **Inspect Variables**: Use Debug Console to examine variables
4. **Step Through Code**: Use debug controls (Step Over, Step Into, etc.)

### Performance Troubleshooting

#### Slow Test Discovery
```json
// Optimize VSCode performance
"python.analysis.indexing": true,
"python.analysis.memory.keepLibraryAst": true,
"files.exclude": {
    "**/__pycache__": true,
    "**/*.pyc": true
}
```

#### Memory Usage Issues
```json
// Reduce memory footprint
"python.analysis.memory.keepLibraryAst": false,
"python.analysis.packageIndexDepths": [
    {"name": "sklearn", "depth": 1}
]
```

---

## Development Workflow

### Recommended Development Practices

#### 1. Test-Driven Development (TDD) Workflow
```
1. Write failing test
2. Write minimal code to pass test
3. Refactor code
4. Run full test suite
5. Commit changes
```

**VSCode Integration**:
- Use "Run Test at Cursor" for rapid feedback
- Configure auto-test discovery for continuous testing
- Use debug mode for complex test scenarios

#### 2. Continuous Testing Setup
```bash
# Install pytest-watch for continuous testing
pip install pytest-watch

# Run continuous testing
ptw  # Monitors file changes and runs tests automatically
```

**VSCode Configuration**:
- Auto-test discovery enabled in settings.json
- Format on save ensures code quality
- Linting provides immediate feedback

#### 3. Test Organization Best Practices

**File Naming Convention**:
```
tests/
├── test_<module_name>.py           # Feature tests
├── test_<component>_integration.py # Integration tests
├── test_security_*.py             # Security tests
└── test_performance_*.py          # Performance tests
```

**Test Class Organization**:
```python
class TestComponentName:
    """Test suite for ComponentName."""

    @pytest.mark.unit
    def test_basic_functionality(self):
        """Test basic functionality."""
        pass

    @pytest.mark.security
    def test_security_validation(self):
        """Test security validation."""
        pass

    @pytest.mark.integration
    def test_integration_with_external_service(self):
        """Test integration with external services."""
        pass
```

#### 4. Mock Strategy

**When to Use Mocks**:
- Unit tests for isolated components
- Testing error conditions
- Avoiding external dependencies
- Simulating complex scenarios

**Available Mock Infrastructure**:
```python
# From tests/__init__.py
mock_executors = {
    "ssh": MockSSHExecutor,
    "docker": MockDockerExecutor,
    "http": MockHTTPExecutor,
    "local": MockLocalExecutor,
    "proxmox": MockProxmoxExecutor
}
```

**Example Usage**:
```python
def test_with_mock_ssh():
    """Test using mock SSH executor."""
    ssh_executor = MockSSHExecutor(
        connect_success=True,
        command_success=True,
        output="mock output"
    )
    # Test logic with mock executor
    pass
```

#### 5. Code Quality Integration

**Automated Code Quality Checks**:
- **Black**: Code formatting on save
- **MyPy**: Static type checking
- **Flake8**: Style guide enforcement
- **Pre-commit**: Git hook integration

**VSCode Integration**:
```json
{
    "python.formatting.provider": "black",
    "python.linting.enabled": true,
    "python.linting.mypyEnabled": true,
    "python.linting.flake8Enabled": true,
    "editor.formatOnSave": true,
    "editor.codeActionsOnSave": {
        "source.organizeImports": true,
        "source.fixAll": true
    }
}
```

#### 6. Coverage Goals and Monitoring

**Coverage Targets**:
- **Minimum**: 80% (enforced in pytest.ini)
- **Unit Tests**: >90%
- **Integration Tests**: >70%
- **Security Tests**: 100%

**Coverage Workflow**:
```bash
# Generate coverage report
pytest --cov=src --cov-report=html --cov-report=term-missing

# View HTML coverage report
open htmlcov/index.html  # Opens in browser

# Check coverage for specific module
pytest --cov=src.tools.fleet_tools --cov-report=term-missing
```

#### 7. CI/CD Integration

**GitHub Actions Example**:
```yaml
name: Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Set up Python
      uses: actions/setup-python@v2
      with:
        python-version: 3.11
    - name: Install dependencies
      run: |
        pip install -r requirements.txt
    - name: Run tests
      run: pytest --cov=src --cov-report=xml --cov-report=html
    - name: Upload coverage
      uses: codecov/codecov-action@v1
```

### Performance Optimization

#### Test Execution Optimization
```bash
# Parallel test execution
pytest -n auto

# Run only affected tests (requires pytest-changed)
pytest --changed-only

# Skip slow tests during development
pytest -m "not slow"

# Run tests in specific order
pytest --randomly
```

#### Development Environment Optimization
1. **Virtual Always use project Environment Isolation**: virtual environment
2. **VSCode Performance Settings**: Configure exclusions and indexing
3. **Test Selection**: Use markers to run relevant test subsets
4. **Mock Usage**: Minimize external dependencies in unit tests

#### Continuous Integration Best Practices
1. **Fast Failures**: Run unit tests first, then integration tests
2. **Parallel Execution**: Use pytest-xdist for CI parallelization
3. **Test Artifacts**: Generate coverage reports and test results
4. **Environment Isolation**: Use containerized test environments

---

## Summary

The TailOpsMCP testing setup provides a comprehensive, VSCode-integrated testing environment that addresses the original pytest discovery failure through careful workspace configuration. The solution combines:

- **Robust Configuration**: Multiple configuration files working together
- **VSCode Integration**: Seamless IDE experience with test discovery and debugging
- **Comprehensive Test Suite**: Multiple test categories with proper organization
- **Development Workflow**: TDD-friendly tools and continuous testing support
- **Quality Assurance**: Code coverage, linting, and formatting automation

This setup enables developers to:
- Run tests efficiently from both command line and VSCode
- Debug test failures with full IDE integration
- Maintain high code quality through automated checks
- Scale testing across unit, integration, security, and performance categories
- Integrate seamlessly with CI/CD pipelines

The documented troubleshooting guide and development workflow ensure that new team members can quickly get up to speed and that common issues can be resolved efficiently.
