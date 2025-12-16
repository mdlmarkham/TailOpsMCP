# Developer Setup Guide

Welcome to TailOpsMCP development! This guide will get you set up with a complete development environment in minutes.

---

## 📋 Table of Contents

1. [Prerequisites](#prerequisites)
2. [Quick Start](#quick-start)
3. [Detailed Setup](#detailed-setup)
4. [IDE Configuration](#ide-configuration)
5. [Daily Development Workflow](#daily-development-workflow)
6. [Common Workflows](#common-workflows)
7. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### **Required Software**

#### **Python 3.12+**
TailOpsMCP requires Python 3.12 or later.

**Check your Python version:**
```bash
python3 --version
# Should show: Python 3.12.x or higher
```

**Install Python 3.12+ if needed:**
- **Ubuntu/Debian**: `sudo apt update && sudo apt install python3.12 python3.12-venv python3.12-dev`
- **macOS**: `brew install python@3.12`
- **Windows**: Download from [python.org](https://www.python.org/downloads/)
- **Other**: Use [pyenv](https://github.com/pyenv/pyenv) for version management

#### **Git**
Required for version control and contributing.

**Install Git:**
- **Ubuntu/Debian**: `sudo apt install git`
- **macOS**: `brew install git` or install Xcode Command Line Tools
- **Windows**: Download from [git-scm.com](https://git-scm.com/download/win)

#### **Optional but Recommended**

**Make** (for convenience commands):
- **Ubuntu/Debian**: `sudo apt install make`
- **macOS**: Usually pre-installed, or `brew install make`
- **Windows**: Install via [chocolatey](https://chocolatey.org/) or [winget](https://learn.microsoft.com/en-us/windows/package-manager/winget/)

**Docker** (for containerized development):
- Install from [docker.com](https://www.docker.com/products/docker-desktop)

---

## Quick Start

Get up and running in 3 simple steps:

```bash
# 1. Clone the repository
git clone https://github.com/mdlmarkham/TailOpsMCP.git
cd TailOpsMCP

# 2. Set up development environment (one command)
make setup

# 3. Verify everything works
make test
```

**That's it!** 🎉 You're ready to start developing.

### **What `make setup` does:**

- ✅ Checks Python version (3.12+)
- ✅ Creates virtual environment (`venv/`)
- ✅ Installs all development dependencies
- ✅ Installs project in development mode
- ✅ Sets up pre-commit hooks
- ✅ Creates development configuration
- ✅ Verifies installation

### **Quick verification:**

```bash
# Run a simple test to confirm everything works
make test

# Or run all quality checks
make quality
```

---

## Detailed Setup

### **Step 1: Clone Repository**

```bash
# Clone with SSH (recommended if you have SSH keys set up)
git clone git@github.com:mdlmarkham/TailOpsMCP.git
cd TailOpsMCP

# Or clone with HTTPS
git clone https://github.com/mdlmarkham/TailOpsMCP.git
cd TailOpsMCP
```

### **Step 2: Manual Environment Setup**

If you prefer manual setup or `make` is not available:

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements-dev.txt
pip install -e .

# Set up pre-commit hooks
pre-commit install

# Verify installation
python -c "import pytest, ruff, mypy, bandit; print('✅ All tools installed successfully')"
```

### **Step 3: Development Configuration**

The setup creates several helpful files:

```bash
# Development configuration
cat .dev_config

# Virtual environment activation helper
source activate_dev.sh

# Quick environment test
./quick_test.sh
```

### **Step 4: IDE Setup** (See [IDE Configuration](#ide-configuration))

---

## IDE Configuration

### **Visual Studio Code** (Recommended)

#### **Required Extensions**

Install these VS Code extensions for the best development experience:

1. **Python** - Official Python extension
2. **Pylance** - Advanced Python language server
3. **Black Formatter** - Code formatting
4. **isort** - Import sorting
5. **Prettier** - General code formatting
6. **GitLens** - Enhanced Git integration
7. **Error Lens** - Inline error display

#### **Settings Configuration**

Create `.vscode/settings.json`:

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
  "python.testing.pytestEnabled": true,
  "python.testing.unittestEnabled": false,
  "python.testing.pytestArgs": [
    "tests"
  ],
  "mypy.enabled": true,
  "files.exclude": {
    "**/__pycache__": true,
    "**/*.pyc": true,
    "**.mypy_cache": true,
    "**.pytest_cache": true,
    "**.ruff_cache": true
  }
}
```

#### **Launch Configuration**

Create `.vscode/launch.json` for debugging:

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Debug Tests",
      "type": "python",
      "request": "launch",
      "program": "${workspaceFolder}/venv/bin/pytest",
      "args": [
        "${workspaceFolder}/tests",
        "-v",
        "-s"
      ],
      "console": "integratedTerminal",
      "cwd": "${workspaceFolder}",
      "env": {
        "PYTHONPATH": "${workspaceFolder}/src"
      }
    },
    {
      "name": "Debug Current Test File",
      "type": "python",
      "request": "launch",
      "program": "${workspaceFolder}/venv/bin/pytest",
      "args": [
        "${file}",
        "-v",
        "-s"
      ],
      "console": "integratedTerminal",
      "cwd": "${workspaceFolder}",
      "env": {
        "PYTHONPATH": "${workspaceFolder}/src"
      }
    }
  ]
}
```

#### **Tasks Configuration**

Create `.vscode/tasks.json` for common commands:

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "Setup Development Environment",
      "type": "shell",
      "command": "make",
      "args": ["setup"],
      "group": "build",
      "presentation": {
        "echo": true,
        "reveal": "always",
        "focus": false,
        "panel": "shared"
      }
    },
    {
      "label": "Run Quality Checks",
      "type": "shell",
      "command": "make",
      "args": ["quality"],
      "group": "test",
      "presentation": {
        "echo": true,
        "reveal": "always",
        "focus": false,
        "panel": "shared"
      }
    },
    {
      "label": "Run Tests",
      "type": "shell",
      "command": "make",
      "args": ["test"],
      "group": "test",
      "presentation": {
        "echo": true,
        "reveal": "always",
        "focus": false,
        "panel": "shared"
      }
    },
    {
      "label": "Fix Code Issues",
      "type": "shell",
      "command": "make",
      "args": ["fix"],
      "group": "build",
      "presentation": {
        "echo": true,
        "reveal": "always",
        "focus": false,
        "panel": "shared"
      }
    }
  ]
}
```

### **PyCharm/IntelliJ**

#### **Project Configuration**

1. **Python Interpreter**: Set to `./venv/bin/python` (Project Interpreter)
2. **Code Style**: 
   - Line length: 88
   - Import organization: Sort by name, grouped by type
   - Enable Black formatter integration

#### **Testing Configuration**

- **Test Runner**: Pytest
- **Test Directory**: `tests/`
- **Coverage**: Enable with minimum threshold 80%

### **Vim/Neovim**

#### **Plugin Recommendations**

```vim
" Add to your .vimrc or init.lua
Plug 'neovim/nvim-lspconfig'
Plug 'python-lsp-server/python-lsp-server'
Plug 'charliermarsh/vim-ruff'
Plug 'psf/black', { 'branch': 'main' }
Plug 'pycqa/isort'
```

#### **LSP Configuration**

```lua
-- lua/lsp.lua
local lspconfig = require('lspconfig')
local lsp_defaults = lspconfig.util.default_config

lsp_defaults.capabilities = vim.tbl_deep_extend(
  'force',
  lsp_defaults.capabilities,
  require('cmp_nvim_lsp').default_capabilities()
)

-- Python LSP
lspconfig.pyright.setup({
  settings = {
    python = {
      analysis = {
        typeCheckingMode = "strict",
        autoImportCompletions = true,
      }
    }
  }
})

-- Ruff LSP for linting and formatting
lspconfig.ruff_lsp.setup({
  init_options = {
    settings = {
      ruff = {
        lineLength = 88,
        exclude = {"tests/", "scripts/"}
      }
    }
  }
})
```

### **Other Editors**

Most modern editors support the tools we use:

- **Sublime Text**: Install Python, Black, Ruff packages
- **Atom**: Install python, black, linter packages
- **Emacs**: Use lsp-mode with python-lsp-server

---

## Daily Development Workflow

### **🚀 Start of Day**

```bash
# Activate development environment
source venv/bin/activate
# Or use helper script
source activate_dev.sh

# Pull latest changes
git pull origin main

# Run quick quality check
make dev
```

### **🔧 During Development**

#### **Making Changes**

1. **Create feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**
   - Write code following our style guide
   - Add tests for new functionality
   - Update documentation

3. **Test frequently**
   ```bash
   # Run tests for specific module
   pytest tests/test_your_module.py -v
   
   # Run tests with coverage
   pytest tests/ --cov=src --cov-report=html
   
   # Run specific test
   pytest tests/test_specific_function.py::test_specific_case -v
   ```

4. **Check code quality**
   ```bash
   # Auto-fix formatting and import issues
   make fix
   
   # Run all quality checks
   make quality
   ```

#### **Quality-First Development**

Our development philosophy emphasizes quality from the start:

```bash
# The "dev" command combines fix + test for quick feedback
make dev

# Use this frequently during development
# - Auto-fixes formatting and import issues
# - Runs tests to catch bugs early
# - Takes ~30 seconds vs ~3 minutes for full quality check
```

### **✅ Before Commit**

```bash
# Run pre-push checks locally
make pre-push

# This runs:
# 1. make quality (linting, type checking, security, complexity)
# 2. make security (additional security scanning)
# 3. make test (comprehensive test suite)
```

**If all checks pass, commit will work automatically** (pre-commit hooks run during commit).

```bash
git add .
git commit -m "feat: add your feature description"
```

### **🚀 Before Push**

```bash
# Final comprehensive check
make ci

# Push your feature branch
git push origin feature/your-feature-name
```

### **🔄 End of Day**

```bash
# Save your work
git add .
git commit -m "wip: save progress"

# Or merge to main if ready
git checkout main
git merge feature/your-feature-name
git push origin main
```

---

## Common Workflows

### **🐛 Bug Fix Workflow**

```bash
# 1. Create bug fix branch
git checkout -b bugfix/issue-description

# 2. Write failing test first
pytest tests/ -k "test_specific_bug"  # Should fail

# 3. Fix the bug
# ... edit code ...

# 4. Verify fix
pytest tests/ -k "test_specific_bug"  # Should pass

# 5. Run full test suite
make test

# 6. Commit fix
git add .
git commit -m "fix: resolve issue with target registry lookup

- Fix null pointer exception in target discovery
- Add proper null checking for target configuration
- Include test coverage for edge case"
```

### **📚 Documentation Updates**

```bash
# 1. Create documentation branch
git checkout -b docs/update-api-reference

# 2. Update documentation
# ... edit .md files ...

# 3. Check documentation builds (if applicable)
# 4. Commit documentation
git add .
git commit -m "docs: update API reference for v2.0

- Add new container orchestration endpoints
- Update authentication examples
- Fix broken links in quick start guide"
```

### **🛡️ Security Updates**

```bash
# 1. Create security branch
git checkout -b security/update-dependencies

# 2. Run security scans
make security-scan

# 3. Update dependencies
pip install --upgrade package-name

# 4. Re-run security scans
make security-scan

# 5. Test changes
make test

# 6. Commit security update
git add .
git commit -m "security: update dependencies and fix vulnerabilities

- Update requests from 2.28.1 to 2.31.0 (CVE-2023-32681)
- Update cryptography from 3.4.8 to 41.0.3
- Add security test coverage for credential handling"
```

### **🚀 Feature Development Workflow**

```bash
# 1. Plan your feature
# - Write user stories
# - Design API changes
# - Plan test coverage

# 2. Create feature branch
git checkout -b feature/container-management

# 3. Write tests first (TDD approach)
# Create test files for new functionality
pytest tests/test_container_management.py  # Should fail initially

# 4. Implement feature incrementally
# - Start with basic functionality
# - Add tests as you go
# - Run make dev frequently

# 5. When feature is complete, run comprehensive checks
make pre-push

# 6. Commit with clear description
git add .
git commit -m "feat: add container management capabilities

- Implement Docker container lifecycle management
- Add container health monitoring
- Support container orchestration across targets
- Include comprehensive test coverage (95%)
- Update API documentation

Closes: #123"
```

### **🔄 Refactoring Workflow**

```bash
# 1. Create refactoring branch
git checkout -b refactor/simplify-target-registry

# 2. Write tests that cover existing functionality
pytest tests/test_target_registry.py  # Should pass

# 3. Refactor incrementally
# - Make small, testable changes
# - Run tests after each change
# - Keep commits focused and atomic

# 4. Validate no regressions
make test

# 5. Check performance impact
make complexity

# 6. Commit refactoring
git add .
git commit -m "refactor: simplify target registry implementation

- Replace O(n²) lookup with O(n) dictionary access
- Reduce code complexity from rank C to rank A
- Improve maintainability score from 67 to 89
- No functional changes, only internal improvements
- All existing tests pass"
```

---

## Troubleshooting

### **🚨 Common Setup Issues**

#### **Issue: Python version too old**

```bash
# Error: Python 3.12+ required
python3 --version  # Shows Python 3.10.x
```

**Solutions**:
```bash
# Option 1: Install newer Python
# Ubuntu/Debian:
sudo apt update && sudo apt install python3.12 python3.12-venv

# macOS:
brew install python@3.12

# Option 2: Use pyenv (recommended)
curl https://pyenv.run | bash
pyenv install 3.12.0
pyenv local 3.12.0

# Option 3: Use docker
docker run --rm -it python:3.12 bash
```

#### **Issue: Virtual environment creation fails**

```bash
# Error: python3 -m venv venv fails
```

**Solutions**:
```bash
# Install python3-venv
sudo apt install python3-12 python3.12-dev python3.12-venv

# Or use alternative virtual environment tools
pip install virtualenv
virtualenv venv
source venv/bin/activate
```

#### **Issue: Pre-commit hooks fail**

```bash
# Error: pre-commit install fails or hooks fail during commit
```

**Solutions**:
```bash
# Reinstall pre-commit
pip install --upgrade pre-commit
pre-commit uninstall
pre-commit install

# Update hooks to latest versions
pre-commit autoupdate

# Run hooks on all files to set up environment
pre-commit run --all-files

# Skip hooks temporarily (not recommended)
git commit --no-verify
```

#### **Issue: Import errors during development**

```bash
# Error: ModuleNotFoundError: No module named 'src'
```

**Solutions**:
```bash
# Ensure project is installed in development mode
pip install -e .

# Set PYTHONPATH
export PYTHONPATH="${PYTHONPATH}:$(pwd)/src"

# Or run from project root
python -m pytest tests/
```

### **🔧 Development Workflow Issues**

#### **Issue: Tests fail after making changes**

```bash
# Error: pytest tests fail with new changes
```

**Debugging approach**:
```bash
# 1. Run specific failing test
pytest tests/test_specific.py::test_function -v -s

# 2. Run with debugger
pytest tests/test_specific.py::test_function --pdb

# 3. Check for import issues
python -c "import src; print('Import successful')"

# 4. Verify virtual environment is activated
which python  # Should show venv/bin/python

# 5. Reinstall dependencies
pip install -r requirements-dev.txt
```

#### **Issue: Quality checks take too long**

```bash
# Error: make quality takes several minutes
```

**Performance optimization**:
```bash
# Use faster development workflow
make dev  # Only fix + test (~30 seconds)

# Run specific checks
make lint          # Only ruff (~10 seconds)
make typecheck     # Only mypy (~20 seconds)
make test-fast     # Tests without coverage

# Use parallel execution
pytest tests/ -n auto
```

#### **Issue: IDE not recognizing virtual environment**

**VS Code**:
```json
// .vscode/settings.json
{
  "python.defaultInterpreterPath": "./venv/bin/python"
}
```

**PyCharm**:
1. File → Settings → Project → Python Interpreter
2. Click gear icon → Add
3. Select existing environment: `./venv/bin/python`

**Command line**:
```bash
# Verify virtual environment
which python  # Should show: ./venv/bin/python
pip list      # Should show development packages
```

### **🐛 Runtime Issues**

#### **Issue: "command not found" for development tools**

```bash
# Error: ruff: command not found
```

**Solutions**:
```bash
# Ensure virtual environment is activated
source venv/bin/activate

# Verify tool installation
which ruff
pip list | grep ruff

# Reinstall if needed
pip install ruff

# Use full path as fallback
./venv/bin/ruff check src
```

#### **Issue: Configuration file not found**

```bash
# Error: pyproject.toml not found or parsing errors
```

**Solutions**:
```bash
# Run from project root
cd /path/to/TailOpsMCP

# Check configuration files exist
ls -la pyproject.toml
ls -la .pre-commit-config.yaml

# Validate TOML syntax
python -c "import tomllib; tomllib.load(open('pyproject.toml', 'rb'))"

# Check for encoding issues
file pyproject.toml  # Should show: UTF-8
```

#### **Issue: Permission errors**

```bash
# Error: Permission denied when running scripts
```

**Solutions**:
```bash
# Make scripts executable
chmod +x scripts/*.sh

# Fix file permissions
chmod -R u+w .
chmod -R u+x scripts/

# Check ownership
ls -la
sudo chown -R $USER:$USER .
```

### **💡 Getting Help**

#### **Documentation**
- **Code Quality**: [CODE_QUALITY.md](CODE_QUALITY.md)
- **Tools Reference**: [QUALITY_TOOLS_REFERENCE.md](QUALITY_TOOLS_REFERENCE.md)
- **Project README**: [README.md](README.md)

#### **Command Help**
```bash
make help           # Show all available commands
ruff --help         # Ruff linter help
mypy --help         # MyPy type checker help
pytest --help       # Testing framework help
```

#### **Log Files**
Check these locations for detailed error information:
- **Test output**: Terminal output from pytest
- **Quality reports**: `quality-reports/` directory
- **Security reports**: `security-report.json`
- **Coverage reports**: `htmlcov/index.html`

#### **Community Support**
- **GitHub Issues**: [Report bugs or request features](https://github.com/mdlmarkham/TailOpsMCP/issues)
- **GitHub Discussions**: [Ask questions and share ideas](https://github.com/mdlmarkham/TailOpsMCP/discussions)
- **Documentation**: Check existing documentation first

### **🔄 Reset Development Environment**

If you need to start fresh:

```bash
# Option 1: Clean reinstall (preserves changes)
deactivate  # Exit virtual environment
rm -rf venv
make setup

# Option 2: Complete reset (removes all changes)
git clean -fdx
git checkout .
make setup

# Option 3: Reset specific tools
pip uninstall -r requirements-dev.txt -y
pip install -r requirements-dev.txt
pre-commit uninstall
pre-commit install
```

This setup guide should get you productive with TailOpsMCP development quickly. The combination of automated setup, quality tools, and comprehensive workflows ensures a smooth development experience from day one.