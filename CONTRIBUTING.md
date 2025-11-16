# Contributing to TailOpsMCP

Thank you for your interest in contributing to TailOpsMCP! We welcome contributions from the home lab community.

## 🎯 Ways to Contribute

### 1. Report Bugs
- Check [existing issues](https://github.com/mdlmarkham/TailOpsMCP/issues) first
- Use the bug report template
- Include system details (OS, Python version, Docker version)
- Provide logs: `journalctl -u systemmanager-mcp -n 100`

### 2. Suggest Features
- Open a [feature request](https://github.com/mdlmarkham/TailOpsMCP/issues/new)
- Explain the use case and benefit
- Link to examples if applicable
- Consider contributing the implementation!

### 3. Improve Documentation
- Fix typos and clarify confusing sections
- Add examples and use cases
- Translate documentation
- Write tutorials and guides

### 4. Contribute Code
- See [Development Setup](#development-setup) below
- Pick an issue labeled `good-first-issue` or `help-wanted`
- Follow the [pull request process](#pull-request-process)

### 5. Share Your Setup
- Write blog posts or create videos
- Share your configuration and automations
- Join discussions in [GitHub Discussions](https://github.com/mdlmarkham/TailOpsMCP/discussions)

---

## 🛠️ Development Setup

### Local Development

```bash
# 1. Fork and clone the repository
git clone https://github.com/YOUR-USERNAME/TailOpsMCP.git
cd TailOpsMCP

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt  # Development tools

# 4. Install pre-commit hooks
pre-commit install

# 5. Run tests
pytest

# 6. Run server in development mode
export SYSTEMMANAGER_AUTH_MODE=token
export SYSTEMMANAGER_SHARED_SECRET=dev-secret-token
export SYSTEMMANAGER_REQUIRE_AUTH=false  # For local testing
python -m src.mcp_server
```

### Testing in Proxmox LXC

```bash
# Create test LXC
pct create 999 local:vztmpl/debian-12-standard_12.0-1_amd64.tar.zst \
  --hostname systemmanager-dev \
  --memory 2048 \
  --cores 2 \
  --net0 name=eth0,bridge=vmbr0,ip=dhcp \
  --features nesting=1,keyctl=1 \
  --unprivileged 1

# Start and enter container
pct start 999
pct enter 999

# Clone your fork and test
git clone https://github.com/YOUR-USERNAME/TailOpsMCP.git
cd TailOpsMCP
bash install.sh
```

---

## 📝 Code Style

### Python Code

We follow [PEP 8](https://pep8.org/) with some modifications:

- **Line length**: 100 characters (not 79)
- **Type hints**: Required for all public functions
- **Docstrings**: Google style for all public classes/methods
- **Formatting**: Use `black` for automatic formatting

```python
from typing import Optional

def get_system_status(format: str = "json") -> dict:
    """Get comprehensive system status.
    
    Args:
        format: Output format ('json' or 'toon')
        
    Returns:
        Dictionary containing system metrics
        
    Raises:
        ValueError: If format is invalid
    """
    if format not in ("json", "toon"):
        raise ValueError(f"Invalid format: {format}")
    
    return {"cpu": 45.2, "memory": 62.1}
```

### MCP Tool Definitions

- **Names**: Use snake_case (e.g., `get_system_status`)
- **Descriptions**: Clear, concise, under 100 characters
- **Parameters**: Use Pydantic models for validation
- **Returns**: Always include type hints and descriptions

```python
@mcp.tool()
def ping_host(
    host: str,
    count: int = 4,
    format: str = "json"
) -> dict:
    """Ping a host and return latency statistics.
    
    Args:
        host: Hostname or IP address
        count: Number of ping packets (default: 4)
        format: Response format ('json' or 'toon')
    """
    # Implementation
```

### Testing

- Write tests for all new features
- Aim for >80% code coverage
- Use pytest fixtures for common setup

```python
def test_get_system_status():
    result = get_system_status(format="json")
    assert "cpu" in result
    assert isinstance(result["cpu"], float)
```

---

## 🔄 Pull Request Process

### 1. Create Feature Branch

```bash
git checkout -b feature/amazing-feature
# Or: git checkout -b fix/bug-description
```

### 2. Make Changes

- Write clear, focused commits
- Follow conventional commits format:
  ```
  feat: Add Docker Compose stack management
  fix: Resolve OAuth token expiration issue
  docs: Update installation instructions
  test: Add tests for network diagnostics
  ```

### 3. Run Tests and Checks

```bash
# Format code
black src/ tests/

# Type checking
mypy src/

# Linting
flake8 src/ tests/

# Tests
pytest

# All checks at once
pre-commit run --all-files
```

### 4. Push and Create PR

```bash
git push origin feature/amazing-feature
```

Then:
1. Go to GitHub and create a Pull Request
2. Fill out the PR template completely
3. Link related issues (e.g., "Fixes #123")
4. Wait for CI checks to pass
5. Request review from maintainers

### 5. Address Review Feedback

- Be responsive to comments
- Make requested changes in new commits
- Don't force-push after review starts
- Update PR description if scope changes

---

## 🏷️ Issue Labels

| Label | Description |
|-------|-------------|
| `bug` | Something isn't working |
| `enhancement` | New feature or request |
| `good-first-issue` | Good for newcomers |
| `help-wanted` | Extra attention needed |
| `documentation` | Improvements to docs |
| `security` | Security-related issue |
| `proxmox` | Proxmox-specific feature |
| `docker` | Docker-related feature |
| `tailscale` | Tailscale integration |

---

## 📋 Roadmap Priorities

Check [HOMELAB_FEATURES.md](./HOMELAB_FEATURES.md) for the full roadmap.

### High Priority (Help Wanted!)

1. **Docker Compose Stack Management**
   - Deploy stacks from GitHub repos
   - Update stacks (git pull + redeploy)
   - Environment variable management

2. **Systemd Service Management**
   - Start/stop/restart services
   - Enable/disable auto-start
   - View service status and logs

3. **LXC Network Auditing**
   - Scan container network configuration
   - Detect security issues
   - Recommend fixes

### Medium Priority

4. **Proxmox API Integration**
   - VM/CT lifecycle management
   - Resource monitoring
   - Snapshot management

5. **Backup Automation**
   - Scheduled backups
   - Verification and testing
   - Off-site replication

---

## 🧪 Testing Guidelines

### Unit Tests

```python
# tests/test_network_status.py
import pytest
from src.services.network_status import ping_host

def test_ping_localhost():
    result = ping_host("127.0.0.1", count=1)
    assert result["host"] == "127.0.0.1"
    assert result["packets_sent"] == 1
    assert result["packet_loss"] < 100

@pytest.mark.integration
def test_ping_external():
    result = ping_host("1.1.1.1", count=2)
    assert result["avg_latency"] > 0
```

### Integration Tests

```python
# tests/test_docker_manager.py
import pytest
from src.services.docker_manager import get_container_list

@pytest.mark.integration
@pytest.mark.requires_docker
def test_get_container_list():
    containers = get_container_list()
    assert isinstance(containers, list)
```

### Running Tests

```bash
# All tests
pytest

# Specific test file
pytest tests/test_network_status.py

# With coverage
pytest --cov=src --cov-report=html

# Skip integration tests (faster)
pytest -m "not integration"

# Only integration tests
pytest -m integration
```

---

## 🔒 Security

### Reporting Vulnerabilities

**DO NOT** open a public issue for security vulnerabilities.

Instead:
1. Email: security@tailopsmcp.dev (or create a private security advisory)
2. Include detailed description
3. Provide steps to reproduce
4. Suggest a fix if possible

We will respond within 48 hours.

### Security Best Practices

When contributing code:
- Never hardcode secrets or credentials
- Validate all user inputs
- Use parameterized queries (if adding database features)
- Follow principle of least privilege
- Log security-relevant events

---

## 📄 License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

## 💬 Communication

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: Questions, ideas, and general discussion
- **Pull Requests**: Code contributions
- **Discord** (coming soon): Real-time chat

---

## 🙏 Recognition

Contributors are recognized in:
- README.md acknowledgments section
- Release notes for their contributions
- GitHub contributor stats

Thank you for helping make TailOpsMCP better for the home lab community! 🚀
