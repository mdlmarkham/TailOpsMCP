# TailOpsMCP Development Makefile
# Comprehensive development automation and quality checks

.PHONY: help setup lint format typecheck security complexity quality fix test test-verbose clean docs install-deps pre-commit

# Default target
.DEFAULT_GOAL := help

# Configuration
PYTHON := python3
PIP := pip3
PROJECT_ROOT := .
SRC_DIR := src
TEST_DIR := tests

# Colors for output
BOLD := \033[1m
RED := \033[31m
GREEN := \033[32m
YELLOW := \033[33m
BLUE := \033[34m
RESET := \033[0m

# Help target
help: ## Show this help message
	@echo "$(BOLD)TailOpsMCP Development Commands$(RESET)"
	@echo ""
	@echo "$(BOLD)Setup & Installation:$(RESET)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | grep -E 'setup|install|pre-commit' | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-15s$(RESET) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(BOLD)Quality Checks:$(RESET)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | grep -E 'lint|format|typecheck|security|complexity' | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-15s$(RESET) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(BOLD)Convenience Commands:$(RESET)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | grep -E 'fix|quality|test|clean' | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-15s$(RESET) %s\n", $$1, $$2}'

# Setup & Installation
setup: ## Set up complete development environment
	@echo "$(BLUE)Setting up TailOpsMCP development environment...$(RESET)"
	@$(PIP) install -r requirements-dev.txt
	@$(PIP) install -e .
	@$(MAKE) pre-commit
	@echo "$(GREEN)Development environment setup complete!$(RESET)"

install-deps: ## Install all dependencies (including dev dependencies)
	@echo "$(BLUE)Installing dependencies...$(RESET)"
	@$(PIP) install -r requirements-dev.txt
	@$(PIP) install -e .
	@echo "$(GREEN)Dependencies installed successfully!$(RESET)"

pre-commit: ## Set up pre-commit hooks
	@echo "$(BLUE)Setting up pre-commit hooks...$(RESET)"
	@pre-commit install
	@echo "$(GREEN)Pre-commit hooks installed!$(RESET)"

# Code Quality Checks
lint: ## Run ruff lint on src/ and tests/
	@echo "$(BLUE)Running ruff lint...$(RESET)"
	@ruff check $(SRC_DIR) $(TEST_DIR)
	@echo "$(GREEN)Linting completed!$(RESET)"

format: ## Run ruff format and isort on src/ and tests/
	@echo "$(BLUE)Formatting code...$(RESET)"
	@ruff format $(SRC_DIR) $(TEST_DIR)
	@isort $(SRC_DIR) $(TEST_DIR)
	@echo "$(GREEN)Code formatted successfully!$(RESET)"

typecheck: ## Run mypy type checking on src/
	@echo "$(BLUE)Running type checks...$(RESET)"
	@mypy $(SRC_DIR) --ignore-missing-imports --show-error-codes
	@echo "$(GREEN)Type checking completed!$(RESET)"

security: ## Run security scans (bandit and safety)
	@echo "$(BLUE)Running security scans...$(RESET)"
	@$(PYTHON) scripts/run_bandit.py -r $(SRC_DIR) -f json -o security-report.json || true
	@safety check --json --output safety-report.json || true
	@echo "$(GREEN)Security scanning completed!$(RESET)"
	@echo "$(YELLOW)Reports saved: security-report.json, safety-report.json$(RESET)"

complexity: ## Run complexity analysis using radon
	@echo "$(BLUE)Running complexity analysis...$(RESET)"
	@radon cc $(SRC_DIR) --json > complexity-report.json || true
	@radon mi $(SRC_DIR) > maintainability-report.txt || true
	@echo "$(GREEN)Complexity analysis completed!$(RESET)"
	@echo "$(YELLOW)Reports saved: complexity-report.json, maintainability-report.txt$(RESET)"

# Comprehensive Quality Checks
quality: lint typecheck security complexity ## Run all quality checks
	@echo "$(GREEN)All quality checks completed!$(RESET)"

fix: ## Auto-fix code issues with ruff and isort
	@echo "$(BLUE)Auto-fixing code issues...$(RESET)"
	@ruff check --fix $(SRC_DIR) $(TEST_DIR)
	@ruff format $(SRC_DIR) $(TEST_DIR)
	@isort --profile black $(SRC_DIR) $(TEST_DIR)
	@echo "$(GREEN)Code issues auto-fixed!$(RESET)"

# Testing
test: ## Run pytest with coverage
	@echo "$(BLUE)Running tests with coverage...$(RESET)"
	@pytest $(TEST_DIR) -v --cov=$(SRC_DIR) --cov-report=html --cov-report=term-missing
	@echo "$(GREEN)Tests completed!$(RESET)"
	@echo "$(YELLOW)Coverage report generated in htmlcov/index.html$(RESET)"

test-verbose: ## Run tests with verbose output
	@echo "$(BLUE)Running tests with verbose output...$(RESET)"
	@pytest $(TEST_DIR) -v --tb=short --durations=10
	@echo "$(GREEN)Tests completed!$(RESET)"

test-fast: ## Run tests without coverage (faster)
	@echo "$(BLUE)Running fast tests...$(RESET)"
	@pytest $(TEST_DIR) -x -q
	@echo "$(GREEN)Fast tests completed!$(RESET)"

# Security scanning using custom scanner
security-scan: ## Run comprehensive security scan using custom scanner
	@echo "$(BLUE)Running comprehensive security scan...$(RESET)"
	@$(PYTHON) scripts/scan.py --full
	@echo "$(GREEN)Security scan completed!$(RESET)"

security-quick: ## Run quick security scan
	@echo "$(BLUE)Running quick security scan...$(RESET)"
	@$(PYTHON) scripts/scan.py --quick
	@echo "$(GREEN)Quick security scan completed!$(RESET)"

# Development workflow targets
dev: fix test ## Quick development workflow: fix code and run tests
	@echo "$(GREEN)Development workflow completed!$(RESET)"

ci: quality test ## CI pipeline: run all quality checks and tests
	@echo "$(GREEN)CI pipeline completed!$(RESET)"

pre-push: quality security test ## Run before pushing to repository
	@echo "$(GREEN)Pre-push checks completed!$(RESET)"

# Documentation
docs: ## Generate documentation (placeholder for future docs tool)
	@echo "$(YELLOW)Documentation generation not yet implemented$(RESET)"
	@echo "Consider using: sphinx, mkdocs, or pydoc"

# Cleaning
clean: ## Clean up generated files and caches
	@echo "$(BLUE)Cleaning up...$(RESET)"
	@find . -type f -name "*.pyc" -delete
	@find . -type d -name "__pycache__" -delete
	@find . -type d -name "*.egg-info" -exec rm -rf {} +
	@rm -rf build/
	@rm -rf dist/
	@rm -rf .coverage
	@rm -rf htmlcov/
	@rm -rf .pytest_cache/
	@rm -rf .mypy_cache/
	@rm -rf .ruff_cache/
	@rm -f *.log
	@rm -f security-report.json
	@rm -f safety-report.json
	@rm -f complexity-report.json
	@rm -f maintainability-report.txt
	@echo "$(GREEN)Cleanup completed!$(RESET)"

# Development server (if applicable)
serve: ## Start development server (if applicable)
	@echo "$(YELLOW)Development server not configured$(RESET)"

# Docker commands (if Docker is available)
docker-build: ## Build Docker image (if Dockerfile exists)
	@if [ -f "Dockerfile" ]; then \
		echo "$(BLUE)Building Docker image...$(RESET)"; \
		docker build -t tailopsmcp:latest .; \
		echo "$(GREEN)Docker image built successfully!$(RESET)"; \
	else \
		echo "$(YELLOW)Dockerfile not found$(RESET)"; \
	fi

docker-test: ## Run tests in Docker container
	@if [ -f "Dockerfile" ]; then \
		echo "$(BLUE)Running tests in Docker...$(RESET)"; \
		docker run --rm -v $$(pwd):/app tailopsmcp:latest make test; \
		echo "$(GREEN)Docker tests completed!$(RESET)"; \
	else \
		echo "$(YELLOW)Dockerfile not found$(RESET)"; \
	fi

# Version and info targets
version: ## Show project version
	@$(PYTHON) -c "import src; print('TailOpsMCP version:', getattr(src, '__version__', '1.0.0'))"

info: ## Show project information
	@echo "$(BOLD)TailOpsMCP Project Information$(RESET)"
	@echo "Python version: $(shell $(PYTHON) --version)"
	@echo "Project root: $(PROJECT_ROOT)"
	@echo "Source directory: $(SRC_DIR)"
	@echo "Test directory: $(TEST_DIR)"
	@echo "Development dependencies installed: $(shell $(PIP) list | grep -E 'pytest|ruff|mypy|bandit' | wc -l) packages"
