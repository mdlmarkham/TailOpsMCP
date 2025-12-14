"""
Secure logging initialization with production hardening and sensitive data redaction.
"""

import logging
import os
import sys
import re
from typing import Optional


class SecureLogFormatter(logging.Formatter):
    """Secure log formatter with sensitive data redaction."""
    
    # Patterns for sensitive data that should be redacted
    SENSITIVE_PATTERNS = [
        (re.compile(r'(?i)(password\s*[:=]\s*)([^\s,}]+)', re.IGNORECASE), r'\1<REDACTED>'),
        (re.compile(r'(?i)(secret\s*[:=]\s*)([^\s,}]+)', re.IGNORECASE), r'\1<REDACTED>'),
        (re.compile(r'(?i)(token\s*[:=]\s*)([^\s,}]+)', re.IGNORECASE), r'\1<REDACTED>'),
        (re.compile(r'(?i)(key\s*[:=]\s*)([^\s,}]+)', re.IGNORECASE), r'\1<REDACTED>'),
        (re.compile(r'(?i)(auth\s*[:=]\s*)([^\s,}]+)', re.IGNORECASE), r'\1<REDACTED>'),
        (re.compile(r'([A-Za-z0-9+/]{40,}={0,2})', re.IGNORECASE), '<REDACTED_B64>'),  # Base64 tokens
        (re.compile(r'([A-Fa-f0-9]{32,})', re.IGNORECASE), '<REDACTED_HEX>'),  # Hex hashes/tokens
        (re.compile(r'(\${[^}]+})', re.IGNORECASE), '<REDACTED_VAR>'),  # Environment variables
    ]
    
    # Common sensitive paths and patterns
    SENSITIVE_PATHS = [
        '/etc/shadow', '/etc/passwd', '/etc/sudoers', '/root', 
        '/home/*/.ssh', '/var/log/*', '/tmp/*', '/proc/*', '/sys/*'
    ]
    
    def __init__(self, environment: str = "production"):
        """Initialize secure formatter with environment-specific settings.
        
        Args:
            environment: Environment type (production, development, testing)
        """
        super().__init__()
        self.environment = environment
        
        # Set format based on environment
        if environment == "production":
            # Minimal format for production - no debug info
            self.FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        else:
            # Detailed format for development/testing
            self.FORMAT = '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record with sensitive data redaction."""
        try:
            # Apply base formatting
            formatted = super().format(record)
            
            # Redact sensitive information
            redacted = self._redact_sensitive_data(formatted)
            
            return redacted
            
        except Exception as e:
            # If formatting fails, return safe fallback
            return f"LOG_ERROR: {str(e)}"
    
    def _redact_sensitive_data(self, text: str) -> str:
        """Redact sensitive data from log text."""
        redacted = text
        
        # Apply sensitive pattern redactions
        for pattern, replacement in self.SENSITIVE_PATTERNS:
            redacted = pattern.sub(replacement, redacted)
        
        # Redact file paths that might contain sensitive information
        for sensitive_path in self.SENSITIVE_PATHS:
            if sensitive_path in redacted:
                redacted = redacted.replace(sensitive_path, '<REDACTED_PATH>')
        
        return redacted


def setup_secure_logging(environment: Optional[str] = None) -> None:
    """Set up secure logging configuration with production hardening.
    
    Args:
        environment: Environment type (production, development, testing)
    """
    if environment is None:
        environment = os.getenv("SYSTEMMANAGER_ENV", "production").lower()
    
    # Root logger configuration
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO if environment == "production" else logging.DEBUG)
    
    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Create secure formatter
    formatter = SecureLogFormatter(environment)
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.INFO if environment == "production" else logging.DEBUG)
    root_logger.addHandler(console_handler)
    
    # File handler for production environments
    if environment == "production":
        try:
            log_dir = os.getenv("SYSTEMMANAGER_LOG_DIR", "/var/log/systemmanager")
            os.makedirs(log_dir, exist_ok=True)
            
            file_handler = logging.FileHandler(os.path.join(log_dir, "systemmanager.log"))
            file_handler.setFormatter(formatter)
            file_handler.setLevel(logging.INFO)
            root_logger.addHandler(file_handler)
            
            # Error file handler
            error_handler = logging.FileHandler(os.path.join(log_dir, "systemmanager-errors.log"))
            error_handler.setFormatter(formatter)
            error_handler.setLevel(logging.ERROR)
            root_logger.addHandler(error_handler)
            
        except Exception as e:
            root_logger.warning(f"Could not set up file logging: {str(e)}")
    
    # Environment-specific configurations
    if environment == "production":
        # Production: Disable debug logging completely and prevent exposure
        logging.getLogger("fastmcp.server.auth").setLevel(logging.INFO)
        logging.getLogger("fastmcp.server.auth").propagate = False
        
        # Reduce noise from third-party libraries
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        logging.getLogger("requests").setLevel(logging.WARNING)
        
        # Disable potentially sensitive debug logging
        logging.getLogger("paramiko").setLevel(logging.WARNING)
        logging.getLogger("docker").setLevel(logging.WARNING)
        
    elif environment == "development":
        # Development: Enable debug logging with safeguards
        logging.getLogger("fastmcp.server.auth").setLevel(logging.DEBUG)
        logging.getLogger("fastmcp.server.auth").propagate = True
        
        # Enable debug for relevant components
        logging.getLogger("src").setLevel(logging.DEBUG)
    
    # Security logging configuration
    _setup_security_logging(environment)


def _setup_security_logging(environment: str) -> None:
    """Set up security-specific logging configuration."""
    # Security logger
    security_logger = logging.getLogger("security")
    security_logger.setLevel(logging.INFO)
    
    # Ensure security events are always logged
    if not any(isinstance(h, logging.FileHandler) for h in security_logger.handlers):
        try:
            log_dir = os.getenv("SYSTEMMANAGER_LOG_DIR", "/var/log/systemmanager")
            os.makedirs(log_dir, exist_ok=True)
            
            security_handler = logging.FileHandler(os.path.join(log_dir, "security.log"))
            security_formatter = SecureLogFormatter(environment)
            security_handler.setFormatter(security_formatter)
            security_handler.setLevel(logging.INFO)
            security_logger.addHandler(security_handler)
            
            # Prevent propagation to avoid duplicate logs
            security_logger.propagate = False
            
        except Exception as e:
            logging.getLogger(__name__).warning(f"Could not set up security logging: {str(e)}")