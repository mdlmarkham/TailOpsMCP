from enum import Enum

class ValidationMode(Enum):
    """Validation modes for policy enforcement."""
    STRICT = "strict"        # Reject invalid operations
    WARN = "warn"           # Warn but allow invalid operations
    DRY_RUN = "dry_run"     # Simulate without executing
    PERMISSIVE = "permissive"  # Allow with minimal validation