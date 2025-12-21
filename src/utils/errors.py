from enum import Enum


class ErrorCategory(str, Enum):
    SYSTEM = "system"
    VALIDATION = "validation"
    PERMISSION = "permission"
    UNAUTHORIZED = "unauthorized"
    FORBIDDEN = "forbidden"
    CONFIGURATION = "configuration"
    EXECUTION = "execution"


class SystemManagerError(Exception):
    """Custom exception for SystemManager with a category."""

    def __init__(self, message: str, category: ErrorCategory = ErrorCategory.SYSTEM):
        super().__init__(message)
        self.message = message
        self.category = category

    def to_dict(self):
        return {"error": self.message, "category": self.category.value}


class SecurityError(SystemManagerError):
    """Security-related exception for SystemManager."""

    def __init__(self, message: str):
        super().__init__(message, ErrorCategory.PERMISSION)
