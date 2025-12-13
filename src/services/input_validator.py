"""
Input Validation and Allowlisting System

Provides robust validation for all capability parameters to prevent command injection
and "typo hazards" through comprehensive parameter validation.
"""

import os
import re
import time
from typing import Any, Dict, List, Optional, Set, Tuple
from enum import Enum
from dataclasses import dataclass
from pathlib import Path

from src.utils.errors import SystemManagerError


class ValidationMode(str, Enum):
    """Validation modes for parameter validation."""
    STRICT = "strict"        # Reject invalid parameters
    WARN = "warn"           # Warn but allow invalid parameters
    PERMISSIVE = "permissive" # Allow with minimal validation


class ParameterType(str, Enum):
    """Supported parameter types for validation."""
    SERVICE_NAME = "service_name"
    CONTAINER_NAME = "container_name"
    STACK_NAME = "stack_name"
    FILE_PATH = "file_path"
    PORT_NUMBER = "port_number"
    TIMEOUT = "timeout"
    OUTPUT_LIMIT = "output_limit"
    HOSTNAME = "hostname"
    IP_ADDRESS = "ip_address"
    URL = "url"


@dataclass
class ValidationRule:
    """Individual validation rule definition."""
    parameter_type: ParameterType
    pattern: Optional[str] = None
    min_value: Optional[int] = None
    max_value: Optional[int] = None
    allowed_values: Optional[List[str]] = None
    allowlist_source: Optional[str] = None  # Discovery tool to populate allowlist
    max_length: Optional[int] = None
    min_length: Optional[int] = None


@dataclass
class AllowlistEntry:
    """Allowlist entry with metadata."""
    value: str
    source: str  # Discovery tool that found this value
    discovered_at: float  # Timestamp
    expires_at: Optional[float] = None  # Optional TTL


class AllowlistManager:
    """Manage allowlists for parameter validation with caching."""
    
    def __init__(self, cache_ttl: int = 300):  # 5 minutes default TTL
        self._allowlists: Dict[str, Dict[str, AllowlistEntry]] = {}
        self._cache_ttl = cache_ttl
        self._discovery_tools = {}
    
    def register_discovery_tool(self, name: str, tool_func):
        """Register a discovery tool for populating allowlists."""
        self._discovery_tools[name] = tool_func
    
    async def populate_allowlist(self, allowlist_name: str, target: str) -> List[str]:
        """Populate an allowlist using discovery tools."""
        if allowlist_name not in self._discovery_tools:
            raise SystemManagerError(f"No discovery tool registered for {allowlist_name}")
        
        tool_func = self._discovery_tools[allowlist_name]
        try:
            result = await tool_func(target)
            if isinstance(result, dict) and "data" in result:
                values = result["data"]
            elif isinstance(result, list):
                values = result
            else:
                values = []
            
            # Update allowlist
            current_time = time.time()
            expires_at = current_time + self._cache_ttl
            
            if allowlist_name not in self._allowlists:
                self._allowlists[allowlist_name] = {}
            
            for value in values:
                if isinstance(value, dict) and "name" in value:
                    value_str = value["name"]
                elif isinstance(value, str):
                    value_str = value
                else:
                    continue
                
                self._allowlists[allowlist_name][value_str] = AllowlistEntry(
                    value=value_str,
                    source=allowlist_name,
                    discovered_at=current_time,
                    expires_at=expires_at
                )
            
            return [entry.value for entry in self._allowlists[allowlist_name].values()]
            
        except Exception as e:
            raise SystemManagerError(f"Failed to populate allowlist {allowlist_name}: {e}")
    
    def get_allowlist(self, allowlist_name: str) -> List[str]:
        """Get current allowlist values."""
        if allowlist_name not in self._allowlists:
            return []
        
        # Clean expired entries
        current_time = time.time()
        expired_keys = []
        for key, entry in self._allowlists[allowlist_name].items():
            if entry.expires_at and entry.expires_at < current_time:
                expired_keys.append(key)
        
        for key in expired_keys:
            del self._allowlists[allowlist_name][key]
        
        return [entry.value for entry in self._allowlists[allowlist_name].values()]
    
    def is_value_allowed(self, allowlist_name: str, value: str) -> bool:
        """Check if a value is in the allowlist."""
        return value in self.get_allowlist(allowlist_name)


class InputValidator:
    """Comprehensive input validation for all capability parameters."""
    
    def __init__(self, allowlist_manager: AllowlistManager):
        self.allowlist_manager = allowlist_manager
        self._validation_rules = self._build_validation_rules()
    
    def _build_validation_rules(self) -> Dict[ParameterType, ValidationRule]:
        """Build default validation rules."""
        return {
            ParameterType.SERVICE_NAME: ValidationRule(
                parameter_type=ParameterType.SERVICE_NAME,
                pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$",
                max_length=64,
                allowlist_source="list_services"
            ),
            ParameterType.CONTAINER_NAME: ValidationRule(
                parameter_type=ParameterType.CONTAINER_NAME,
                pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$",
                max_length=128,
                allowlist_source="list_containers"
            ),
            ParameterType.STACK_NAME: ValidationRule(
                parameter_type=ParameterType.STACK_NAME,
                pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$",
                max_length=64,
                allowlist_source="list_stacks"
            ),
            ParameterType.FILE_PATH: ValidationRule(
                parameter_type=ParameterType.FILE_PATH,
                pattern=r"^[a-zA-Z0-9./_-]+$",
                max_length=1024
            ),
            ParameterType.PORT_NUMBER: ValidationRule(
                parameter_type=ParameterType.PORT_NUMBER,
                min_value=1,
                max_value=65535
            ),
            ParameterType.TIMEOUT: ValidationRule(
                parameter_type=ParameterType.TIMEOUT,
                min_value=1,
                max_value=3600  # 1 hour max
            ),
            ParameterType.OUTPUT_LIMIT: ValidationRule(
                parameter_type=ParameterType.OUTPUT_LIMIT,
                min_value=1,
                max_value=10485760  # 10MB max
            ),
            ParameterType.HOSTNAME: ValidationRule(
                parameter_type=ParameterType.HOSTNAME,
                pattern=r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$",
                max_length=253
            ),
            ParameterType.IP_ADDRESS: ValidationRule(
                parameter_type=ParameterType.IP_ADDRESS,
                pattern=r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
            ),
            ParameterType.URL: ValidationRule(
                parameter_type=ParameterType.URL,
                pattern=r"^https?://[^\s/$.?#].[^\s]*$",
                max_length=2048
            )
        }
    
    async def validate_parameter(self, param_type: ParameterType, value: Any, 
                               target: Optional[str] = None, 
                               validation_mode: ValidationMode = ValidationMode.STRICT) -> List[str]:
        """Validate a parameter against its type rules."""
        errors = []
        
        if param_type not in self._validation_rules:
            errors.append(f"Unknown parameter type: {param_type}")
            return errors
        
        rule = self._validation_rules[param_type]
        
        # Type conversion and basic validation
        if rule.parameter_type in [ParameterType.PORT_NUMBER, ParameterType.TIMEOUT, ParameterType.OUTPUT_LIMIT]:
            try:
                value = int(value)
            except (ValueError, TypeError):
                errors.append(f"Parameter must be an integer")
                return errors
        else:
            if not isinstance(value, str):
                errors.append(f"Parameter must be a string")
                return errors
        
        # Pattern validation
        if rule.pattern and isinstance(value, str):
            if not re.match(rule.pattern, value):
                errors.append(f"Parameter does not match required pattern")
        
        # Length validation
        if rule.max_length and isinstance(value, str) and len(value) > rule.max_length:
            errors.append(f"Parameter exceeds maximum length of {rule.max_length}")
        
        if rule.min_length and isinstance(value, str) and len(value) < rule.min_length:
            errors.append(f"Parameter below minimum length of {rule.min_length}")
        
        # Range validation
        if rule.min_value is not None and isinstance(value, int) and value < rule.min_value:
            errors.append(f"Parameter below minimum value of {rule.min_value}")
        
        if rule.max_value is not None and isinstance(value, int) and value > rule.max_value:
            errors.append(f"Parameter above maximum value of {rule.max_value}")
        
        # Allowlist validation
        if rule.allowlist_source and target and isinstance(value, str):
            if not self.allowlist_manager.is_value_allowed(rule.allowlist_source, value):
                # Try to populate allowlist and check again
                try:
                    await self.allowlist_manager.populate_allowlist(rule.allowlist_source, target)
                    if not self.allowlist_manager.is_value_allowed(rule.allowlist_source, value):
                        errors.append(f"Parameter value '{value}' not found in {rule.allowlist_source}")
                except SystemManagerError as e:
                    if validation_mode == ValidationMode.STRICT:
                        errors.append(f"Allowlist validation failed: {e}")
                    elif validation_mode == ValidationMode.WARN:
                        errors.append(f"Warning: Allowlist validation failed: {e}")
        
        # File path validation with traversal protection
        if param_type == ParameterType.FILE_PATH and isinstance(value, str):
            errors.extend(self._validate_file_path(value))
        
        return errors
    
    def _validate_file_path(self, path: str) -> List[str]:
        """Validate file path with directory traversal protection."""
        errors = []
        
        # Check for directory traversal attempts
        if ".." in path or path.startswith("/") or "~" in path:
            errors.append("File path contains potential directory traversal")
        
        # Check for dangerous characters
        if any(char in path for char in ['|', ';', '&', '`', '$', '(', ')', '<', '>']):
            errors.append("File path contains dangerous characters")
        
        # Check path length
        if len(path) > 1024:
            errors.append("File path too long")
        
        return errors
    
    async def validate_parameters(self, parameters: Dict[str, Any], 
                                parameter_types: Dict[str, ParameterType],
                                target: Optional[str] = None,
                                validation_mode: ValidationMode = ValidationMode.STRICT) -> Dict[str, List[str]]:
        """Validate multiple parameters against their types."""
        validation_results = {}
        
        for param_name, param_value in parameters.items():
            if param_name not in parameter_types:
                validation_results[param_name] = [f"Unknown parameter: {param_name}"]
                continue
            
            param_type = parameter_types[param_name]
            errors = await self.validate_parameter(param_type, param_value, target, validation_mode)
            validation_results[param_name] = errors
        
        return validation_results