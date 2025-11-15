# Data Model: SystemManager MCP Server Improvements

**Date**: 2025-11-15  
**Purpose**: Define structured data models for production-ready MCP server

## **Core Data Models**

### **SystemStatus Model**
```python
from pydantic import BaseModel, Field
from typing import Dict, List, Optional
from datetime import datetime

class CPUStats(BaseModel):
    percent: float = Field(..., ge=0, le=100, description="Overall CPU usage percentage")
    user: float = Field(..., ge=0, description="User CPU time")
    system: float = Field(..., ge=0, description="System CPU time")
    idle: float = Field(..., ge=0, description="Idle CPU time")
    iowait: Optional[float] = Field(None, ge=0, description="I/O wait time")

class MemoryStats(BaseModel):
    total: int = Field(..., ge=0, description="Total memory in bytes")
    available: int = Field(..., ge=0, description="Available memory in bytes")
    used: int = Field(..., ge=0, description="Used memory in bytes")
    percent: float = Field(..., ge=0, le=100, description="Memory usage percentage")
    free: int = Field(..., ge=0, description="Free memory in bytes")

class DiskUsage(BaseModel):
    total: int = Field(..., ge=0, description="Total disk space in bytes")
    used: int = Field(..., ge=0, description="Used disk space in bytes")
    free: int = Field(..., ge=0, description="Free disk space in bytes")
    percent: float = Field(..., ge=0, le=100, description="Disk usage percentage")

class NetworkStats(BaseModel):
    bytes_sent: int = Field(..., ge=0, description="Bytes sent")
    bytes_recv: int = Field(..., ge=0, description="Bytes received")
    packets_sent: int = Field(..., ge=0, description="Packets sent")
    packets_recv: int = Field(..., ge=0, description="Packets received")

class SystemStatus(BaseModel):
    timestamp: datetime = Field(..., description="Status timestamp")
    cpu: CPUStats = Field(..., description="CPU statistics")
    memory: MemoryStats = Field(..., description="Memory statistics")
    disk_usage: Dict[str, DiskUsage] = Field(..., description="Disk usage by mount point")
    network: NetworkStats = Field(..., description="Network statistics")
    load_average: List[float] = Field(..., description="Load average [1min, 5min, 15min]")
    uptime: int = Field(..., ge=0, description="System uptime in seconds")
```

### **Container Models**
```python
class ContainerPort(BaseModel):
    host_port: Optional[int] = Field(None, description="Host port")
    container_port: int = Field(..., description="Container port")
    protocol: str = Field(..., description="Port protocol")

class ContainerInfo(BaseModel):
    id: str = Field(..., description="Container ID")
    name: str = Field(..., description="Container name")
    status: str = Field(..., description="Container status")
    image: str = Field(..., description="Docker image")
    created: datetime = Field(..., description="Creation timestamp")
    ports: List[ContainerPort] = Field(default_factory=list, description="Port mappings")
    environment: Dict[str, str] = Field(default_factory=dict, description="Environment variables")
    labels: Dict[str, str] = Field(default_factory=dict, description="Container labels")
    
class ContainerStats(BaseModel):
    container_id: str = Field(..., description="Container ID")
    cpu_percent: float = Field(..., ge=0, description="CPU usage percentage")
    memory_usage: int = Field(..., ge=0, description="Memory usage in bytes")
    memory_limit: int = Field(..., ge=0, description="Memory limit in bytes")
    network_io: NetworkStats = Field(..., description="Network I/O statistics")
    timestamp: datetime = Field(..., description="Stats timestamp")
```

### **File System Models**
```python
class FileSystemEntry(BaseModel):
    path: str = Field(..., description="Full path")
    name: str = Field(..., description="File/directory name")
    type: str = Field(..., description="Entry type: file, directory, symlink")
    size: int = Field(0, ge=0, description="Size in bytes (files only)")
    permissions: str = Field(..., description="File permissions")
    owner: str = Field(..., description="File owner")
    group: str = Field(..., description="File group")
    modified: datetime = Field(..., description="Last modification time")
    accessed: datetime = Field(..., description="Last access time")
    created: datetime = Field(..., description="Creation time")

class SearchResult(BaseModel):
    path: str = Field(..., description="File path")
    name: str = Field(..., description="File name")
    size: int = Field(..., ge=0, description="File size in bytes")
    modified: datetime = Field(..., description="Last modification time")
    matches: Optional[List[str]] = Field(None, description="Matching content lines")
```

### **Network Models**
```python
class NetworkInterface(BaseModel):
    name: str = Field(..., description="Interface name")
    status: str = Field(..., description="Interface status")
    ip_addresses: List[str] = Field(default_factory=list, description="IP addresses")
    mac_address: Optional[str] = Field(None, description="MAC address")
    speed: Optional[int] = Field(None, description="Interface speed in Mbps")
    mtu: int = Field(..., description="Maximum transmission unit")

class ConnectionInfo(BaseModel):
    protocol: str = Field(..., description="Connection protocol")
    local_address: str = Field(..., description="Local address:port")
    remote_address: Optional[str] = Field(None, description="Remote address:port")
    status: str = Field(..., description="Connection status")
    pid: Optional[int] = Field(None, description="Process ID")
```

### **Security Models**
```python
class AccessToken(BaseModel):
    token: str = Field(..., description="Access token")
    scopes: List[str] = Field(..., description="Token scopes")
    expires_at: Optional[datetime] = Field(None, description="Token expiration")
    user_id: str = Field(..., description="User identifier")

class SecurityContext(BaseModel):
    user_id: str = Field(..., description="Authenticated user")
    scopes: List[str] = Field(..., description="Authorized scopes")
    session_id: str = Field(..., description="Session identifier")
    client_info: Dict[str, str] = Field(default_factory=dict, description="Client information")
```

### **Error Models**
```python
class MCPError(BaseModel):
    code: str = Field(..., description="Error code")
    message: str = Field(..., description="Error message")
    details: Optional[Dict] = Field(None, description="Additional error details")
    retryable: bool = Field(False, description="Whether operation can be retried")

class ErrorResponse(BaseModel):
    success: bool = Field(False, description="Operation status")
    error: MCPError = Field(..., description="Error information")
    timestamp: datetime = Field(..., description="Error timestamp")
```

## **Tool Schemas**

### **System Monitoring Tools**
```json
{
  "get_system_status": {
    "name": "get_system_status",
    "description": "Get comprehensive system health metrics",
    "inputSchema": {
      "type": "object",
      "properties": {
        "detailed": {
          "type": "boolean",
          "description": "Include detailed metrics"
        }
      }
    },
    "outputSchema": {
      "$ref": "#/components/schemas/SystemStatus"
    }
  }
}
```

### **Container Management Tools**
```json
{
  "get_container_list": {
    "name": "get_container_list", 
    "description": "List Docker containers with status information",
    "inputSchema": {
      "type": "object",
      "properties": {
        "show_all": {
          "type": "boolean",
          "description": "Include stopped containers"
        }
      }
    },
    "outputSchema": {
      "type": "array",
      "items": {
        "$ref": "#/components/schemas/ContainerInfo"
      }
    }
  }
}
```

### **File System Tools**
```json
{
  "search_files": {
    "name": "search_files",
    "description": "Search for files by name pattern or content",
    "inputSchema": {
      "type": "object",
      "properties": {
        "pattern": {
          "type": "string",
          "description": "Search pattern (glob or regex)"
        },
        "path": {
          "type": "string", 
          "description": "Base directory for search"
        },
        "max_results": {
          "type": "integer",
          "description": "Maximum number of results"
        }
      },
      "required": ["pattern"]
    },
    "outputSchema": {
      "type": "array",
      "items": {
        "$ref": "#/components/schemas/SearchResult"
      }
    }
  }
}
```

## **Configuration Models**

### **Server Configuration**
```python
class ServerConfig(BaseModel):
    host: str = Field("localhost", description="Server host")
    port: int = Field(8080, description="Server port")
    transport: str = Field("stdio", description="Transport protocol")
    auth_required: bool = Field(True, description="Authentication required")
    rate_limit: int = Field(100, description="Requests per minute")
    max_file_size: int = Field(10485760, description="Maximum file size in bytes")
    
    class Config:
        env_file = ".env"
        case_sensitive = False
```

### **Security Configuration**
```python
class SecurityConfig(BaseModel):
    oauth_issuer: str = Field(..., description="OAuth issuer URL")
    allowed_scopes: List[str] = Field(..., description="Allowed OAuth scopes")
    token_expiration: int = Field(3600, description="Token expiration in seconds")
    require_https: bool = Field(True, description="Require HTTPS")
```

## **Response Models**

### **Standard Response**
```python
class MCPResponse(BaseModel):
    success: bool = Field(..., description="Operation status")
    data: Optional[Any] = Field(None, description="Response data")
    error: Optional[MCPError] = Field(None, description="Error information")
    timestamp: datetime = Field(..., description="Response timestamp")
    request_id: str = Field(..., description="Request identifier")
```

### **Paginated Response**
```python
class PaginatedResponse(BaseModel):
    items: List[Any] = Field(..., description="Page items")
    total: int = Field(..., description="Total items")
    page: int = Field(..., description="Current page")
    page_size: int = Field(..., description="Items per page")
    has_more: bool = Field(..., description="More items available")
    next_cursor: Optional[str] = Field(None, description="Cursor for next page")
```

This data model provides a comprehensive foundation for the SystemManager MCP server with type-safe, validated data structures that align with the MCP protocol and production requirements.