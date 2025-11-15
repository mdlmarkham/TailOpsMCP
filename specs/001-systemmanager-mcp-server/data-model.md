# Data Model: SystemManager MCP Server

**Date**: 2025-11-15  
**Purpose**: Define the core data structures and entities for the MCP server implementation.

## Core Entities

### SystemStatus
Represents the current health and performance metrics of the system.

```python
class SystemStatus:
    cpu_usage: float  # Percentage (0-100)
    memory_usage: float  # Percentage (0-100)
    memory_total: int  # Bytes
    memory_available: int  # Bytes
    disk_usage: Dict[str, float]  # Mount point -> usage percentage
    load_average: Tuple[float, float, float]  # 1, 5, 15 minute averages
    uptime: int  # Seconds
    timestamp: datetime
```

### ContainerInfo
Represents a Docker container's state and configuration.

```python
class ContainerInfo:
    id: str
    name: str
    image: str
    status: str  # running, stopped, paused, etc.
    created: datetime
    ports: List[Dict[str, str]]  # Port mappings
    environment: Dict[str, str]
    labels: Dict[str, str]
    resource_usage: Dict[str, float]  # CPU, memory usage
```

### FileSystemEntry
Represents a file or directory in the file system.

```python
class FileSystemEntry:
    path: str
    name: str
    type: str  # file, directory, symlink
    size: int  # Bytes (files only)
    permissions: str  # Octal permissions
    owner: str
    group: str
    modified: datetime
    accessed: datetime
```

### NetworkInterface
Represents a network interface and its status.

```python
class NetworkInterface:
    name: str
    status: str  # up, down, unknown
    ip_addresses: List[str]
    mac_address: str
    rx_bytes: int  # Received bytes
    tx_bytes: int  # Transmitted bytes
    speed: int  # Mbps
```

### MCPConnection
Represents an authenticated MCP client session.

```python
class MCPConnection:
    client_id: str
    authenticated: bool
    permissions: List[str]  # Allowed operations
    created: datetime
    last_activity: datetime
    remote_addr: str  # Client address
```

## Tool Schemas

### System Monitoring Tools

#### get_system_status
```json
{
  "name": "get_system_status",
  "description": "Get current system health metrics",
  "inputSchema": {
    "type": "object",
    "properties": {
      "detailed": {
        "type": "boolean",
        "description": "Include detailed metrics"
      }
    }
  }
}
```

#### get_container_list
```json
{
  "name": "get_container_list",
  "description": "List all Docker containers",
  "inputSchema": {
    "type": "object",
    "properties": {
      "all": {
        "type": "boolean",
        "description": "Include stopped containers"
      }
    }
  }
}
```

### File System Tools

#### list_directory
```json
{
  "name": "list_directory",
  "description": "List contents of a directory",
  "inputSchema": {
    "type": "object",
    "properties": {
      "path": {
        "type": "string",
        "description": "Directory path"
      },
      "recursive": {
        "type": "boolean",
        "description": "List recursively"
      }
    },
    "required": ["path"]
  }
}
```

#### search_files
```json
{
  "name": "search_files",
  "description": "Search for files by name or content",
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
  }
}
```

### Network Tools

#### get_network_status
```json
{
  "name": "get_network_status",
  "description": "Get network interface status",
  "inputSchema": {
    "type": "object",
    "properties": {
      "interface": {
        "type": "string",
        "description": "Specific interface name"
      }
    }
  }
}
```

## Configuration Models

### ServerConfig
Main server configuration.

```python
class ServerConfig:
    host: str = "localhost"
    port: int = 8080
    transport: str = "stdio"  # stdio, http-sse
    auth_required: bool = True
    max_connections: int = 10
    log_level: str = "INFO"
    allowed_paths: List[str]  # File system access restrictions
    docker_socket: str = "/var/run/docker.sock"
```

### SecurityConfig
Security and authentication configuration.

```python
class SecurityConfig:
    auth_tokens: List[str]  # Bearer tokens for authentication
    rate_limit: int = 100  # Requests per minute
    max_file_size: int = 10485760  # 10MB file size limit
    allowed_operations: List[str]  # Whitelist of allowed operations
    audit_log_enabled: bool = True
```

### TailscaleConfig
Tailscale Services configuration.

```python
class TailscaleConfig:
    enabled: bool = False
    service_name: str = "systemmanager-mcp"
    endpoints: Dict[str, str]  # Protocol:port -> local target
    tags: List[str]  # Service tags for access control
    validate_endpoints: bool = True
```

## Error Models

### MCPError
Standardized error responses.

```python
class MCPError:
    code: int
    message: str
    details: Optional[Dict[str, Any]]
    retryable: bool = False
```

### Error Codes
- **1000**: Authentication required
- **1001**: Invalid authentication
- **2000**: Permission denied
- **3000**: System error
- **3001**: Docker daemon unavailable
- **4000**: Invalid input
- **4001**: Resource not found
- **5000**: Rate limit exceeded

## API Response Models

### Standard Response
```python
class MCPResponse:
    success: bool
    data: Optional[Any]
    error: Optional[MCPError]
    timestamp: datetime
```

### Paginated Response
```python
class PaginatedResponse:
    items: List[Any]
    total: int
    page: int
    page_size: int
    has_more: bool
```

This data model provides the foundation for implementing the MCP server with clear, type-safe data structures that align with the MCP protocol and project requirements.