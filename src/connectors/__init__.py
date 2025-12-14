"""
Remote Agent Connectors for TailOpsMCP

Provides agent-like functionality without requiring agent installation on target systems.
Supports comprehensive in-guest management via SSH/Tailscale connections.
"""

from .remote_agent_connector import RemoteAgentConnector
from .journald_connector import JournaldConnector
from .service_connector import ServiceConnector
from .docker_connector import DockerConnector
from .file_connector import FileConnector

__all__ = [
    'RemoteAgentConnector',
    'JournaldConnector',
    'ServiceConnector',
    'DockerConnector',
    'FileConnector'
]