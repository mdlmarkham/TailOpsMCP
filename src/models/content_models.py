"""
Content Models for TailOpsMCP

This module provides content categorization and metadata models for TailOpsMCP operations.
"""

from enum import Enum
from dataclasses import dataclass
from typing import Dict, List, Optional


class ContentCategory(Enum):
    """Content categorization for TailOpsMCP operations."""

    SYSTEM = "system"
    USER = "user"
    CONFIGURATION = "configuration"
    LOGS = "logs"
    METRICS = "metrics"


@dataclass
class ContentMetadata:
    """Metadata for content items."""

    category: ContentCategory
    tags: List[str]
    created_at: str
    updated_at: str
    size_bytes: int


class SerializationResult:
    """Result of TOON serialization operations."""

    def __init__(
        self,
        content: str,
        metadata: Dict,
        success: bool = True,
        error: Optional[str] = None,
    ):
        self.content = content
        self.metadata = metadata
        self.success = success
        self.error = error
        self.size = len(content.encode("utf-8"))

    def to_dict(self) -> Dict:
        """Convert to dictionary representation."""
        return {
            "content": self.content,
            "metadata": self.metadata,
            "success": self.success,
            "error": self.error,
            "size": self.size,
        }


class CompressionStrategy(Enum):
    """Compression strategies for TOON serialization."""

    NONE = "none"
    GZIP = "gzip"
    LZ4 = "lz4"
    ZSTD = "zstd"
