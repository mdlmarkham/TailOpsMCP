"""
Enhanced TOON (TailOps Optimized Object Notation) Framework for LLM-Facing Serialization

This module provides comprehensive TOON serialization for all TailOpsMCP data types,
dramatically reducing token usage while preserving structure and context fidelity
for long-running conversational workflows.
"""

from __future__ import annotations

import json
import hashlib
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union, Type, Callable
from dataclasses import dataclass, field
from enum import Enum
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

from src.models.fleet_inventory import FleetInventory, ProxmoxHost, Node, Service, Snapshot, Event
from src.models.event_models import SystemEvent, HealthReport, Alert, SecurityEvent
from src.models.execution import OperationResult, CapabilityExecution
from src.models.policy_models import PolicyStatus
from src.utils.toon import _compact_json, _to_toon_tabular, compute_delta, apply_delta


# Configure logging
logger = logging.getLogger(__name__)


class TOONVersion(Enum):
    """TOON format versions for compatibility."""
    V1_0 = "1.0"
    V1_1 = "1.1"


class ContentPriority(Enum):
    """Content priority levels for smart compression."""
    CRITICAL = 1    # Critical alerts, failures
    IMPORTANT = 2   # Warnings, status changes  
    INFO = 3        # General info, metrics
    DEBUG = 4       # Debug info, verbose data


@dataclass
class TOONDocument:
    """TOON document structure with metadata and optimization hints."""
    
    version: TOONVersion = TOONVersion.V1_1
    document_type: str = ""
    created_at: datetime = field(default_factory=datetime.now)
    expires_at: Optional[datetime] = None
    
    # Content sections with priorities
    sections: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    priorities: Dict[str, ContentPriority] = field(default_factory=dict)
    
    # Optimization metadata
    token_estimate: int = 0
    compression_ratio: float = 0.0
    original_size: int = 0
    
    # Content metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def add_section(self, name: str, content: Any, priority: ContentPriority = ContentPriority.INFO) -> None:
        """Add a content section with priority."""
        self.sections[name] = content
        self.priorities[name] = priority
        self._recalculate_metrics()
    
    def get_section(self, name: str, max_tokens: Optional[int] = None) -> Optional[Any]:
        """Get a content section, optionally with token limit."""
        if name not in self.sections:
            return None
        
        content = self.sections[name]
        if max_tokens and self._estimate_tokens(content) > max_tokens:
            return self._compress_content(content, max_tokens)
        
        return content
    
    def to_compact_format(self) -> str:
        """Convert to compact TOON format for LLM consumption."""
        compact_doc = {
            "v": self.version.value,
            "t": self.document_type,
            "ts": self.created_at.isoformat(),
            "s": self.sections,
            "p": {k: v.value for k, v in self.priorities.items()},
            "m": {
                "tokens": self.token_estimate,
                "compression": self.compression_ratio,
                "size": self.original_size
            }
        }
        
        return _compact_json(compact_doc)
    
    def to_llm_optimized(self) -> str:
        """Format for optimal LLM consumption with priority-based content ordering."""
        # Sort sections by priority (critical first)
        sorted_sections = sorted(
            self.sections.items(),
            key=lambda x: self.priorities.get(x[0], ContentPriority.INFO).value
        )
        
        formatted_content = []
        formatted_content.append(f"TOON Document: {self.document_type}")
        formatted_content.append(f"Generated: {self.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        
        if self.metadata:
            formatted_content.append("Metadata:")
            for key, value in self.metadata.items():
                formatted_content.append(f"  {key}: {value}")
        
        formatted_content.append("")
        
        for section_name, content in sorted_sections:
            priority = self.priorities.get(section_name, ContentPriority.INFO)
            formatted_content.append(f"[{priority.name}] {section_name.upper()}:")
            
            if isinstance(content, dict):
                formatted_content.append(self._format_dict_for_llm(content))
            elif isinstance(content, list):
                formatted_content.append(self._format_list_for_llm(content))
            else:
                formatted_content.append(str(content))
            
            formatted_content.append("")
        
        return "\n".join(formatted_content)
    
    def estimated_token_count(self) -> int:
        """Estimate token count for the document."""
        return self.token_estimate
    
    def compression_ratio(self) -> float:
        """Get compression ratio achieved."""
        return self.compression_ratio
    
    def _recalculate_metrics(self) -> None:
        """Recalculate document metrics."""
        if not self.sections:
            self.token_estimate = 0
            self.compression_ratio = 0.0
            return
        
        # Calculate original size
        original_json = json.dumps(self.sections, separators=(",", ":"), ensure_ascii=False)
        self.original_size = len(original_json)
        
        # Calculate token estimate (rough approximation)
        self.token_estimate = self._estimate_tokens(self.sections)
        
        # Calculate compression ratio
        compact_str = self.to_compact_format()
        if len(original_json) > 0:
            self.compression_ratio = 1.0 - (len(compact_str) / len(original_json))
    
    def _estimate_tokens(self, content: Any) -> int:
        """Rough token estimation for content."""
        if isinstance(content, str):
            # Basic token estimation: words + punctuation
            return len(content.split()) + len([c for c in content if c in '.,;:!?'])
        elif isinstance(content, (dict, list)):
            json_str = json.dumps(content, separators=(",", ":"), ensure_ascii=False)
            return self._estimate_tokens(json_str)
        else:
            return self._estimate_tokens(str(content))
    
    def _compress_content(self, content: Any, max_tokens: int) -> Any:
        """Compress content to fit token limit."""
        if isinstance(content, list) and len(content) > max_tokens:
            # Keep first half and last quarter
            keep_count = min(max_tokens // 2, len(content) // 2)
            return content[:keep_count] + content[-len(content)//4:]
        elif isinstance(content, dict) and self._estimate_tokens(content) > max_tokens:
            # Keep only high-priority items
            compressed = {}
            for key, value in content.items():
                if self._estimate_tokens(compressed) + self._estimate_tokens(value) <= max_tokens:
                    compressed[key] = value
                else:
                    break
            return compressed
        return content
    
    def _format_dict_for_llm(self, data: Dict[str, Any], indent: int = 0) -> str:
        """Format dictionary for LLM readability."""
        lines = []
        indent_str = "  " * indent
        
        for key, value in data.items():
            if isinstance(value, dict):
                lines.append(f"{indent_str}{key}:")
                lines.append(self._format_dict_for_llm(value, indent + 1))
            elif isinstance(value, list):
                lines.append(f"{indent_str}{key}:")
                lines.append(self._format_list_for_llm(value, indent + 1))
            else:
                lines.append(f"{indent_str}{key}: {value}")
        
        return "\n".join(lines)
    
    def _format_list_for_llm(self, data: List[Any], indent: int = 0) -> str:
        """Format list for LLM readability."""
        if not data:
            return "  " * indent + "[]"
        
        lines = []
        indent_str = "  " * indent
        
        for item in data[:10]:  # Limit to first 10 items for readability
            if isinstance(item, dict):
                lines.append(f"{indent_str}-")
                lines.append(self._format_dict_for_llm(item, indent + 1))
            elif isinstance(item, list):
                lines.append(f"{indent_str}- {self._format_list_for_llm(item, indent + 1)}")
            else:
                lines.append(f"{indent_str}- {item}")
        
        if len(data) > 10:
            lines.append(f"{indent_str}... and {len(data) - 10} more items")
        
        return "\n".join(lines)


@dataclass
class TOONCacheEntry:
    """Cache entry for TOON documents."""
    document: TOONDocument
    created_at: datetime = field(default_factory=datetime.now)
    access_count: int = 0
    last_accessed: datetime = field(default_factory=datetime.now)
    
    def update_access(self) -> None:
        """Update access statistics."""
        self.access_count += 1
        self.last_accessed = datetime.now()


class TOONDocumentCache:
    """LRU cache for TOON documents with size and TTL management."""
    
    def __init__(self, max_size: int = 1000, ttl_seconds: int = 300):
        self.max_size = max_size
        self.ttl = timedelta(seconds=ttl_seconds)
        self._cache: Dict[str, TOONCacheEntry] = {}
        self._access_order: List[str] = []
        self._lock = threading.RLock()
    
    def get(self, key: str) -> Optional[TOONDocument]:
        """Get document from cache."""
        with self._lock:
            entry = self._cache.get(key)
            if entry:
                # Check TTL
                if datetime.now() - entry.created_at < self.ttl:
                    entry.update_access()
                    self._update_access_order(key)
                    return entry.document
                else:
                    # Expired, remove from cache
                    del self._cache[key]
                    if key in self._access_order:
                        self._access_order.remove(key)
            return None
    
    def put(self, key: str, document: TOONDocument) -> None:
        """Put document in cache."""
        with self._lock:
            # Remove existing entry if present
            if key in self._cache:
                del self._cache[key]
                if key in self._access_order:
                    self._access_order.remove(key)
            
            # Add new entry
            entry = TOONCacheEntry(document=document)
            self._cache[key] = entry
            self._access_order.append(key)
            
            # Evict if over capacity
            while len(self._cache) > self.max_size:
                self._evict_oldest()
    
    def clear(self) -> None:
        """Clear all cached documents."""
        with self._lock:
            self._cache.clear()
            self._access_order.clear()
    
    def _update_access_order(self, key: str) -> None:
        """Update access order for LRU."""
        if key in self._access_order:
            self._access_order.remove(key)
        self._access_order.append(key)
    
    def _evict_oldest(self) -> None:
        """Evict the least recently used entry."""
        if self._access_order:
            oldest_key = self._access_order.pop(0)
            del self._cache[oldest_key]


class TOONEnhancedSerializer:
    """Enhanced TOON serializer with smart compression and LLM optimization."""
    
    def __init__(self, cache_enabled: bool = True, max_cache_size: int = 1000):
        self.cache_enabled = cache_enabled
        self._cache = TOONDocumentCache(max_size=max_cache_size) if cache_enabled else None
        self._serializers: Dict[str, Callable] = {}
        self._register_default_serializers()
    
    def serialize_fleet_inventory(self, inventory: FleetInventory) -> TOONDocument:
        """Serialize fleet inventory to TOON document."""
        cache_key = f"fleet_inventory_{hashlib.md5(str(inventory.to_dict()).encode()).hexdigest()[:16]}"
        
        # Check cache first
        if self.cache_enabled:
            cached = self._cache.get(cache_key)
            if cached:
                return cached
        
        doc = TOONDocument(
            document_type="fleet_inventory",
            metadata={
                "total_hosts": inventory.total_hosts,
                "total_nodes": inventory.total_nodes,
                "total_services": inventory.total_services,
                "total_snapshots": inventory.total_snapshots
            }
        )
        
        # Fleet summary
        summary = {
            "total_hosts": inventory.total_hosts,
            "healthy_hosts": len([h for h in inventory.proxmox_hosts.values() if h.is_active]),
            "total_nodes": inventory.total_nodes,
            "managed_nodes": len([n for n in inventory.nodes.values() if n.is_managed]),
            "total_services": inventory.total_services,
            "running_services": len([s for s in inventory.services.values() if s.status.value == "running"]),
            "total_snapshots": inventory.total_snapshots,
            "last_updated": inventory.last_updated
        }
        doc.add_section("fleet_summary", summary, ContentPriority.IMPORTANT)
        
        # Host details
        hosts_data = []
        for host in inventory.proxmox_hosts.values():
            hosts_data.append({
                "id": host.id,
                "hostname": host.hostname,
                "address": host.address,
                "status": "active" if host.is_active else "inactive",
                "resources": {
                    "cpu": host.cpu_cores,
                    "memory": host.memory_mb,
                    "storage": host.storage_gb
                },
                "version": host.version,
                "last_seen": host.last_seen
            })
        doc.add_section("hosts", hosts_data, ContentPriority.IMPORTANT)
        
        # Node details
        nodes_data = []
        for node in inventory.nodes.values():
            nodes_data.append({
                "id": node.id,
                "name": node.name,
                "type": node.node_type.value,
                "status": node.status,
                "resources": {
                    "cpu": node.cpu_cores,
                    "memory": node.memory_mb,
                    "disk": node.disk_gb
                },
                "network": {
                    "ip": node.ip_address,
                    "mac": node.mac_address
                },
                "runtime": node.runtime.value,
                "managed": node.is_managed
            })
        doc.add_section("nodes", nodes_data, ContentPriority.INFO)
        
        # Service details
        services_data = []
        for service in inventory.services.values():
            services_data.append({
                "id": service.id,
                "name": service.name,
                "node_id": service.node_id,
                "type": service.service_type,
                "status": service.status.value,
                "port": service.port,
                "version": service.version,
                "monitored": service.is_monitored
            })
        doc.add_section("services", services_data, ContentPriority.INFO)
        
        # Recent events
        events_data = []
        for event in inventory.events.values()[:20]:  # Limit to recent 20 events
            events_data.append({
                "id": event.id,
                "type": event.event_type.value,
                "severity": event.severity.value,
                "source": event.source,
                "message": event.message,
                "timestamp": event.timestamp
            })
        doc.add_section("recent_events", events_data, ContentPriority.IMPORTANT)
        
        # Cache the document
        if self.cache_enabled:
            self._cache.put(cache_key, doc)
        
        return doc
    
    def serialize_operation_result(self, result: OperationResult) -> TOONDocument:
        """Serialize operation result to TOON document."""
        doc = TOONDocument(
            document_type="operation_result",
            metadata={
                "operation_id": result.operation_id,
                "status": result.status.value if result.status else "unknown",
                "duration": getattr(result, 'duration', None)
            }
        )
        
        # Operation summary
        summary = {
            "id": result.operation_id,
            "status": result.status.value if result.status else "unknown",
            "started_at": getattr(result, 'started_at', None),
            "completed_at": getattr(result, 'completed_at', None),
            "duration": getattr(result, 'duration', None),
            "items_processed": getattr(result, 'items_processed', 0),
            "errors_count": len(getattr(result, 'errors', []))
        }
        doc.add_section("operation_summary", summary, ContentPriority.CRITICAL)
        
        # Execution details
        if hasattr(result, 'execution_details'):
            doc.add_section("execution_details", result.execution_details, ContentPriority.IMPORTANT)
        
        # Results
        if hasattr(result, 'results'):
            doc.add_section("results", result.results, ContentPriority.IMPORTANT)
        
        # Errors
        if hasattr(result, 'errors') and result.errors:
            doc.add_section("errors", result.errors, ContentPriority.CRITICAL)
        
        # Next steps
        if hasattr(result, 'next_steps'):
            doc.add_section("next_steps", result.next_steps, ContentPriority.IMPORTANT)
        
        return doc
    
    def serialize_events_summary(self, events: List[SystemEvent], time_range: str = "24h") -> TOONDocument:
        """Serialize events summary to TOON document."""
        doc = TOONDocument(
            document_type="events_summary",
            metadata={
                "time_range": time_range,
                "total_events": len(events)
            }
        )
        
        # Event statistics
        critical_count = len([e for e in events if e.severity.value == "critical"])
        error_count = len([e for e in events if e.severity.value == "error"])
        warning_count = len([e for e in events if e.severity.value == "warning"])
        info_count = len([e for e in events if e.severity.value == "info"])
        
        stats = {
            "time_range": time_range,
            "total_events": len(events),
            "critical_events": critical_count,
            "error_events": error_count,
            "warning_events": warning_count,
            "info_events": info_count,
            "severity_distribution": {
                "critical": critical_count,
                "error": error_count,
                "warning": warning_count,
                "info": info_count
            }
        }
        doc.add_section("event_statistics", stats, ContentPriority.IMPORTANT)
        
        # Top event sources
        source_counts = {}
        for event in events:
            source = event.source
            source_counts[source] = source_counts.get(source, 0) + 1
        
        top_sources = sorted(source_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        doc.add_section("top_event_sources", top_sources, ContentPriority.INFO)
        
        # Recent critical events
        critical_events = [
            {
                "id": event.id,
                "source": event.source,
                "message": event.message,
                "timestamp": event.timestamp,
                "severity": event.severity.value
            }
            for event in events if event.severity.value == "critical"
        ][:10]  # Limit to 10 most recent
        
        doc.add_section("critical_events", critical_events, ContentPriority.CRITICAL)
        
        return doc
    
    def serialize_health_report(self, report: HealthReport) -> TOONDocument:
        """Serialize health report to TOON document."""
        doc = TOONDocument(
            document_type="health_report",
            metadata={
                "report_id": getattr(report, 'id', 'unknown'),
                "generated_at": getattr(report, 'generated_at', datetime.now())
            }
        )
        
        # Overall health status
        overall_health = {
            "status": getattr(report, 'overall_status', 'unknown'),
            "score": getattr(report, 'health_score', 0.0),
            "critical_issues": getattr(report, 'critical_issues', []),
            "warnings": getattr(report, 'warnings', [])
        }
        doc.add_section("overall_health", overall_health, ContentPriority.CRITICAL)
        
        # Component health
        if hasattr(report, 'components'):
            component_health = {}
            for component_name, component_data in report.components.items():
                component_health[component_name] = {
                    "status": component_data.get('status', 'unknown'),
                    "score": component_data.get('score', 0.0),
                    "issues": component_data.get('issues', [])
                }
            doc.add_section("component_health", component_health, ContentPriority.IMPORTANT)
        
        # Recommendations
        if hasattr(report, 'recommendations'):
            doc.add_section("recommendations", report.recommendations, ContentPriority.IMPORTANT)
        
        return doc
    
    def serialize_policy_status(self, policy_status: PolicyStatus) -> TOONDocument:
        """Serialize policy status to TOON document."""
        doc = TOONDocument(
            document_type="policy_status",
            metadata={
                "policy_name": getattr(policy_status, 'policy_name', 'unknown'),
                "last_checked": getattr(policy_status, 'last_checked', datetime.now())
            }
        )
        
        # Policy summary
        policy_summary = {
            "name": getattr(policy_status, 'policy_name', 'unknown'),
            "status": getattr(policy_status, 'status', 'unknown'),
            "compliant": getattr(policy_status, 'compliant', False),
            "violations": len(getattr(policy_status, 'violations', [])),
            "last_checked": getattr(policy_status, 'last_checked', datetime.now())
        }
        doc.add_section("policy_summary", policy_summary, ContentPriority.IMPORTANT)
        
        # Violations
        violations = getattr(policy_status, 'violations', [])
        if violations:
            doc.add_section("violations", violations, ContentPriority.CRITICAL)
        
        # Compliance details
        if hasattr(policy_status, 'compliance_details'):
            doc.add_section("compliance_details", policy_status.compliance_details, ContentPriority.INFO)
        
        return doc
    
    def _register_default_serializers(self) -> None:
        """Register default serializers for common data types."""
        self._serializers[FleetInventory] = self.serialize_fleet_inventory
        self._serializers[OperationResult] = self.serialize_operation_result
        # Add more serializers as needed
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        if not self.cache_enabled or not self._cache:
            return {"enabled": False}
        
        return {
            "enabled": True,
            "size": len(self._cache._cache),
            "max_size": self._cache.max_size,
            "access_count": sum(entry.access_count for entry in self._cache._cache.values())
        }
    
    def clear_cache(self) -> None:
        """Clear the serialization cache."""
        if self.cache_enabled and self._cache:
            self._cache.clear()


# Global enhanced serializer instance
_enhanced_serializer = TOONEnhancedSerializer(cache_enabled=True)


def get_enhanced_toon_serializer() -> TOONEnhancedSerializer:
    """Get the global enhanced TOON serializer instance."""
    return _enhanced_serializer