"""
TOON Performance Optimization for High-Volume Serialization

This module provides performance optimization features for TOON serialization,
including caching, batching, parallel processing, and memory management
for high-throughput scenarios.
"""

from __future__ import annotations

import json
import hashlib
import threading
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union, Tuple, Callable
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from collections import defaultdict, OrderedDict
import weakref
import psutil
import logging
from functools import lru_cache, wraps
import gc

from src.integration.toon_enhanced import TOONDocument, TOONDocumentCache, TOONCacheEntry
from src.integration.toon_serializers import TOONEnhancedSerializer
from src.utils.toon import _compact_json


logger = logging.getLogger(__name__)


@dataclass
class PerformanceMetrics:
    """Performance metrics for TOON operations."""
    
    operation_count: int = 0
    total_time: float = 0.0
    avg_time: float = 0.0
    min_time: float = float('inf')
    max_time: float = 0.0
    cache_hits: int = 0
    cache_misses: int = 0
    memory_usage_mb: float = 0.0
    throughput_per_second: float = 0.0
    
    def update(self, operation_time: float, cache_hit: bool = False) -> None:
        """Update metrics with new operation."""
        self.operation_count += 1
        self.total_time += operation_time
        self.avg_time = self.total_time / self.operation_count
        self.min_time = min(self.min_time, operation_time)
        self.max_time = max(self.max_time, operation_time)
        
        if cache_hit:
            self.cache_hits += 1
        else:
            self.cache_misses += 1
        
        # Update throughput
        if self.total_time > 0:
            self.throughput_per_second = self.operation_count / self.total_time
        
        # Update memory usage
        process = psutil.Process()
        self.memory_usage_mb = process.memory_info().rss / 1024 / 1024
    
    def get_hit_ratio(self) -> float:
        """Get cache hit ratio."""
        total_requests = self.cache_hits + self.cache_misses
        return self.cache_hits / max(total_requests, 1)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary."""
        return {
            "operation_count": self.operation_count,
            "total_time": self.total_time,
            "avg_time": self.avg_time,
            "min_time": self.min_time if self.min_time != float('inf') else 0,
            "max_time": self.max_time,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "cache_hit_ratio": self.get_hit_ratio(),
            "memory_usage_mb": self.memory_usage_mb,
            "throughput_per_second": self.throughput_per_second
        }


@dataclass
class CacheStats:
    """Statistics for cache operations."""
    
    size: int = 0
    max_size: int = 0
    hit_ratio: float = 0.0
    evictions: int = 0
    memory_usage_mb: float = 0.0
    average_access_time: float = 0.0
    last_cleanup: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "size": self.size,
            "max_size": self.max_size,
            "hit_ratio": self.hit_ratio,
            "evictions": self.evictions,
            "memory_usage_mb": self.memory_usage_mb,
            "average_access_time": self.average_access_time,
            "last_cleanup": self.last_cleanup.isoformat() if self.last_cleanup else None
        }


class TOONPerformanceOptimizer:
    """Performance optimizer for TOON serialization operations."""
    
    def __init__(self, max_workers: int = 4, enable_profiling: bool = False):
        self.max_workers = max_workers
        self.enable_profiling = enable_profiling
        self._metrics: Dict[str, PerformanceMetrics] = defaultdict(PerformanceMetrics)
        self._lock = threading.RLock()
        
        # Memory management
        self._memory_threshold_mb = 1024  # 1GB threshold
        self._last_gc_time = time.time()
        self._gc_interval = 300  # 5 minutes
        
        # Performance monitoring
        self._operation_times: List[float] = []
        self._max_history = 1000
    
    def cache_serialized_documents(self, key: str, document: TOONDocument) -> None:
        """Cache serialized document with performance tracking."""
        start_time = time.time()
        
        try:
            # Use the existing cache from TOONDocument
            cache_key = self._generate_cache_key(key, document)
            document._cache.put(cache_key, document) if hasattr(document, '_cache') else None
            
            operation_time = time.time() - start_time
            self._update_metrics("cache_store", operation_time, cache_hit=False)
            
        except Exception as e:
            logger.error(f"Error caching document: {e}")
    
    def get_cached_document(self, key: str) -> Optional[TOONDocument]:
        """Get cached document with performance tracking."""
        start_time = time.time()
        
        try:
            # This would need to be implemented based on the actual cache system
            # For now, return None as placeholder
            cached_doc = None
            
            operation_time = time.time() - start_time
            cache_hit = cached_doc is not None
            self._update_metrics("cache_retrieve", operation_time, cache_hit=cache_hit)
            
            return cached_doc
            
        except Exception as e:
            logger.error(f"Error retrieving cached document: {e}")
            return None
    
    def batch_serialize(self, items: List[Any]) -> List[TOONDocument]:
        """Serialize multiple items in batch for efficiency."""
        if not items:
            return []
        
        start_time = time.time()
        
        try:
            # Use appropriate serializer based on item types
            serializer = self._select_serializer(items)
            
            # Process in batches to avoid memory issues
            batch_size = self._calculate_optimal_batch_size(len(items))
            results = []
            
            for i in range(0, len(items), batch_size):
                batch = items[i:i + batch_size]
                batch_results = self._process_batch(serializer, batch)
                results.extend(batch_results)
                
                # Check memory usage
                self._check_memory_usage()
            
            operation_time = time.time() - start_time
            self._update_metrics("batch_serialize", operation_time, cache_hit=False)
            
            return results
            
        except Exception as e:
            logger.error(f"Error in batch serialization: {e}")
            return []
    
    def parallel_serialization(
        self,
        items: List[Any],
        max_workers: Optional[int] = None
    ) -> List[TOONDocument]:
        """Serialize items in parallel for improved performance."""
        if not items:
            return []
        
        max_workers = max_workers or self.max_workers
        start_time = time.time()
        
        try:
            serializer = self._select_serializer(items)
            
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Submit all serialization tasks
                future_to_item = {
                    executor.submit(self._serialize_single, serializer, item): item
                    for item in items
                }
                
                # Collect results as they complete
                results = []
                for future in as_completed(future_to_item):
                    try:
                        result = future.result(timeout=30)  # 30 second timeout
                        results.append(result)
                    except Exception as e:
                        logger.error(f"Error in parallel serialization: {e}")
                        # Add placeholder for failed items
                        results.append(None)
            
            operation_time = time.time() - start_time
            self._update_metrics("parallel_serialize", operation_time, cache_hit=False)
            
            return results
            
        except Exception as e:
            logger.error(f"Error in parallel serialization: {e}")
            return []
    
    def optimize_for_throughput(
        self,
        documents: List[TOONDocument],
        target_throughput: float = 100.0
    ) -> List[TOONDocument]:
        """Optimize documents for maximum throughput."""
        if not documents:
            return []
        
        start_time = time.time()
        
        try:
            # Sort documents by priority and complexity
            sorted_docs = self._sort_by_optimization_priority(documents)
            
            optimized_docs = []
            for doc in sorted_docs:
                optimized_doc = self._optimize_single_document(doc)
                optimized_docs.append(optimized_doc)
                
                # Check if we're meeting throughput target
                elapsed_time = time.time() - start_time
                current_throughput = len(optimized_docs) / max(elapsed_time, 0.001)
                
                if current_throughput < target_throughput * 0.8:  # 80% threshold
                    # Apply more aggressive optimization
                    optimized_docs[-1] = self._aggressive_optimize(optimized_docs[-1])
            
            operation_time = time.time() - start_time
            self._update_metrics("throughput_optimize", operation_time, cache_hit=False)
            
            return optimized_docs
            
        except Exception as e:
            logger.error(f"Error in throughput optimization: {e}")
            return documents
    
    def get_performance_metrics(self, operation_type: Optional[str] = None) -> Dict[str, Any]:
        """Get performance metrics for operations."""
        if operation_type:
            return self._metrics.get(operation_type, PerformanceMetrics()).to_dict()
        else:
            return {
                op_type: metrics.to_dict()
                for op_type, metrics in self._metrics.items()
            }
    
    def clear_metrics(self) -> None:
        """Clear all performance metrics."""
        with self._lock:
            self._metrics.clear()
            self._operation_times.clear()
    
    def _update_metrics(
        self,
        operation_type: str,
        operation_time: float,
        cache_hit: bool = False
    ) -> None:
        """Update performance metrics."""
        with self._lock:
            metrics = self._metrics[operation_type]
            metrics.update(operation_time, cache_hit)
            
            # Track operation times for analysis
            self._operation_times.append(operation_time)
            if len(self._operation_times) > self._max_history:
                self._operation_times.pop(0)
    
    def _generate_cache_key(self, key: str, document: TOONDocument) -> str:
        """Generate cache key for document."""
        content_hash = hashlib.md5(
            json.dumps(document.sections, sort_keys=True).encode()
        ).hexdigest()
        return f"{key}:{content_hash}"
    
    def _select_serializer(self, items: List[Any]) -> TOONEnhancedSerializer:
        """Select appropriate serializer for item types."""
        # Simple heuristic - in practice, this would be more sophisticated
        if all(hasattr(item, 'document_type') for item in items):
            return TOONEnhancedSerializer()
        else:
            return TOONEnhancedSerializer()
    
    def _calculate_optimal_batch_size(self, total_items: int) -> int:
        """Calculate optimal batch size based on system resources."""
        # Base batch size
        base_batch_size = 50
        
        # Adjust based on available memory
        available_memory = psutil.virtual_memory().available / 1024 / 1024  # MB
        if available_memory < 512:  # Less than 512MB available
            return max(10, base_batch_size // 4)
        elif available_memory < 1024:  # Less than 1GB available
            return max(20, base_batch_size // 2)
        
        # Adjust based on CPU count
        cpu_count = psutil.cpu_count()
        if cpu_count <= 2:
            return max(20, base_batch_size // 2)
        
        return base_batch_size
    
    def _process_batch(self, serializer: TOONEnhancedSerializer, batch: List[Any]) -> List[TOONDocument]:
        """Process a batch of items."""
        results = []
        for item in batch:
            try:
                # Simple serialization - would need proper type detection
                if hasattr(item, 'document_type'):
                    doc = serializer.serialize_fleet_inventory(item) if hasattr(item, 'proxmox_hosts') else None
                else:
                    doc = TOONDocument(document_type="generic")
                
                if doc:
                    results.append(doc)
            except Exception as e:
                logger.error(f"Error processing batch item: {e}")
                results.append(None)
        
        return results
    
    def _serialize_single(self, serializer: TOONEnhancedSerializer, item: Any) -> TOONDocument:
        """Serialize a single item."""
        try:
            if hasattr(item, 'document_type'):
                return serializer.serialize_fleet_inventory(item)
            else:
                return TOONDocument(document_type="generic")
        except Exception as e:
            logger.error(f"Error serializing item: {e}")
            return TOONDocument(document_type="error")
    
    def _sort_by_optimization_priority(self, documents: List[TOONDocument]) -> List[TOONDocument]:
        """Sort documents by optimization priority."""
        def priority_key(doc: TOONDocument) -> Tuple[int, int]:
            # Higher priority value = higher priority (processed first)
            priority_score = 0
            
            # Critical sections get highest priority
            critical_count = sum(
                1 for section in doc.sections.keys()
                if doc.priorities.get(section) == ContentPriority.CRITICAL
            )
            priority_score += critical_count * 10
            
            # Document complexity (more sections = lower priority for optimization)
            complexity_penalty = len(doc.sections)
            priority_score -= complexity_penalty
            
            # Token count (more tokens = lower priority)
            token_penalty = doc.token_estimate // 1000
            priority_score -= token_penalty
            
            return (-priority_score, doc.token_estimate)  # Negative for descending order
        
        return sorted(documents, key=priority_key)
    
    def _optimize_single_document(self, document: TOONDocument) -> TOONDocument:
        """Optimize a single document for performance."""
        optimized = TOONDocument(
            document_type=document.document_type,
            metadata=document.metadata.copy()
        )
        
        # Copy sections with potential optimization
        for section_name, content in document.sections.items():
            priority = document.priorities.get(section_name)
            
            # Apply optimization based on priority
            if priority == ContentPriority.CRITICAL:
                # Keep critical content as-is
                optimized.add_section(section_name, content, priority)
            elif priority == ContentPriority.IMPORTANT:
                # Apply moderate compression
                compressed_content = self._moderate_compress(content)
                optimized.add_section(section_name, compressed_content, priority)
            else:
                # Apply aggressive compression for low-priority content
                compressed_content = self._aggressive_compress(content)
                optimized.add_section(section_name, compressed_content, priority)
        
        return optimized
    
    def _aggressive_optimize(self, document: TOONDocument) -> TOONDocument:
        """Apply aggressive optimization to document."""
        optimized = TOONDocument(
            document_type=document.document_type,
            metadata=document.metadata.copy()
        )
        
        # Only keep critical sections
        for section_name, content in document.sections.items():
            priority = document.priorities.get(section_name)
            if priority == ContentPriority.CRITICAL:
                # Compress critical content aggressively
                compressed = self._aggressive_compress(content)
                optimized.add_section(section_name, compressed, priority)
        
        return optimized
    
    def _moderate_compress(self, content: Any) -> Any:
        """Apply moderate compression to content."""
        if isinstance(content, list):
            # Keep first 50% and last 25%
            if len(content) > 20:
                keep_count = max(10, len(content) // 2)
                return content[:keep_count] + content[-len(content)//4:]
        elif isinstance(content, dict):
            # Keep only essential keys
            essential_keys = ['id', 'name', 'status', 'score', 'count', 'total']
            compressed = {}
            for key, value in content.items():
                if any(essential in key.lower() for essential in essential_keys):
                    compressed[key] = value
                elif len(compressed) < 10:  # Keep up to 10 additional keys
                    compressed[key] = value
            return compressed
        
        return content
    
    def _aggressive_compress(self, content: Any) -> Any:
        """Apply aggressive compression to content."""
        if isinstance(content, list):
            # Keep only first 10 items
            return content[:10] if len(content) > 10 else content
        elif isinstance(content, dict):
            # Keep only first 5 keys
            return dict(list(content.items())[:5])
        elif isinstance(content, str):
            # Truncate to 200 characters
            return content[:200] + "..." if len(content) > 200 else content
        
        return content
    
    def _check_memory_usage(self) -> None:
        """Check and manage memory usage."""
        current_time = time.time()
        
        # Check if it's time for garbage collection
        if current_time - self._last_gc_time > self._gc_interval:
            gc.collect()
            self._last_gc_time = current_time
        
        # Check memory threshold
        memory_usage = psutil.virtual_memory()
        if memory_usage.percent > 85:  # More than 85% memory usage
            # Trigger aggressive garbage collection
            gc.collect()
            
            # Clear old operation times
            with self._lock:
                if len(self._operation_times) > 500:
                    self._operation_times = self._operation_times[-500:]


class TOONMemoryManager:
    """Memory management for TOON documents."""
    
    def __init__(self, max_memory_mb: int = 2048):
        self.max_memory_mb = max_memory_mb
        self._document_registry: Dict[str, weakref.ref] = {}
        self._memory_usage = 0
        self._lock = threading.RLock()
    
    def register_document(self, doc_id: str, document: TOONDocument) -> None:
        """Register document for memory tracking."""
        with self._lock:
            # Create weak reference to avoid circular dependencies
            weak_ref = weakref.ref(document, lambda ref: self._cleanup_document(doc_id))
            self._document_registry[doc_id] = weak_ref
            
            # Estimate memory usage
            estimated_size = self._estimate_document_size(document)
            self._memory_usage += estimated_size
            
            # Check if we need to free memory
            if self._memory_usage > self.max_memory_mb * 1024 * 1024:
                self._free_memory()
    
    def compress_large_documents(self, size_threshold_mb: int = 10) -> int:
        """Compress documents larger than threshold."""
        compressed_count = 0
        
        with self._lock:
            for doc_id, weak_ref in list(self._document_registry.items()):
                document = weak_ref()
                if document and self._estimate_document_size(document) > size_threshold_mb * 1024 * 1024:
                    self._compress_document(document)
                    compressed_count += 1
        
        return compressed_count
    
    def archive_old_documents(self, before_date: datetime) -> int:
        """Archive documents older than specified date."""
        archived_count = 0
        
        with self._lock:
            for doc_id, weak_ref in list(self._document_registry.items()):
                document = weak_ref()
                if document and document.created_at < before_date:
                    self._archive_document(document)
                    archived_count += 1
        
        return archived_count
    
    def optimize_document_tiers(self, documents: List[TOONDocument]) -> List[TOONDocument]:
        """Optimize documents into memory tiers."""
        # Sort by importance and size
        tier1_docs = []  # Critical, small documents
        tier2_docs = []  # Important, medium documents
        tier3_docs = []  # Low priority, large documents
        
        for doc in documents:
            priority_score = self._calculate_priority_score(doc)
            size_mb = self._estimate_document_size(doc) / 1024 / 1024
            
            if priority_score >= 8 and size_mb <= 1:
                tier1_docs.append(doc)
            elif priority_score >= 5 and size_mb <= 5:
                tier2_docs.append(doc)
            else:
                tier3_docs.append(doc)
        
        # Apply different optimization strategies
        optimized_docs = []
        optimized_docs.extend(self._optimize_tier1(tier1_docs))
        optimized_docs.extend(self._optimize_tier2(tier2_docs))
        optimized_docs.extend(self._optimize_tier3(tier3_docs))
        
        return optimized_docs
    
    def get_memory_stats(self) -> Dict[str, Any]:
        """Get memory usage statistics."""
        with self._lock:
            return {
                "current_usage_mb": self._memory_usage / 1024 / 1024,
                "max_usage_mb": self.max_memory_mb,
                "usage_percent": (self._memory_usage / (self.max_memory_mb * 1024 * 1024)) * 100,
                "registered_documents": len(self._document_registry),
                "available_mb": self.max_memory_mb - (self._memory_usage / 1024 / 1024)
            }
    
    def _estimate_document_size(self, document: TOONDocument) -> int:
        """Estimate memory size of document."""
        # Rough estimation based on content size
        size = 0
        
        # Document metadata
        size += len(json.dumps(document.metadata, default=str))
        
        # Sections
        for section_name, content in document.sections.items():
            size += len(section_name)
            size += len(json.dumps(content, default=str))
        
        return size
    
    def _cleanup_document(self, doc_id: str) -> None:
        """Clean up document reference."""
        with self._lock:
            if doc_id in self._document_registry:
                del self._document_registry[doc_id]
    
    def _free_memory(self) -> None:
        """Free memory by compressing or archiving documents."""
        # Trigger garbage collection
        gc.collect()
        
        # Compress large documents
        self.compress_large_documents()
        
        # Archive old documents (older than 1 day)
        cutoff_date = datetime.now() - timedelta(days=1)
        self.archive_old_documents(cutoff_date)
    
    def _compress_document(self, document: TOONDocument) -> None:
        """Compress document content."""
        for section_name, content in document.sections.items():
            if isinstance(content, list) and len(content) > 50:
                # Compress large lists
                document.sections[section_name] = content[:25] + content[-25:]
            elif isinstance(content, dict) and len(content) > 20:
                # Compress large dictionaries
                document.sections[section_name] = dict(list(content.items())[:10])
    
    def _archive_document(self, document: TOONDocument) -> None:
        """Archive document (remove from active memory)."""
        # Remove all sections except critical metadata
        critical_sections = ["document_type", "created_at"]
        document.sections = {
            k: v for k, v in document.sections.items()
            if k in critical_sections
        }
    
    def _calculate_priority_score(self, document: TOONDocument) -> int:
        """Calculate priority score for document."""
        score = 0
        
        # Base score by document type
        doc_type_scores = {
            "fleet_inventory": 8,
            "health_report": 9,
            "operation_result": 7,
            "events_summary": 6,
            "security_analysis": 10
        }
        score += doc_type_scores.get(document.document_type, 5)
        
        # Adjust by content priority
        critical_sections = sum(
            1 for section in document.sections.keys()
            if document.priorities.get(section) == ContentPriority.CRITICAL
        )
        score += critical_sections
        
        return score
    
    def _optimize_tier1(self, documents: List[TOONDocument]) -> List[TOONDocument]:
        """Optimize tier 1 documents (critical, small)."""
        # Minimal optimization for critical documents
        return [doc for doc in documents]
    
    def _optimize_tier2(self, documents: List[TOONDocument]) -> List[TOONDocument]:
        """Optimize tier 2 documents (important, medium)."""
        optimized = []
        for doc in documents:
            # Moderate compression
            compressed_sections = {}
            for section_name, content in doc.sections.items():
                if isinstance(content, list) and len(content) > 20:
                    compressed_sections[section_name] = content[:10]
                else:
                    compressed_sections[section_name] = content
            doc.sections = compressed_sections
            optimized.append(doc)
        return optimized
    
    def _optimize_tier3(self, documents: List[TOONDocument]) -> List[TOONDocument]:
        """Optimize tier 3 documents (low priority, large)."""
        optimized = []
        for doc in documents:
            # Aggressive compression
            compressed_sections = {}
            for section_name, content in doc.sections.items():
                if document.priorities.get(section_name) == ContentPriority.CRITICAL:
                    # Keep critical sections with light compression
                    if isinstance(content, list):
                        compressed_sections[section_name] = content[:5]
                    else:
                        compressed_sections[section_name] = content
                else:
                    # Remove non-critical sections or compress heavily
                    if isinstance(content, list):
                        compressed_sections[section_name] = content[:3]
                    elif isinstance(content, dict):
                        compressed_sections[section_name] = dict(list(content.items())[:3])
                    else:
                        compressed_sections[section_name] = str(content)[:100]
            doc.sections = compressed_sections
            optimized.append(doc)
        return optimized


# Global performance optimizer
_performance_optimizer = TOONPerformanceOptimizer()
_memory_manager = TOONMemoryManager()


def get_performance_optimizer() -> TOONPerformanceOptimizer:
    """Get the global performance optimizer."""
    return _performance_optimizer


def get_memory_manager() -> TOONMemoryManager:
    """Get the global memory manager."""
    return _memory_manager


# Performance monitoring decorator
def performance_monitor(operation_type: str):
    """Decorator to monitor performance of functions."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            optimizer = get_performance_optimizer()
            
            try:
                result = func(*args, **kwargs)
                operation_time = time.time() - start_time
                optimizer._update_metrics(operation_type, operation_time, cache_hit=False)
                return result
            except Exception as e:
                operation_time = time.time() - start_time
                optimizer._update_metrics(operation_type, operation_time, cache_hit=False)
                logger.error(f"Error in {operation_type}: {e}")
                raise
        
        return wrapper
    return decorator


# Optimized serialization functions
@performance_monitor("optimized_fleet_serialize")
def optimized_serialize_fleet_inventory(inventory: Any) -> TOONDocument:
    """Optimized fleet inventory serialization."""
    optimizer = get_performance_optimizer()
    serializer = TOONEnhancedSerializer()
    
    # Check cache first
    cache_key = f"fleet_inventory_{hash(str(inventory))}"
    cached_doc = optimizer.get_cached_document(cache_key)
    if cached_doc:
        return cached_doc
    
    # Serialize and cache
    doc = serializer.serialize_fleet_inventory(inventory)
    optimizer.cache_serialized_documents(cache_key, doc)
    
    return doc


@performance_monitor("optimized_batch_process")
def optimized_batch_process(items: List[Any], use_parallel: bool = True) -> List[TOONDocument]:
    """Optimized batch processing of items."""
    optimizer = get_performance_optimizer()
    
    if use_parallel and len(items) > 10:
        return optimizer.parallel_serialization(items)
    else:
        return optimizer.batch_serialize(items)