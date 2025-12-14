# TOON Integration Guide for TailOpsMCP

## Overview

The TOON (TailOps Optimized Object Notation) integration provides a comprehensive serialization framework designed specifically for LLM consumption in the TailOpsMCP system. This integration dramatically reduces token usage (50-70% reduction) while preserving structure and context fidelity for long-running conversational workflows.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Core Components](#core-components)
3. [Usage Patterns](#usage-patterns)
4. [Integration Examples](#integration-examples)
5. [Configuration Management](#configuration-management)
6. [Performance Optimization](#performance-optimization)
7. [Quality Assurance](#quality-assurance)
8. [Best Practices](#best-practices)
9. [Troubleshooting](#troubleshooting)

## Quick Start

### Basic Fleet Status Query

```python
from src.tools.toon_enhanced_tools import get_fleet_status_toon

# Get TOON-optimized fleet status
result = get_fleet_status_toon(hours=24)

print("Fleet Status (TOON Format):")
print(result["formatted_response"])
print(f"Token reduction: {result['metadata']['token_reduction_percentage']:.1f}%")
print(f"Quality score: {result['metadata']['quality_score']:.2f}")
```

### Events Analysis

```python
from src.tools.toon_enhanced_tools import get_events_summary_toon

# Get TOON-optimized events summary
result = get_events_summary_toon(hours=6, severity_filter="error")

print("Event Analysis:")
print(result["formatted_response"])
print(f"Critical patterns detected: {result['key_patterns']}")
```

### System Health Report

```python
from src.tools.toon_enhanced_tools import get_health_report_toon

# Generate comprehensive health report
result = get_health_report_toon()

print("Health Report:")
print(result["formatted_response"])
print(f"Health score: {result['health_score']:.2f}")
print(f"Immediate actions: {result['immediate_actions']}")
```

## Core Components

### 1. TOON Document Structure

```python
from src.integration.toon_enhanced import TOONDocument, ContentPriority

# Create a TOON document
doc = TOONDocument(
    document_type="custom_report",
    metadata={
        "generated_at": datetime.now().isoformat(),
        "source": "tailops_mcp"
    }
)

# Add content sections with priorities
doc.add_section("summary", {"status": "operational"}, ContentPriority.CRITICAL)
doc.add_section("metrics", {"cpu": 45, "memory": 62}, ContentPriority.IMPORTANT)
doc.add_section("details", {"config": "standard"}, ContentPriority.INFO)

# Generate different formats
compact_format = doc.to_compact_format()  # For API responses
llm_format = doc.to_llm_optimized()       # For conversational AI
```

### 2. Specialized Serializers

```python
from src.integration.toon_serializers import (
    TOONInventorySerializer, TOONEventsSerializer,
    TOONOperationsSerializer, TOONPolicySerializer
)

# Fleet inventory serialization
inventory_serializer = TOONInventorySerializer()
doc = inventory_serializer.serialize_fleet_inventory(inventory_data)

# Events analysis
events_serializer = TOONEventsSerializer()
doc = events_serializer.serialize_events_summary(events_list, "24h")

# Operation results
operations_serializer = TOONOperationsSerializer()
doc = operations_serializer.serialize_operation_result(operation_result)
```

### 3. Document Templates

```python
from src.integration.toon_templates import (
    TemplateType, create_optimized_document, get_fleet_overview_template
)

# Use predefined templates
template = get_fleet_overview_template()
content = {"fleet_summary": {...}, "health_status": {...}}
doc = create_optimized_document(content, TemplateType.FLEET_OVERVIEW)

# Custom template creation
from src.integration.toon_templates import TOONTemplate, TOONSectionTemplate, ContentPriority

custom_template = TOONTemplate(
    template_type=TemplateType.FLEET_OVERVIEW,
    name="Custom Fleet Report",
    description="Tailored fleet overview",
    sections=[
        TOONSectionTemplate("summary", ContentPriority.CRITICAL, 200),
        TOONSectionTemplate("performance", ContentPriority.IMPORTANT, 300)
    ],
    global_token_limit=1000
)
```

### 4. LLM Formatter

```python
from src.integration.toon_llm_formatter import (
    TOONLLMFormatter, FormattingContext, LLMFormat, ContextType
)

formatter = TOONLLMFormatter()

# Different formatting styles
contexts = [
    FormattingContext(format_style=LLMFormat.CONVERSATIONAL),
    FormattingContext(format_style=LLMFormat.EXECUTIVE),
    FormattingContext(format_style=LLMFormat.TECHNICAL),
    FormattingContext(format_style=LLMFormat.ACTIONABLE)
]

for context in contexts:
    response = formatter.format_for_conversation(document, context)
    print(f"{context.format_style.value}: {response.content[:100]}...")
```

## Usage Patterns

### Pattern 1: Real-time Fleet Monitoring

```python
import asyncio
from datetime import datetime
from src.integration.toon_system_integration import get_system_integrator

class FleetMonitor:
    def __init__(self):
        self.integrator = get_system_integrator()
        self.alert_threshold = 0.8
    
    async def monitor_fleet_health(self):
        while True:
            try:
                # Get fleet data
                fleet_data = await self.get_fleet_data()
                
                # Create TOON report
                result = self.integrator.integrate_fleet_inventory(fleet_data)
                
                # Check for alerts
                if result.quality_score < self.alert_threshold:
                    await self.send_alert(result)
                
                # Log metrics
                self.log_metrics(result)
                
                await asyncio.sleep(60)  # Monitor every minute
                
            except Exception as e:
                await self.handle_error(e)
    
    async def get_fleet_data(self):
        # Integrate with actual fleet data sources
        return {"hosts": [...], "services": [...]}
    
    async def send_alert(self, result):
        print(f"ALERT: Fleet health degraded - Score: {result.quality_score}")
        # Send to alerting system
    
    def log_metrics(self, result):
        print(f"Metrics: Tokens={result.token_reduction:.1f}%, "
              f"Quality={result.quality_score:.2f}, "
              f"Time={result.processing_time:.3f}s")

# Usage
monitor = FleetMonitor()
asyncio.run(monitor.monitor_fleet_health())
```

### Pattern 2: Batch Operations Analysis

```python
from src.integration.toon_performance import optimized_batch_process

def analyze_batch_operations():
    # Large dataset of operations
    operations = [
        {"id": f"op_{i}", "type": "deploy", "status": "success", "duration": 120}
        for i in range(1000)
    ]
    
    # Process with TOON optimization
    results = optimized_batch_process(operations, use_parallel=True)
    
    # Analyze results
    successful_ops = [r for r in results if r and hasattr(r, 'success') and r.success]
    failed_ops = [r for r in results if r and hasattr(r, 'success') and not r.success]
    
    print(f"Processed {len(operations)} operations:")
    print(f"Success rate: {len(successful_ops)/len(operations)*100:.1f}%")
    
    # Get performance insights
    from src.tools.toon_enhanced_tools import get_performance_stats
    stats = get_performance_stats()
    print(f"Performance: {stats}")
```

### Pattern 3: Conversational AI Interface

```python
from src.integration.toon_llm_formatter import (
    TOONLLMFormatter, FormattingContext, LLMFormat, ContextType
)

class ConversationalInterface:
    def __init__(self):
        self.formatter = TOONLLMFormatter()
        self.conversation_history = []
    
    def process_query(self, user_query: str, context_data: dict):
        # Determine query type and context
        query_type = self.classify_query(user_query)
        
        # Create appropriate context
        formatting_context = self.create_context(user_query, query_type, context_data)
        
        # Generate TOON document from context data
        document = self.create_document_from_data(context_data, query_type)
        
        # Format for LLM
        response = self.formatter.format_for_conversation(document, formatting_context)
        
        # Update conversation history
        self.conversation_history.append({
            "user_query": user_query,
            "response": response.content,
            "timestamp": datetime.now()
        })
        
        return response
    
    def classify_query(self, query: str) -> str:
        # Simple classification - in practice, use NLP
        if "health" in query.lower():
            return "health_query"
        elif "performance" in query.lower():
            return "performance_query"
        elif "error" in query.lower():
            return "error_query"
        else:
            return "general_query"
    
    def create_context(self, query: str, query_type: str, data: dict) -> FormattingContext:
        # Determine formatting style based on query
        style_map = {
            "health_query": LLMFormat.EXECUTIVE,
            "performance_query": LLMFormat.TECHNICAL,
            "error_query": LLMFormat.ACTIONABLE,
            "general_query": LLMFormat.CONVERSATIONAL
        }
        
        return FormattingContext(
            format_style=style_map.get(query_type, LLMFormat.CONVERSATIONAL),
            context_type=ContextType.FOLLOW_UP if self.conversation_history else ContextType.INITIAL_QUERY,
            user_expertise="intermediate",
            focus_area=query_type,
            include_recommendations=True,
            previous_context=self.get_relevant_context(query)
        )
    
    def create_document_from_data(self, data: dict, query_type: str):
        # Create TOON document based on query type and data
        doc = TOONDocument(document_type=query_type)
        
        if query_type == "health_query":
            doc.add_section("health_status", data.get("health", {}), ContentPriority.CRITICAL)
            doc.add_section("alerts", data.get("alerts", []), ContentPriority.CRITICAL)
        elif query_type == "performance_query":
            doc.add_section("metrics", data.get("metrics", {}), ContentPriority.IMPORTANT)
            doc.add_section("trends", data.get("trends", {}), ContentPriority.INFO)
        
        return doc
    
    def get_relevant_context(self, query: str):
        # Extract relevant context from conversation history
        return self.conversation_history[-3:] if len(self.conversation_history) >= 3 else []

# Usage
interface = ConversationalInterface()
response = interface.process_query(
    "What's the current fleet health status?",
    {"health": {"score": 0.85}, "alerts": ["High CPU on host1"]}
)
print(response.content)
```

### Pattern 4: Quality-Guided Optimization

```python
from src.utils.toon_quality import (
    TOONQualityAssurance, QualityLevel, optimize_toon_document, validate_toon_document
)

def create_quality_optimized_report(raw_data: dict):
    # Create initial document
    initial_doc = create_document_from_raw_data(raw_data)
    
    # Validate quality
    quality_report = validate_toon_document(initial_doc)
    
    print(f"Initial quality: {quality_report.quality_level.value} "
          f"(Score: {quality_report.overall_score:.2f})")
    
    # Check if optimization needed
    if quality_report.quality_level.value in ["poor", "failed"]:
        print("Optimizing document...")
        
        # Apply automatic fixes
        optimized_doc, optimization_report = optimize_toon_document(initial_doc)
        
        # Validate optimized version
        final_report = validate_toon_document(optimized_doc)
        
        print(f"Optimized quality: {final_report.quality_level.value} "
              f"(Score: {final_report.overall_score:.2f})")
        
        return optimized_doc, final_report
    else:
        print("Document quality is acceptable")
        return initial_doc, quality_report

def create_document_from_raw_data(raw_data: dict):
    # Convert raw data to TOON document
    doc = TOONDocument(document_type="optimization_test")
    
    # Process different data types
    if "fleet" in raw_data:
        doc.add_section("fleet_summary", raw_data["fleet"], ContentPriority.CRITICAL)
    
    if "events" in raw_data:
        doc.add_section("events", raw_data["events"], ContentPriority.IMPORTANT)
    
    if "metrics" in raw_data:
        doc.add_section("metrics", raw_data["metrics"], ContentPriority.INFO)
    
    return doc

# Usage
raw_data = {
    "fleet": {"hosts": 50, "healthy": 45},
    "events": [{"severity": "error", "message": "Connection timeout"}],
    "metrics": {"cpu": 45, "memory": 62}
}

optimized_doc, quality_report = create_quality_optimized_report(raw_data)
print(f"Final document: {optimized_doc.to_llm_optimized()[:200]}...")
```

## Integration Examples

### Example 1: Fleet Inventory Integration

```python
from src.integration.toon_system_integration import integrate_fleet_inventory_toon
from src.models.fleet_inventory import FleetInventory, ProxmoxHost

# Create fleet inventory
inventory = FleetInventory()

# Add Proxmox host
host = ProxmoxHost(
    id="proxmox-01",
    hostname="proxmox-server-01",
    address="192.168.1.10",
    cpu_cores=8,
    memory_mb=32768,
    storage_gb=1000
)
inventory.add_proxmox_host(host)

# Integrate with TOON
result = integrate_fleet_inventory_toon(inventory)

print("Fleet Status (TOON Optimized):")
print(result.formatted_response)
print(f"\nMetadata:")
print(f"- Token reduction: {result.token_reduction:.1f}%")
print(f"- Quality score: {result.quality_score:.2f}")
print(f"- Processing time: {result.processing_time:.3f}s")
```

### Example 2: Events System Integration

```python
from src.integration.toon_system_integration import integrate_events_toon
from src.models.event_models import SystemEvent, EventSeverity

# Create events
events = []
for i in range(20):
    event = SystemEvent(
        id=f"evt_{i}",
        event_type="system_monitor",
        severity=EventSeverity.WARNING if i % 3 == 0 else EventSeverity.INFO,
        source=f"host_{i % 5}",
        message=f"Event {i} description",
        timestamp=datetime.now() - timedelta(minutes=i)
    )
    events.append(event)

# Integrate with TOON
result = integrate_events_toon(events, time_range="1h")

print("Events Analysis (TOON Optimized):")
print(result.formatted_response)
print(f"\nInsights: {result.metadata.get('event_insights', [])}")
print(f"Patterns: {result.metadata.get('event_patterns', [])}")
```

### Example 3: Multi-System Dashboard

```python
from src.integration.toon_system_integration import create_system_dashboard_toon

# Aggregate data from multiple systems
system_data = {
    "fleet": {
        "status": "healthy",
        "health_score": 0.89,
        "total_hosts": 25,
        "critical_issues": 1
    },
    "events": {
        "status": "active",
        "event_count": 156,
        "critical_events": 3,
        "trend": "increasing"
    },
    "operations": {
        "status": "running",
        "success_rate": 0.94,
        "pending_operations": 5,
        "avg_duration": 180
    },
    "security": {
        "status": "secure",
        "threat_level": "low",
        "compliance_score": 0.92,
        "open_vulnerabilities": 2
    }
}

# Create TOON dashboard
result = create_system_dashboard_toon(system_data)

print("System Dashboard (TOON Optimized):")
print(result.formatted_response)
print(f"\nKey Metrics: {result.metadata.get('key_metrics', {})}")
print(f"Priority Actions: {result.metadata.get('priority_actions', [])}")
```

## Configuration Management

### Environment-Specific Configuration

```python
from src.integration.toon_config import (
    get_toon_config, update_toon_config, create_production_config,
    create_development_config, load_toon_config_from_env
)

# Load configuration
config = get_toon_config()

# Update configuration
update_toon_config({
    "environment": "production",
    "serialization": {
        "default_token_budget": 3000,
        "compression_enabled": True
    },
    "performance": {
        "caching_enabled": True,
        "batch_size": 200
    }
})

# Use environment presets
production_config = create_production_config()
development_config = create_development_config()

# Load from environment variables
load_toon_config_from_env()
```

### Configuration File

Create `config/toon_config.yaml`:

```yaml
version: "1.0.0"
toon_version: "1.1"
environment: "production"
debug_mode: false
logging_level: "INFO"

features:
  enhanced_serialization: true
  llm_optimization: true
  performance_optimization: true
  quality_assurance: true

serialization:
  default_token_budget: 4000
  compression_enabled: true
  smart_prioritization: true
  min_token_efficiency: 0.6

templates:
  fleet_overview_enabled: true
  fleet_overview_token_limit: 3000
  operation_result_enabled: true
  operation_result_token_limit: 1000

llm:
  default_format_style: "conversational"
  default_user_expertise: "intermediate"
  include_recommendations: true
  quality_threshold: 0.8

performance:
  caching_enabled: true
  cache_ttl_seconds: 300
  batch_processing_enabled: true
  batch_size: 100
  max_concurrent_operations: 4

quality:
  validation_enabled: true
  min_quality_score: 0.7
  auto_fix_enabled: true
  required_sections:
    - "summary"
    - "status"
    - "recommendations"
```

## Performance Optimization

### Caching Strategy

```python
from src.integration.toon_performance import get_performance_optimizer

optimizer = get_performance_optimizer()

# Enable caching
config = get_toon_config()
config.performance.caching_enabled = True
config.performance.cache_ttl_seconds = 300

# Monitor cache performance
stats = optimizer.get_performance_metrics()
print(f"Cache hit ratio: {stats.get('cache_hit_ratio', 0):.2%}")

# Clear cache if needed
optimizer.clear_cache()
```

### Batch Processing

```python
from src.integration.toon_performance import optimized_batch_process

def process_large_dataset():
    # Large dataset
    data = [{"id": i, "value": f"data_{i}"} for i in range(10000)]
    
    # Process with batching and parallelization
    results = optimized_batch_process(data, use_parallel=True)
    
    print(f"Processed {len(data)} items")
    print(f"Results: {len(results)} documents created")
    
    return results
```

### Memory Management

```python
from src.integration.toon_performance import get_memory_manager

memory_manager = get_memory_manager()

# Monitor memory usage
stats = memory_manager.get_memory_stats()
print(f"Memory usage: {stats['current_usage_mb']:.1f}MB")
print(f"Available: {stats['available_mb']:.1f}MB")

# Optimize memory usage
if stats['usage_percent'] > 80:
    # Compress large documents
    compressed = memory_manager.compress_large_documents(size_threshold_mb=10)
    print(f"Compressed {compressed} large documents")
    
    # Archive old documents
    cutoff = datetime.now() - timedelta(days=7)
    archived = memory_manager.archive_old_documents(cutoff)
    print(f"Archived {archived} old documents")
```

## Quality Assurance

### Automatic Quality Checks

```python
from src.utils.toon_quality import validate_toon_document, QualityLevel

def ensure_document_quality(document):
    # Validate document
    report = validate_toon_document(document)
    
    # Check quality level
    if report.quality_level == QualityLevel.FAILED:
        raise ValueError(f"Document failed quality checks: {report.issues}")
    elif report.quality_level == QualityLevel.POOR:
        print(f"Warning: Document quality is poor: {report.issues}")
    
    return report

def optimize_document_quality(document):
    from src.utils.toon_quality import optimize_toon_document
    
    # Apply automatic optimizations
    optimized_doc, quality_report = optimize_toon_document(document)
    
    print(f"Quality improved from {quality_report.overall_score:.2f}")
    
    return optimized_doc
```

### Quality Monitoring

```python
def monitor_quality_metrics():
    from src.utils.toon_quality import get_quality_assurance
    
    qa = get_quality_assurance()
    
    # Get quality distribution
    stats = get_system_integrator().get_integration_statistics()
    quality_dist = stats.get("quality_distribution", {})
    
    print("Quality Distribution:")
    for level, count in quality_dist.items():
        print(f"  {level}: {count} documents")
    
    # Alert on quality issues
    if quality_dist.get("poor", 0) > 5:
        print("ALERT: High number of poor quality documents detected")
    
    return quality_dist
```

## Best Practices

### 1. Token Budget Management

```python
# Always consider token limits
def create_efficient_document(data, max_tokens=4000):
    doc = TOONDocument(document_type="optimized")
    
    # Add content in priority order
    priorities = [
        (ContentPriority.CRITICAL, ["summary", "alerts", "errors"]),
        (ContentPriority.IMPORTANT, ["metrics", "status", "trends"]),
        (ContentPriority.INFO, ["details", "logs", "debug"])
    ]
    
    for priority, sections in priorities:
        for section in sections:
            if section in data:
                estimated_tokens = estimate_tokens(data[section])
                if doc.estimated_token_count() + estimated_tokens < max_tokens:
                    doc.add_section(section, data[section], priority)
    
    return doc

def estimate_tokens(content):
    # Rough token estimation
    if isinstance(content, str):
        return len(content.split())
    elif isinstance(content, (dict, list)):
        return len(str(content).split())
    return 1
```

### 2. Content Prioritization

```python
def prioritize_content(data):
    """Prioritize content for LLM consumption."""
    
    # Critical content (always include)
    critical = {
        "health_score": data.get("health_score"),
        "critical_issues": data.get("critical_issues", []),
        "operational_status": data.get("status")
    }
    
    # Important content (include if space permits)
    important = {
        "metrics": data.get("metrics", {}),
        "recent_events": data.get("recent_events", [])[:10],
        "trends": data.get("trends", {})
    }
    
    # Informational content (include if space permits)
    informational = {
        "details": data.get("details", {}),
        "configuration": data.get("config", {}),
        "debug_info": data.get("debug", {})
    }
    
    return {
        "critical": critical,
        "important": important,
        "informational": informational
    }
```

### 3. Error Handling

```python
def robust_toon_integration(data):
    """Robust TOON integration with error handling."""
    try:
        # Try TOON integration
        result = integrate_fleet_inventory_toon(data)
        if result.success:
            return result
    except Exception as e:
        print(f"TOON integration failed: {e}")
    
    # Fallback to standard format
    try:
        return {
            "success": False,
            "fallback": True,
            "data": data,
            "error": "TOON integration failed"
        }
    except Exception as fallback_error:
        return {
            "success": False,
            "fallback": False,
            "error": f"Both TOON and fallback failed: {fallback_error}"
        }
```

### 4. Performance Monitoring

```python
import time
from functools import wraps

def monitor_performance(func):
    """Decorator to monitor TOON operation performance."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        try:
            result = func(*args, **kwargs)
            success = True
        except Exception as e:
            result = {"error": str(e)}
            success = False
        finally:
            duration = time.time() - start_time
            
            # Log performance metrics
            print(f"{func.__name__}: {duration:.3f}s (success: {success})")
            
            # Alert on slow operations
            if duration > 5.0:
                print(f"ALERT: Slow operation detected: {func.__name__}")
        
        return result
    return wrapper

# Usage
@monitor_performance
def get_fleet_status():
    return get_fleet_status_toon(hours=24)
```

## Troubleshooting

### Common Issues and Solutions

#### 1. Token Limit Exceeded

**Problem**: Document exceeds token budget
```python
# Error: Document exceeds token limit: 4500 > 4000
```

**Solution**:
```python
from src.integration.toon_llm_formatter import TOONLLMFormatter

formatter = TOONLLMFormatter()
optimized_content, included_sections = formatter.optimize_for_token_limit(
    document, target_token_limit=3000
)
print(f"Included sections: {included_sections}")
```

#### 2. Quality Score Too Low

**Problem**: Document quality score below threshold
```python
# Quality score: 0.45 (below 0.7 threshold)
```

**Solution**:
```python
from src.utils.toon_quality import optimize_toon_document

optimized_doc, report = optimize_toon_document(document)
print(f"Improved quality score: {report.overall_score:.2f}")
```

#### 3. Performance Issues

**Problem**: Slow serialization performance
```python
# Processing time: 10.5s (too slow)
```

**Solution**:
```python
from src.integration.toon_performance import get_performance_optimizer

optimizer = get_performance_optimizer()

# Enable caching and parallel processing
config = get_toon_config()
config.performance.caching_enabled = True
config.performance.parallel_processing_enabled = True

# Use batch processing
results = optimizer.batch_serialize(data, batch_size=50)
```

#### 4. Memory Issues

**Problem**: High memory usage
```python
# Memory usage: 2.1GB (exceeds 2GB limit)
```

**Solution**:
```python
from src.integration.toon_performance import get_memory_manager

memory_manager = get_memory_manager()

# Compress large documents
compressed = memory_manager.compress_large_documents(size_threshold_mb=5)
print(f"Compressed {compressed} documents")

# Archive old documents
cutoff = datetime.now() - timedelta(days=3)
archived = memory_manager.archive_old_documents(cutoff)
print(f"Archived {archived} documents")
```

### Debug Mode

```python
# Enable debug mode for detailed logging
from src.integration.toon_config import update_toon_config

update_toon_config({
    "debug_mode": True,
    "logging_level": "DEBUG"
})

# Check configuration
config = get_toon_config()
print(f"Debug mode: {config.debug_mode}")
print(f"Logging level: {config.logging_level}")
```

### Performance Profiling

```python
def profile_toon_operations():
    """Profile TOON operations for optimization."""
    import cProfile
    import pstats
    
    # Profile TOON operations
    profiler = cProfile.Profile()
    profiler.enable()
    
    # Run TOON operations
    result = get_fleet_status_toon(hours=24)
    events_result = get_events_summary_toon(hours=6)
    
    profiler.disable()
    
    # Analyze results
    stats = pstats.Stats(profiler)
    stats.sort_stats('cumulative')
    stats.print_stats(10)  # Top 10 functions
    
    return stats

# Run profiling
profile_toon_operations()
```

## Conclusion

The TOON integration provides a powerful, efficient framework for LLM-facing serialization in TailOpsMCP. Key benefits include:

- **50-70% token reduction** while preserving information density
- **Quality assurance** with automatic optimization
- **Performance optimization** with caching and parallel processing
- **Flexible configuration** for different environments and use cases
- **Comprehensive testing** ensuring reliability

For additional support or questions, refer to the test suite in `tests/test_toon_integration.py` for detailed usage examples.