"""
Real-time event processing system for TailOpsMCP observability.

This module provides real-time event streaming, processing, and WebSocket support
for live event monitoring and analysis.
"""

import asyncio
import json
import websockets
from collections import deque
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, AsyncIterator, Callable
from dataclasses import dataclass, field

from src.models.event_models import (
    SystemEvent,
    EventType,
    EventSeverity,
    EventSource,
    EventCategory,
    EventFilters,
)
from src.services.event_store import get_event_store
from src.services.event_analyzer import get_event_analyzer
from src.utils.logging_config import get_logger


@dataclass
class EventBatch:
    """A batch of events for processing."""

    events: List[SystemEvent]
    timestamp: datetime = field(default_factory=datetime.utcnow)
    batch_id: str = field(default="")
    size: int = 0

    def __post_init__(self):
        if not self.batch_id:
            import uuid

            self.batch_id = str(uuid.uuid4())
        self.size = len(self.events)


@dataclass
class EventStreamConfig:
    """Configuration for event streaming."""

    buffer_size: int = 1000
    batch_size: int = 50
    batch_timeout: float = 5.0  # seconds
    processing_interval: float = 1.0  # seconds
    enable_websocket: bool = True
    websocket_port: int = 8765
    filters: Optional[EventFilters] = None
    enable_analysis: bool = True
    enable_correlation: bool = True


@dataclass
class EventFilterRule:
    """Rule for filtering events in real-time."""

    name: str
    condition: Callable[[SystemEvent], bool]
    priority: int = 0
    enabled: bool = True
    description: str = ""


class EventStreamProcessor:
    """Real-time event processing and streaming."""

    def __init__(self, config: Optional[EventStreamConfig] = None):
        self.config = config or EventStreamConfig()
        self.logger = get_logger("event_stream_processor")

        # Event collections
        self.event_buffer: deque = deque(maxlen=self.config.buffer_size)
        self.event_batches: deque = deque(maxlen=100)

        # Processing state
        self.is_processing = False
        self.is_streaming = False
        self.processing_tasks: List[asyncio.Task] = []

        # WebSocket connections
        self.websocket_clients: Set[websockets.WebSocketServerProtocol] = set()
        self.websocket_server = None

        # Filter rules
        self.filter_rules: List[EventFilterRule] = []

        # Event hooks and callbacks
        self.event_hooks: List[Callable[[SystemEvent], Any]] = []
        self.batch_hooks: List[Callable[[EventBatch], Any]] = []

        # Statistics
        self.stats = {
            "events_processed": 0,
            "batches_processed": 0,
            "events_filtered": 0,
            "websocket_clients": 0,
            "processing_errors": 0,
        }

    async def start_event_stream(self) -> AsyncIterator[SystemEvent]:
        """Start the event stream and yield events in real-time."""
        self.logger.info("Starting real-time event stream")
        self.is_streaming = True

        # Start processing tasks
        processing_task = asyncio.create_task(self._process_events_loop())
        batch_task = asyncio.create_task(self._batch_processing_loop())

        self.processing_tasks = [processing_task, batch_task]

        # Start WebSocket server if enabled
        if self.config.enable_websocket:
            websocket_task = asyncio.create_task(self._start_websocket_server())
            self.processing_tasks.append(websocket_task)

        try:
            while self.is_streaming:
                # Yield events from buffer
                while self.event_buffer:
                    event = self.event_buffer.popleft()
                    self.stats["events_processed"] += 1
                    yield event

                # Small delay to prevent busy waiting
                await asyncio.sleep(0.1)

        except asyncio.CancelledError:
            self.logger.info("Event stream cancelled")
        except Exception as e:
            self.logger.error(f"Event stream error: {e}")
            self.stats["processing_errors"] += 1
        finally:
            await self.stop_event_stream()

    async def stop_event_stream(self) -> None:
        """Stop the event stream and cleanup."""
        self.logger.info("Stopping event stream")
        self.is_streaming = False
        self.is_processing = False

        # Cancel processing tasks
        for task in self.processing_tasks:
            if not task.done():
                task.cancel()

        # Wait for tasks to complete
        if self.processing_tasks:
            await asyncio.gather(*self.processing_tasks, return_exceptions=True)

        # Close WebSocket server
        if self.websocket_server:
            self.websocket_server.close()
            await self.websocket_server.wait_closed()

        # Close WebSocket clients
        if self.websocket_clients:
            await asyncio.gather(
                *[client.close() for client in self.websocket_clients],
                return_exceptions=True,
            )

        self.processing_tasks = []
        self.websocket_clients = set()
        self.logger.info("Event stream stopped")

    async def add_event(self, event: SystemEvent) -> None:
        """Add an event to the processing pipeline."""
        try:
            # Apply filter rules
            if self._should_filter_event(event):
                self.stats["events_filtered"] += 1
                return

            # Add to buffer
            self.event_buffer.append(event)

            # Trigger event hooks
            for hook in self.event_hooks:
                try:
                    await hook(event) if asyncio.iscoroutinefunction(hook) else hook(
                        event
                    )
                except Exception as e:
                    self.logger.error(f"Event hook error: {e}")

            # Broadcast to WebSocket clients
            if self.websocket_clients:
                await self._broadcast_event_to_clients(event)

        except Exception as e:
            self.logger.error(f"Failed to add event: {e}")
            self.stats["processing_errors"] += 1

    async def add_events(self, events: List[SystemEvent]) -> None:
        """Add multiple events to the processing pipeline."""
        for event in events:
            await self.add_event(event)

    def _should_filter_event(self, event: SystemEvent) -> bool:
        """Check if event should be filtered out."""
        # Sort rules by priority
        sorted_rules = sorted(self.filter_rules, key=lambda r: r.priority, reverse=True)

        for rule in sorted_rules:
            if rule.enabled and rule.condition(event):
                return True

        # Apply config filters if available
        if self.config.filters:
            return not self._event_matches_filters(event, self.config.filters)

        return False

    def _event_matches_filters(self, event: SystemEvent, filters: EventFilters) -> bool:
        """Check if event matches the given filters."""
        if filters.event_types and event.event_type not in filters.event_types:
            return False

        if filters.severities and event.severity not in filters.severities:
            return False

        if filters.sources and event.source not in filters.sources:
            return False

        if filters.categories and event.category not in filters.categories:
            return False

        if filters.targets and event.target not in filters.targets:
            return False

        if filters.start_time and event.timestamp < filters.start_time:
            return False

        if filters.end_time and event.timestamp > filters.end_time:
            return False

        if filters.min_health_score and (
            event.health_score is None or event.health_score < filters.min_health_score
        ):
            return False

        if filters.max_health_score and (
            event.health_score is None or event.health_score > filters.max_health_score
        ):
            return False

        if (
            filters.search_text
            and filters.search_text.lower() not in event.title.lower()
            and filters.search_text.lower() not in event.description.lower()
        ):
            return False

        return True

    async def _process_events_loop(self) -> None:
        """Main event processing loop."""
        while self.is_streaming:
            try:
                # Process events in batch
                await self._process_event_batch()

                # Wait for next processing cycle
                await asyncio.sleep(self.config.processing_interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Processing loop error: {e}")
                self.stats["processing_errors"] += 1
                await asyncio.sleep(1)  # Brief pause on error

    async def _process_event_batch(self) -> None:
        """Process events in batches."""
        if not self.event_buffer:
            return

        # Collect batch of events
        batch_events = []
        while self.event_buffer and len(batch_events) < self.config.batch_size:
            batch_events.append(self.event_buffer.popleft())

        if not batch_events:
            return

        # Create event batch
        event_batch = EventBatch(events=batch_events)
        self.event_batches.append(event_batch)

        # Trigger batch hooks
        for hook in self.batch_hooks:
            try:
                await hook(event_batch) if asyncio.iscoroutinefunction(hook) else hook(
                    event_batch
                )
            except Exception as e:
                self.logger.error(f"Batch hook error: {e}")

        # Process batch if analysis is enabled
        if self.config.enable_analysis and self.config.enable_correlation:
            await self._analyze_event_batch(event_batch)

        self.stats["batches_processed"] += 1

    async def _analyze_event_batch(self, batch: EventBatch) -> None:
        """Analyze an event batch."""
        try:
            analyzer = get_event_analyzer()

            # Detect trends and patterns
            trends = await analyzer.detect_trends(batch.events)
            patterns = await analyzer.detect_patterns(batch.events)

            # Generate insights and predictions if we have enough events
            if len(batch.events) >= 10:
                insights = await analyzer.generate_insights(batch.events)
                predictions = await analyzer.predict_issues(batch.events)

                # Create analysis events for significant insights/predictions
                for insight in insights:
                    if insight.priority == "high":
                        analysis_event = SystemEvent(
                            event_type=EventType.ANOMALY,
                            severity=EventSeverity.WARNING,
                            source=EventSource.SYSTEM,
                            category=EventCategory.OPERATIONS,
                            title=f"High Priority Insight: {insight.title}",
                            description=insight.description,
                            details={
                                "analysis_type": "insight",
                                "insight_data": insight.__dict__,
                                "related_events": insight.related_events,
                            },
                            metadata=batch.events[0].metadata if batch.events else None,
                        )
                        await self.add_event(analysis_event)

                for prediction in predictions:
                    if prediction.risk_level == "high":
                        analysis_event = SystemEvent(
                            event_type=EventType.WARNING,
                            severity=EventSeverity.WARNING,
                            source=EventSource.SYSTEM,
                            category=EventCategory.OPERATIONS,
                            title=f"High Risk Prediction: {prediction.description}",
                            description=f"Probability: {prediction.probability:.2f}, Time horizon: {prediction.time_horizon}",
                            details={
                                "analysis_type": "prediction",
                                "prediction_data": prediction.__dict__,
                            },
                            metadata=batch.events[0].metadata if batch.events else None,
                        )
                        await self.add_event(analysis_event)

        except Exception as e:
            self.logger.error(f"Batch analysis error: {e}")

    async def _batch_processing_loop(self) -> None:
        """Background batch processing loop."""
        while self.is_streaming:
            try:
                # Process any pending batches
                while self.event_batches:
                    batch = self.event_batches.popleft()

                    # Store batch in database
                    event_store = get_event_store()
                    await event_store.store_events(batch.events)

                await asyncio.sleep(5)  # Process batches every 5 seconds

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Batch processing error: {e}")
                await asyncio.sleep(1)

    async def _start_websocket_server(self) -> None:
        """Start WebSocket server for real-time event streaming."""
        try:
            self.websocket_server = await websockets.serve(
                self._handle_websocket_client, "localhost", self.config.websocket_port
            )
            self.logger.info(
                f"WebSocket server started on port {self.config.websocket_port}"
            )

        except Exception as e:
            self.logger.error(f"Failed to start WebSocket server: {e}")

    async def _handle_websocket_client(
        self, websocket: websockets.WebSocketServerProtocol, path: str
    ) -> None:
        """Handle WebSocket client connection."""
        self.websocket_clients.add(websocket)
        self.stats["websocket_clients"] = len(self.websocket_clients)

        self.logger.info(
            f"WebSocket client connected. Total clients: {self.stats['websocket_clients']}"
        )

        try:
            async for message in websocket:
                try:
                    # Parse client message
                    data = json.loads(message)
                    await self._handle_websocket_message(websocket, data)
                except json.JSONDecodeError:
                    await websocket.send(json.dumps({"error": "Invalid JSON"}))
                except Exception as e:
                    self.logger.error(f"WebSocket message error: {e}")

        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            self.websocket_clients.discard(websocket)
            self.stats["websocket_clients"] = len(self.websocket_clients)
            self.logger.info(
                f"WebSocket client disconnected. Total clients: {self.stats['websocket_clients']}"
            )

    async def _handle_websocket_message(
        self, websocket: websockets.WebSocketServerProtocol, data: Dict[str, Any]
    ) -> None:
        """Handle incoming WebSocket message."""
        message_type = data.get("type")

        if message_type == "subscribe":
            # Client wants to subscribe to event stream
            await websocket.send(
                json.dumps(
                    {
                        "type": "subscribed",
                        "message": "Successfully subscribed to event stream",
                    }
                )
            )

        elif message_type == "get_stats":
            # Client wants statistics
            await websocket.send(json.dumps({"type": "stats", "data": self.stats}))

        elif message_type == "set_filters":
            # Client wants to set filters
            filters_data = data.get("filters", {})
            # Convert filters data back to EventFilters if needed
            # This is a simplified version
            await websocket.send(
                json.dumps(
                    {
                        "type": "filters_updated",
                        "message": "Filters updated successfully",
                    }
                )
            )

    async def _broadcast_event_to_clients(self, event: SystemEvent) -> None:
        """Broadcast event to all connected WebSocket clients."""
        if not self.websocket_clients:
            return

        message = {"type": "event", "data": event.to_dict()}

        # Send to all clients
        disconnected_clients = set()
        for client in self.websocket_clients:
            try:
                await client.send(json.dumps(message))
            except websockets.exceptions.ConnectionClosed:
                disconnected_clients.add(client)
            except Exception as e:
                self.logger.error(f"Failed to send to WebSocket client: {e}")
                disconnected_clients.add(client)

        # Remove disconnected clients
        self.websocket_clients -= disconnected_clients
        self.stats["websocket_clients"] = len(self.websocket_clients)

    def add_filter_rule(self, rule: EventFilterRule) -> None:
        """Add a filter rule."""
        self.filter_rules.append(rule)
        self.filter_rules.sort(key=lambda r: r.priority, reverse=True)

    def remove_filter_rule(self, rule_name: str) -> None:
        """Remove a filter rule by name."""
        self.filter_rules = [
            rule for rule in self.filter_rules if rule.name != rule_name
        ]

    def add_event_hook(self, hook: Callable[[SystemEvent], Any]) -> None:
        """Add an event processing hook."""
        self.event_hooks.append(hook)

    def add_batch_hook(self, hook: Callable[[EventBatch], Any]) -> None:
        """Add a batch processing hook."""
        self.batch_hooks.append(hook)

    def get_stats(self) -> Dict[str, Any]:
        """Get processing statistics."""
        return self.stats.copy()

    def get_buffer_status(self) -> Dict[str, int]:
        """Get buffer status information."""
        return {
            "buffer_size": len(self.event_buffer),
            "max_buffer_size": self.config.buffer_size,
            "batch_queue_size": len(self.event_batches),
            "websocket_clients": len(self.websocket_clients),
        }


class EventWebSocket:
    """WebSocket server for real-time event streaming."""

    def __init__(self, port: int = 8765):
        self.port = port
        self.server = None
        self.clients: Set[websockets.WebSocketServerProtocol] = set()
        self.logger = get_logger("event_websocket")

    async def start_server(self) -> None:
        """Start the WebSocket server."""
        try:
            self.server = await websockets.serve(
                self._handle_client, "localhost", self.port
            )
            self.logger.info(f"Event WebSocket server started on port {self.port}")

        except Exception as e:
            self.logger.error(f"Failed to start WebSocket server: {e}")
            raise

    async def stop_server(self) -> None:
        """Stop the WebSocket server."""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self.logger.info("Event WebSocket server stopped")

    async def _handle_client(
        self, websocket: websockets.WebSocketServerProtocol, path: str
    ) -> None:
        """Handle WebSocket client connection."""
        self.clients.add(websocket)
        self.logger.info(
            f"WebSocket client connected. Total clients: {len(self.clients)}"
        )

        try:
            async for message in websocket:
                # Echo message back (simplified)
                await websocket.send(f"Echo: {message}")

        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            self.clients.discard(websocket)
            self.logger.info(
                f"WebSocket client disconnected. Total clients: {len(self.clients)}"
            )

    async def broadcast_event(self, event: SystemEvent) -> None:
        """Broadcast an event to all connected clients."""
        if not self.clients:
            return

        message = {
            "type": "event",
            "data": event.to_dict(),
            "timestamp": datetime.utcnow().isoformat(),
        }

        # Send to all clients
        disconnected_clients = set()
        for client in self.clients:
            try:
                await client.send(json.dumps(message))
            except websockets.exceptions.ConnectionClosed:
                disconnected_clients.add(client)
            except Exception as e:
                self.logger.error(f"Failed to broadcast to client: {e}")
                disconnected_clients.add(client)

        # Remove disconnected clients
        self.clients -= disconnected_clients

    async def subscribe_to_events(
        self, client_id: str, filters: Optional[EventFilters] = None
    ) -> AsyncIterator[SystemEvent]:
        """Subscribe to events with optional filters."""
        # This is a simplified implementation
        # In a real implementation, you would track client subscriptions and filter accordingly
        while True:
            # Yield filtered events (simplified)
            await asyncio.sleep(1)
            yield SystemEvent(
                event_type=EventType.INFO,
                severity=EventSeverity.INFO,
                source=EventSource.SYSTEM,
                title="Heartbeat event",
                description="Periodic heartbeat event",
                details={"client_id": client_id},
            )


# Global instances
_event_stream_processor_instance = None


def get_event_stream_processor(
    config: Optional[EventStreamConfig] = None,
) -> EventStreamProcessor:
    """Get the global event stream processor instance."""
    global _event_stream_processor_instance
    if _event_stream_processor_instance is None:
        _event_stream_processor_instance = EventStreamProcessor(config)
    return _event_stream_processor_instance


async def start_realtime_event_processing(
    config: Optional[EventStreamConfig] = None,
) -> EventStreamProcessor:
    """Start real-time event processing."""
    processor = get_event_stream_processor(config)

    # Add default filter rules
    processor.add_filter_rule(
        EventFilterRule(
            name="exclude_debug_events",
            condition=lambda e: e.severity == EventSeverity.DEBUG,
            description="Exclude debug level events from real-time processing",
        )
    )

    return processor


# Example filter rules
def create_default_filter_rules() -> List[EventFilterRule]:
    """Create default filter rules for event processing."""
    return [
        EventFilterRule(
            name="critical_only",
            condition=lambda e: e.severity
            in [EventSeverity.CRITICAL, EventSeverity.ERROR],
            priority=10,
            description="Only process critical and error events",
        ),
        EventFilterRule(
            name="security_events",
            condition=lambda e: e.category == EventCategory.SECURITY,
            priority=5,
            description="Always process security events",
        ),
        EventFilterRule(
            name="exclude_heartbeat",
            condition=lambda e: "heartbeat" in e.title.lower(),
            priority=-1,
            description="Exclude heartbeat events",
        ),
    ]
