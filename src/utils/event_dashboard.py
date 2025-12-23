"""
Event Dashboard and Visualization for TailOpsMCP observability.

This module provides a web-based dashboard for visualizing events, trends, and system health.
"""

import asyncio
import json
from datetime import datetime
from datetime import timezone, timezone
from typing import Any, Dict
from pathlib import Path

from aiohttp import web, WSMsgType
import aiohttp_jinja2
import jinja2

from src.services.event_reporting import get_event_reporting, TimeRange
from src.services.event_store import get_event_store
from src.services.event_alerting import get_event_alerting
from src.services.event_analyzer import get_event_analyzer
from src.utils.error_sanitizer import sanitize_error_message, create_safe_error_response
from src.utils.logging_config import get_logger


class EventDashboard:
    """Web-based event dashboard."""

    def __init__(self, host: str = "localhost", port: int = 8080):
        self.host = host
        self.port = port
        self.logger = get_logger("event_dashboard")
        self.app = None
        self.websocket_connections = set()

        # Initialize services
        self.event_reporting = get_event_reporting()
        self.event_store = get_event_store()
        self.event_alerting = get_event_alerting()
        self.event_analyzer = get_event_analyzer()

    async def create_app(self) -> web.Application:
        """Create the web application."""
        # Setup Jinja2 templates
        template_dir = Path("./templates")
        template_dir.mkdir(exist_ok=True)

        self.app = web.Application()

        # Add Jinja2 template loader
        loader = jinja2.FileSystemLoader(str(template_dir))
        aiohttp_jinja2.setup(self.app, loader=loader)

        # Add routes
        self.app.router.add_get("/", self.index_handler)
        self.app.router.add_get("/api/events", self.events_api_handler)
        self.app.router.add_get("/api/health", self.health_api_handler)
        self.app.router.add_get("/api/security", self.security_api_handler)
        self.app.router.add_get("/api/alerts", self.alerts_api_handler)
        self.app.router.add_get("/api/trends", self.trends_api_handler)
        self.app.router.add_get("/api/statistics", self.statistics_api_handler)
        self.app.router.add_websocket("/ws", self.websocket_handler)

        # Add static files route
        static_dir = Path("./static")
        static_dir.mkdir(exist_ok=True)
        self.app.router.add_static("/static", str(static_dir))

        return self.app

    async def index_handler(self, request) -> web.Response:
        """Handle dashboard index page."""
        try:
            # Get dashboard data
            dashboard_data = await self._get_dashboard_data()

            return aiohttp_jinja2.render_template(
                "dashboard.html", request, dashboard_data
            )
        except Exception as e:
            # Log full error internally for debugging
            self.logger.error(f"Error rendering dashboard: {e}", exc_info=True)

            # Return generic error to user (no stack traces)
            return web.Response(
                text="Dashboard temporarily unavailable. Please try again later.",
                status=500,
            )

    async def events_api_handler(self, request) -> web.Response:
        """Handle events API endpoint."""
        try:
            # Parse query parameters
            hours = int(request.query.get("hours", 24))
            limit = int(request.query.get("limit", 100))

            # Get events
            from src.models.event_models import EventFilters

            time_range = TimeRange.from_hours(hours)
            filters = EventFilters(
                start_time=time_range.start_time,
                end_time=time_range.end_time,
                limit=limit,
            )

            events = await self.event_store.get_events(filters)
            events_data = [event.to_dict() for event in events]

            return web.json_response(
                {
                    "success": True,
                    "events": events_data,
                    "total": len(events_data),
                    "time_range": {
                        "hours": hours,
                        "start_time": time_range.start_time.isoformat(),
                        "end_time": time_range.end_time.isoformat(),
                    },
                }
            )

        except Exception as e:
            # Log full error internally for debugging
            self.logger.error(f"Events API error: {e}", exc_info=True)

            # Return safe error response
            return web.json_response(
                create_safe_error_response(e, include_type=False), status=500
            )

    async def health_api_handler(self, request) -> web.Response:
        """Handle health API endpoint."""
        try:
            hours = int(request.query.get("hours", 24))
            time_range = TimeRange.from_hours(hours)
            health_report = await self.event_reporting.generate_health_report(
                time_range
            )

            return web.json_response(
                {"success": True, "health_data": health_report.to_dict()}
            )

        except Exception as e:
            # Log full error internally for debugging
            self.logger.error(f"Health API error: {e}", exc_info=True)

            # Return safe error response
            return web.json_response(
                create_safe_error_response(e, include_type=False), status=500
            )

    async def security_api_handler(self, request) -> web.Response:
        """Handle security API endpoint."""
        try:
            hours = int(request.query.get("hours", 24))
            time_range = TimeRange.from_hours(hours)
            security_report = await self.event_reporting.generate_security_report(
                time_range
            )

            return web.json_response(
                {"success": True, "security_data": security_report.to_dict()}
            )

        except Exception as e:
            # Log full error internally for debugging
            self.logger.error(f"Security API error: {e}", exc_info=True)

            # Return safe error response
            return web.json_response(
                create_safe_error_response(e, include_type=False), status=500
            )

    async def alerts_api_handler(self, request) -> web.Response:
        """Handle alerts API endpoint."""
        try:
            alerts = await self.event_alerting.get_active_alerts()
            alerts_data = []

            for alert in alerts:
                alert_dict = {
                    "id": alert.id,
                    "rule_name": alert.rule_name,
                    "title": alert.title,
                    "description": alert.description,
                    "severity": alert.severity.value,
                    "status": alert.status.value,
                    "created_at": alert.created_at.isoformat(),
                    "event_count": alert.event_count,
                    "escalation_level": alert.escalation_level,
                }
                alerts_data.append(alert_dict)

            alert_stats = await self.event_alerting.get_alert_statistics()

            return web.json_response(
                {"success": True, "alerts": alerts_data, "statistics": alert_stats}
            )

        except Exception as e:
            # Log full error internally for debugging
            self.logger.error(f"Alerts API error: {e}", exc_info=True)

            # Return safe error response
            return web.json_response(
                create_safe_error_response(e, include_type=False), status=500
            )

    async def trends_api_handler(self, request) -> web.Response:
        """Handle trends API endpoint."""
        try:
            days = int(request.query.get("days", 7))
            time_range = TimeRange.from_days(days)

            # Get events for trend analysis
            from src.models.event_models import EventFilters

            filters = EventFilters(
                start_time=time_range.start_time,
                end_time=time_range.end_time,
                limit=10000,
            )
            events = await self.event_store.get_events(filters)

            # Analyze trends
            trends = await self.event_analyzer.detect_trends(events)
            trends_data = [trend.__dict__ for trend in trends]

            return web.json_response(
                {
                    "success": True,
                    "trends": trends_data,
                    "total_events": len(events),
                    "time_range": {
                        "days": days,
                        "start_time": time_range.start_time.isoformat(),
                        "end_time": time_range.end_time.isoformat(),
                    },
                }
            )

        except Exception as e:
            # Log full error internally for debugging
            self.logger.error(f"Trends API error: {e}", exc_info=True)

            # Return safe error response
            return web.json_response(
                create_safe_error_response(e, include_type=False), status=500
            )

    async def statistics_api_handler(self, request) -> web.Response:
        """Handle statistics API endpoint."""
        try:
            hours = int(request.query.get("hours", 24))
            stats = await self.event_store.get_statistics(hours)

            return web.json_response({"success": True, "statistics": stats.to_dict()})

        except Exception as e:
            # Log full error internally for debugging
            self.logger.error(f"Statistics API error: {e}", exc_info=True)

            # Return safe error response
            return web.json_response(
                create_safe_error_response(e, include_type=False), status=500
            )

    async def websocket_handler(self, request) -> web.WebSocketResponse:
        """Handle WebSocket connections for real-time updates."""
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        self.websocket_connections.add(ws)
        self.logger.info(
            f"WebSocket client connected. Total clients: {len(self.websocket_connections)}"
        )

        try:
            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    try:
                        data = json.loads(msg.data)
                        await self._handle_websocket_message(ws, data)
                    except json.JSONDecodeError:
                        await ws.send_str(json.dumps({"error": "Invalid JSON"}))
                elif msg.type == WSMsgType.ERROR:
                    self.logger.error(f"WebSocket error: {ws.exception()}")

        except Exception as e:
            self.logger.error(f"WebSocket handler error: {e}")
        finally:
            self.websocket_connections.discard(ws)
            self.logger.info(
                f"WebSocket client disconnected. Total clients: {len(self.websocket_connections)}"
            )

        return ws

    async def _handle_websocket_message(
        self, ws: web.WebSocketResponse, data: Dict[str, Any]
    ) -> None:
        """Handle incoming WebSocket messages."""
        message_type = data.get("type")

        if message_type == "subscribe":
            # Send initial data
            await self._send_initial_data(ws)
        elif message_type == "get_alerts":
            # Send current alerts
            alerts = await self.event_alerting.get_active_alerts()
            alerts_data = [alert.id for alert in alerts]
            await ws.send_str(
                json.dumps({"type": "alerts_update", "alerts": alerts_data})
            )

    async def _send_initial_data(self, ws: web.WebSocketResponse) -> None:
        """Send initial dashboard data to WebSocket client."""
        try:
            # Get basic statistics
            stats = await self.event_store.get_statistics(24)
            alerts = await self.event_alerting.get_active_alerts()

            # Send data
            await ws.send_str(
                json.dumps(
                    {
                        "type": "initial_data",
                        "statistics": stats.to_dict(),
                        "active_alerts": len(alerts),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                )
            )

        except Exception as e:
            self.logger.error(f"Error sending initial WebSocket data: {e}")

    async def _get_dashboard_data(self) -> Dict[str, Any]:
        """Get data for the main dashboard page."""
        try:
            # Get various data sources
            time_range = TimeRange.last_24_hours()

            # Statistics
            stats = await self.event_store.get_statistics(24)

            # Health report
            health_report = await self.event_reporting.generate_health_report(
                time_range
            )

            # Security report
            security_report = await self.event_reporting.generate_security_report(
                time_range
            )

            # Alerts
            alerts = await self.event_alerting.get_active_alerts()
            alert_stats = await self.event_alerting.get_alert_statistics()

            # Recent events
            from src.models.event_models import EventFilters

            filters = EventFilters(
                start_time=time_range.start_time, end_time=time_range.end_time, limit=50
            )
            recent_events = await self.event_store.get_events(filters)

            # Event severity distribution
            severity_counts = {}
            for event in recent_events:
                severity = event.severity.value
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

            # Event source distribution
            source_counts = {}
            for event in recent_events:
                source = event.source.value
                source_counts[source] = source_counts.get(source, 0) + 1

            return {
                "system_name": "TailOpsMCP Observability Dashboard",
                "last_updated": datetime.now(timezone.utc).isoformat(),
                "statistics": {
                    "total_events_24h": stats.total_events,
                    "critical_events_24h": stats.critical_events,
                    "error_events_24h": stats.error_events,
                    "warning_events_24h": stats.warning_events,
                    "active_alerts": len(alerts),
                },
                "health": {
                    "fleet_health_score": health_report.fleet_health_score,
                    "health_status": health_report.system_health_status,
                    "healthy_systems": health_report.healthy_systems,
                    "total_systems": health_report.total_systems,
                },
                "security": {
                    "security_score": security_report.security_score,
                    "security_status": security_report.security_status,
                    "total_security_events": security_report.total_security_events,
                    "critical_security_events": security_report.critical_security_events,
                },
                "alerts": {
                    "active_alerts": len(alerts),
                    "alert_statistics": alert_stats,
                },
                "events": {
                    "recent_events": [event.to_dict() for event in recent_events[:10]],
                    "severity_distribution": severity_counts,
                    "source_distribution": source_counts,
                },
                "websocket_url": f"ws://{self.host}:{self.port}/ws",
            }

        except Exception as e:
            # Log full error internally for debugging
            self.logger.error(f"Error getting dashboard data: {e}", exc_info=True)

            # Return safe error data (no stack traces)
            return {
                "error": "Dashboard data temporarily unavailable",
                "last_updated": datetime.now(timezone.utc).isoformat(),
            }

    async def broadcast_update(self, data: Dict[str, Any]) -> None:
        """Broadcast update to all connected WebSocket clients."""
        if not self.websocket_connections:
            return

        message = json.dumps(data)
        disconnected_clients = set()

        for client in self.websocket_connections:
            try:
                await client.send_str(message)
            except Exception:
                disconnected_clients.add(client)

        # Remove disconnected clients
        self.websocket_connections -= disconnected_clients

    async def start_server(self) -> None:
        """Start the dashboard server."""
        if self.app is None:
            self.app = await self.create_app()

        self.logger.info(f"Starting event dashboard on {self.host}:{self.port}")
        await web._run_app(self.app, host=self.host, port=self.port)

    async def stop_server(self) -> None:
        """Stop the dashboard server."""
        if self.app:
            self.app.shutdown()
            self.logger.info("Event dashboard server stopped")


# HTML Templates
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ system_name }}</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            text-align: center;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
        }
        .stat-value {
            font-size: 2em;
            font-weight: bold;
            margin-bottom: 10px;
        }
        .stat-label {
            color: #666;
            font-size: 0.9em;
        }
        .health-score {
            color: #4CAF50;
        }
        .health-warning {
            color: #FF9800;
        }
        .health-critical {
            color: #F44336;
        }
        .section {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        .section h3 {
            margin-top: 0;
            border-bottom: 2px solid #eee;
            padding-bottom: 10px;
        }
        .event-item {
            border-left: 4px solid #ddd;
            padding: 10px;
            margin: 10px 0;
            background: #f9f9f9;
            border-radius: 5px;
        }
        .event-critical {
            border-left-color: #F44336;
        }
        .event-error {
            border-left-color: #FF9800;
        }
        .event-warning {
            border-left-color: #FFC107;
        }
        .event-info {
            border-left-color: #2196F3;
        }
        .alert-item {
            background: #FFF3E0;
            border: 1px solid #FF9800;
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
        }
        .status-indicator {
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            margin-right: 10px;
        }
        .status-healthy {
            background-color: #4CAF50;
        }
        .status-warning {
            background-color: #FF9800;
        }
        .status-critical {
            background-color: #F44336;
        }
        .chart-container {
            height: 300px;
            margin: 20px 0;
        }
        .refresh-btn {
            background: #667eea;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            margin: 10px 0;
        }
        .refresh-btn:hover {
            background: #5a67d8;
        }
        .last-updated {
            text-align: center;
            color: #666;
            font-size: 0.8em;
            margin-top: 20px;
        }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{ system_name }}</h1>
            <p>Real-time System Monitoring and Observability</p>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{{ statistics.total_events_24h }}</div>
                <div class="stat-label">Events (24h)</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ statistics.critical_events_24h }}</div>
                <div class="stat-label">Critical Events</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{{ statistics.active_alerts }}</div>
                <div class="stat-label">Active Alerts</div>
            </div>
            <div class="stat-card">
                <div class="stat-value health-{% if health.fleet_health_score >= 80 %}healthy{% elif health.fleet_health_score >= 50 %}warning{% else %}critical{% endif %}">
                    {{ "%.1f"|format(health.fleet_health_score) }}%
                </div>
                <div class="stat-label">System Health</div>
            </div>
        </div>

        <div class="section">
            <h3>
                <span class="status-indicator status-{% if health.health_status == 'healthy' %}healthy{% elif health.health_status == 'degraded' %}warning{% else %}critical{% endif %}"></span>
                System Health Status: {{ health.health_status|title }}
            </h3>
            <p>Fleet Health Score: {{ "%.1f"|format(health.fleet_health_score) }}%</p>
            <p>Healthy Systems: {{ health.healthy_systems }} / {{ health.total_systems }}</p>
            <button class="refresh-btn" onclick="refreshData()">Refresh Data</button>
        </div>

        <div class="section">
            <h3>Security Overview</h3>
            <p>Security Score: {{ "%.1f"|format(security.security_score) }}%</p>
            <p>Security Status: {{ security.security_status|title }}</p>
            <p>Security Events (24h): {{ security.total_security_events }}</p>
            <p>Critical Security Events: {{ security.critical_security_events }}</p>
        </div>

        {% if alerts.active_alerts > 0 %}
        <div class="section">
            <h3>Active Alerts ({{ alerts.active_alerts }})</h3>
            <div id="alerts-container">
                <!-- Alerts will be loaded here -->
            </div>
        </div>
        {% endif %}

        <div class="section">
            <h3>Event Distribution</h3>
            <canvas id="severityChart" width="400" height="200"></canvas>
        </div>

        <div class="section">
            <h3>Recent Events</h3>
            <div id="events-container">
                {% for event in events.recent_events %}
                <div class="event-item event-{{ event.severity }}">
                    <strong>{{ event.title }}</strong><br>
                    <small>{{ event.timestamp }} | {{ event.source }} | {{ event.severity }}</small><br>
                    {{ event.description }}
                </div>
                {% endfor %}
            </div>
        </div>

        <div class="last-updated">
            Last updated: {{ last_updated }}
        </div>
    </div>

    <script>
        // WebSocket connection for real-time updates
        const ws = new WebSocket('{{ websocket_url }}');

        ws.onopen = function(event) {
            console.log('WebSocket connected');
            ws.send(JSON.stringify({type: 'subscribe'}));
        };

        ws.onmessage = function(event) {
            const data = JSON.parse(event.data);
            if (data.type === 'initial_data') {
                updateDashboard(data);
            } else if (data.type === 'alerts_update') {
                updateAlerts(data.alerts);
            }
        };

        ws.onclose = function(event) {
            console.log('WebSocket disconnected');
        };

        // Initialize charts
        function initCharts() {
            const severityCtx = document.getElementById('severityChart').getContext('2d');
            const severityData = {{ events.severity_distribution|tojson }};

            new Chart(severityCtx, {
                type: 'doughnut',
                data: {
                    labels: Object.keys(severityData),
                    datasets: [{
                        data: Object.values(severityData),
                        backgroundColor: [
                            '#F44336', // critical - red
                            '#FF9800', // error - orange
                            '#FFC107', // warning - yellow
                            '#2196F3', // info - blue
                            '#9E9E9E'  // debug - gray
                        ]
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false
                }
            });
        }

        function updateDashboard(data) {
            // Update statistics
            console.log('Dashboard updated:', data);
        }

        function updateAlerts(alerts) {
            console.log('Alerts updated:', alerts);
        }

        function refreshData() {
            location.reload();
        }

        // Initialize on page load
        document.addEventListener('DOMContentLoaded', function() {
            initCharts();
        });
    </script>
</body>
</html>
"""


async def create_dashboard_templates():
    """Create dashboard templates."""
    template_dir = Path("./templates")
    template_dir.mkdir(exist_ok=True)

    dashboard_template = template_dir / "dashboard.html"
    with open(dashboard_template, "w") as f:
        f.write(DASHBOARD_HTML)

    # Create static files
    static_dir = Path("./static")
    static_dir.mkdir(exist_ok=True)

    # Create basic CSS
    css_file = static_dir / "dashboard.css"
    with open(css_file, "w") as f:
        f.write("""
/* Additional dashboard styles */
.dashboard-container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 20px;
}

.metric-card {
    background: white;
    padding: 20px;
    border-radius: 8px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    margin-bottom: 20px;
}

.status-good { color: #4CAF50; }
.status-warning { color: #FF9800; }
.status-critical { color: #F44336; }
        """)


# Global dashboard instance
_dashboard_instance = None


def get_event_dashboard(host: str = "localhost", port: int = 8080) -> EventDashboard:
    """Get the global event dashboard instance."""
    global _dashboard_instance
    if _dashboard_instance is None:
        _dashboard_instance = EventDashboard(host, port)
    return _dashboard_instance


async def start_event_dashboard(
    host: str = "localhost", port: int = 8080
) -> EventDashboard:
    """Start the event dashboard server."""
    dashboard = get_event_dashboard(host, port)

    # Create templates
    await create_dashboard_templates()

    # Start server
    await dashboard.start_server()

    return dashboard


# Standalone dashboard runner
async def run_dashboard_server():
    """Run dashboard server standalone."""
    import argparse

    parser = argparse.ArgumentParser(description="TailOpsMCP Event Dashboard")
    parser.add_argument("--host", default="localhost", help="Dashboard host")
    parser.add_argument("--port", type=int, default=8080, help="Dashboard port")
    args = parser.parse_args()

    await start_event_dashboard(args.host, args.port)


if __name__ == "__main__":
    import sys

    sys.exit(asyncio.run(run_dashboard_server()))
