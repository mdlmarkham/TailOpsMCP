#!/usr/bin/env python3
"""
TailOpsMCP - Deployment CLI
"""

import argparse
import asyncio
import sys
from pathlib import Path

from src.mcp_server import mcp


def create_parser():
    """Create command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="TailOpsMCP Deployment Tool"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    
    # Server commands
    server_parser = subparsers.add_parser("serve", help="Start the MCP server")
    server_parser.add_argument("--transport", choices=["stdio", "http-sse"], 
                              default="stdio", help="Transport protocol")
    server_parser.add_argument("--host", default="localhost", help="Host for HTTP server")
    server_parser.add_argument("--port", type=int, default=8080, help="Port for HTTP server")
    
    # System status command
    status_parser = subparsers.add_parser("system-status", help="Get system status")
    status_parser.add_argument("--detailed", action="store_true", help="Show detailed information")
    
    # Container commands
    container_parser = subparsers.add_parser("list-containers", help="List Docker containers")
    container_parser.add_argument("--all", action="store_true", help="Include stopped containers")
    
    # File system commands
    fs_parser = subparsers.add_parser("list-directory", help="List directory contents")
    fs_parser.add_argument("--path", default="/", help="Directory path")
    fs_parser.add_argument("--recursive", action="store_true", help="List recursively")
    
    # Network commands
    net_parser = subparsers.add_parser("network-status", help="Get network status")
    net_parser.add_argument("--interface", help="Specific interface name")
    
    return parser


async def handle_serve(args):
    """Handle serve command."""
    print(f"Starting TailOpsMCP on {args.transport}://{args.host}:{args.port}")
    
    if args.transport == "http-sse":
        # Run HTTP SSE server
        import uvicorn
        from fastmcp.server.http import create_app
        
        app = create_app(mcp)
        config = uvicorn.Config(app, host=args.host, port=args.port, log_level="info")
        server = uvicorn.Server(config)
        await server.serve()
    else:
        # Run stdio server
        await mcp.run(transport="stdio")


async def handle_system_status(args):
    """Handle system-status command."""
    from src.services.system_monitor import SystemMonitor
    
    monitor = SystemMonitor()
    status = await monitor.get_status(detailed=args.detailed)
    
    if status["success"]:
        print("System Status:")
        print(f"  CPU Usage: {status['data']['cpu_percent']}%")
        print(f"  Memory Usage: {status['data']['memory']['percent']}%")
        print(f"  Load Average: {status['data']['load_average']['1min']:.2f}, {status['data']['load_average']['5min']:.2f}, {status['data']['load_average']['15min']:.2f}")
        print(f"  Uptime: {status['data']['uptime']} seconds")
    else:
        print(f"Error: {status['error']}")


async def handle_list_containers(args):
    """Handle list-containers command."""
    from src.services.docker_manager import DockerManager
    
    manager = DockerManager()
    containers = await manager.list_containers(show_all=args.all)
    
    if containers["success"]:
        print("Docker Containers:")
        for container in containers["data"]:
            print(f"  {container['id']} {container['name']} ({container['status']}) - {container['image']}")
    else:
        print(f"Error: {containers['error']}")


async def handle_list_directory(args):
    """Handle list-directory command."""
    from src.services.file_explorer import FileExplorer
    
    explorer = FileExplorer()
    entries = await explorer.list_directory(args.path, recursive=args.recursive)
    
    if entries["success"]:
        print(f"Directory: {args.path}")
        for entry in entries["data"]:
            print(f"  {entry['type'][0]} {entry['permissions']} {entry['size']:10} {entry['name']}")
    else:
        print(f"Error: {entries['error']}")


async def handle_network_status(args):
    """Handle network-status command."""
    from src.services.network_status import NetworkStatus
    
    net_status = NetworkStatus()
    status = await net_status.get_status(interface=args.interface)
    
    if status["success"]:
        print("Network Interfaces:")
        for iface in status["data"]:
            print(f"  {iface['name']}:")
            for addr in iface.get('addresses', []):
                print(f"    {addr['family']}: {addr['address']}")
    else:
        print(f"Error: {status['error']}")


async def main():
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    handlers = {
        "serve": handle_serve,
        "system-status": handle_system_status,
        "list-containers": handle_list_containers,
        "list-directory": handle_list_directory,
        "network-status": handle_network_status,
    }
    
    handler = handlers.get(args.command)
    if handler:
        try:
            await handler(args)
        except KeyboardInterrupt:
            print("\nShutting down...")
        except Exception as e:
            print(f"Error: {e}")
            sys.exit(1)
    else:
        print(f"Unknown command: {args.command}")
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())