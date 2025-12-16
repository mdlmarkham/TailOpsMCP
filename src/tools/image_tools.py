"""Docker image management tools for TailOpsMCP."""

import logging
from typing import Literal, Union
from fastmcp import FastMCP
from src.auth.middleware import secure_tool
from src.server.dependencies import deps
from src.server.utils import format_response, format_error

logger = logging.getLogger(__name__)


def register_tools(mcp: FastMCP):
    """Register Docker image management tools with MCP instance."""

    @mcp.tool()
    @secure_tool("pull_docker_image")
    async def pull_docker_image(image_name: str, tag: str = "latest") -> dict:
        """Pull a Docker image from registry.

        Args:
            image_name: Name of the image (e.g., 'nginx', 'mysql', 'ubuntu')
            tag: Image tag (default: 'latest')

        Returns image ID, tags, and size information.
        """
        try:
            client = deps.get_docker_client()
            from src.services.docker_manager import DockerManager

            dm = DockerManager()
            dm.client = client
            result = await dm.pull_image(image_name, tag)
            return result
        except Exception as e:
            return format_error(e, "pull_docker_image")

    @mcp.tool()
    @secure_tool("update_docker_container")
    async def update_docker_container(
        name_or_id: str, pull_latest: bool = True
    ) -> dict:
        """Update a Docker container by pulling latest image and recreating it.

        This stops the container, pulls the latest image (if requested),
        removes the old container, and creates a new one with the same configuration.

        Args:
            name_or_id: Container name or ID to update
            pull_latest: Whether to pull latest image first (default: True)

        Warning: Container will be stopped and recreated. Ensure data is in volumes.
        """
        try:
            client = deps.get_docker_client()
            from src.services.docker_manager import DockerManager

            dm = DockerManager()
            dm.client = client
            result = await dm.update_container(name_or_id, pull_latest)
            return result
        except Exception as e:
            return format_error(e, "update_docker_container")

    @mcp.tool()
    @secure_tool("list_docker_images")
    async def list_docker_images(
        format: Literal["json", "toon"] = "toon",
    ) -> Union[dict, str]:
        """List all Docker images on the system.

        Args:
            format: Response format - 'toon' (compact, default) or 'json' (verbose)

        Returns image IDs, tags, sizes, and creation dates.
        """
        try:
            client = deps.get_docker_client()
            from src.services.docker_manager import DockerManager

            dm = DockerManager()
            dm.client = client
            result = await dm.list_images()
            return format_response(result, format)
        except Exception as e:
            return format_error(e, "list_docker_images")

    logger.info("Registered 3 Docker image management tools")
