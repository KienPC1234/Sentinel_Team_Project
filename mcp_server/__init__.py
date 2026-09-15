"""
ShieldCall VN – Model Context Protocol (MCP) Server
Bridges ShieldCall's threat intelligence & scam database with modern LLMs.
"""

from mcp_server.server import create_server
from mcp_server.client import ShieldCallClient

__version__ = "1.0.0"
__all__ = ["create_server", "ShieldCallClient"]

