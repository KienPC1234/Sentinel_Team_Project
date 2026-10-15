"""
ShieldCall VN – MCP Server CLI Entrypoint
Allows running the MCP server directly via:
    python -m mcp_server [--transport stdio|sse] [--port 8002] [--api-key sc_live_...]
"""
import sys
import argparse
import logging
from mcp_server.server import create_server

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("shieldcall_mcp")


def main():
    parser = argparse.ArgumentParser(
        description="ShieldCall VN – Model Context Protocol (MCP) Server"
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "streamable-http"],
        default="stdio",
        help="MCP Transport mode (default: stdio)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8002,
        help="Port to bind for SSE or HTTP transport (default: 8002)",
    )
    parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="Host address for network transport (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--api-url",
        type=str,
        default=None,
        help="ShieldCall backend API URL (e.g. http://127.0.0.1:8001/api/v1)",
    )
    parser.add_argument(
        "--api-key",
        type=str,
        default=None,
        help="ShieldCall API Key (e.g. sc_live_...)",
    )

    args = parser.parse_args()

    server = create_server(api_url=args.api_url, api_key=args.api_key)

    if args.transport == "stdio":
        logger.info("Starting ShieldCall MCP Server in stdio transport mode...")
        server.run(transport="stdio")
    elif args.transport == "sse":
        logger.info(f"Starting ShieldCall MCP Server in SSE transport mode on {args.host}:{args.port}...")
        server.run(transport="sse", host=args.host, port=args.port)
    elif args.transport == "streamable-http":
        logger.info(f"Starting ShieldCall MCP Server in HTTP transport mode on {args.host}:{args.port}...")
        server.run(transport="streamable-http", host=args.host, port=args.port)


if __name__ == "__main__":
    main()

