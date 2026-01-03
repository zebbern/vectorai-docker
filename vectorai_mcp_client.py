#!/usr/bin/env python3
"""
VectorAI MCP Client - Docker Bridge
========================================

This script acts as an MCP client that connects to the VectorAI
server running in Docker. It should be used with VS Code Copilot.

Usage:
    python vectorai_mcp_client.py --server http://localhost:8888
"""

from __future__ import annotations
import sys
import os
import argparse
import importlib.util
from typing import NoReturn

VECTORAI_SERVER: str = os.environ.get("VECTORAI_SERVER", "http://localhost:8888")


def validate_url(url: str) -> str:
    """Ensure URL has proper http/https scheme."""
    if not url.startswith(('http://', 'https://')):
        return f"http://{url}"
    return url


def main() -> None:
    """Main entry point for VectorAI MCP Client."""
    parser = argparse.ArgumentParser(description="VectorAI MCP Client")
    parser.add_argument(
        "--server", 
        default=VECTORAI_SERVER, 
        help="VectorAI server URL (default: http://localhost:8888)"
    )
    parser.add_argument(
        "--debug", 
        action="store_true", 
        help="Enable debug mode"
    )
    
    args = parser.parse_args()
    
    # Validate and set the server URL
    server_url = validate_url(args.server)
    os.environ["VECTORAI_SERVER"] = server_url
    
    # Locate the MCP module
    mcp_file = os.path.join(os.path.dirname(__file__), "vectorai_mcp.py")
    
    if not os.path.exists(mcp_file):
        print(f"[ERROR] vectorai_mcp.py not found at {mcp_file}")
        print("[INFO] Make sure vectorai_mcp.py is in the same directory as this script.")
        sys.exit(1)
    
    # Try to import and run the MCP client
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        
        spec = importlib.util.spec_from_file_location("vectorai_mcp", mcp_file)
        if spec is None or spec.loader is None:
            print("[ERROR] Failed to create module spec for vectorai_mcp")
            sys.exit(1)
            
        vectorai_mcp = importlib.util.module_from_spec(spec)
        
        # Modify sys.argv to pass arguments to the module
        sys.argv = ["vectorai_mcp.py", "--server", server_url]
        if args.debug:
            sys.argv.append("--debug")
        
        spec.loader.exec_module(vectorai_mcp)
        
    except ImportError as e:
        print(f"[ERROR] Failed to import vectorai_mcp: {e}")
        print("[INFO] Make sure the VectorAI Docker container is running:")
        print("       docker compose up -d")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
