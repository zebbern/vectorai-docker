#!/usr/bin/env python3
"""
VectorAI MCP Client - Docker Bridge
========================================

This script acts as an MCP client that connects to the VectorAI
server running in Docker. It should be used with VS Code Copilot.

Usage:
    python vectorai_mcp_client.py --server http://localhost:8888
"""

import sys
import os

VECTORAI_SERVER = os.environ.get("VECTORAI_SERVER", "http://localhost:8888")

def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description="VectorAI MCP Client")
    parser.add_argument("--server", default=VECTORAI_SERVER, 
                       help="VectorAI server URL (default: http://localhost:8888)")
    parser.add_argument("--debug", action="store_true", 
                       help="Enable debug mode")
    
    args = parser.parse_args()
    
    # Set the server URL in environment
    os.environ["VECTORAI_SERVER"] = args.server
    
    # Try to import and run the MCP client
    try:
        # Use the local vectorai_mcp module
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        
        mcp_file = os.path.join(os.path.dirname(__file__), "vectorai_mcp.py")
        
        if not os.path.exists(mcp_file):
            print(f"[ERROR] vectorai_mcp.py not found at {mcp_file}")
            print("[INFO] Make sure vectorai_mcp.py is in the same directory as this script.")
            sys.exit(1)
        
        # Import and run
        import importlib.util
        spec = importlib.util.spec_from_file_location("vectorai_mcp", mcp_file)
        vectorai_mcp = importlib.util.module_from_spec(spec)
        
        # Modify sys.argv to pass our arguments to the module
        sys.argv = ["vectorai_mcp.py", "--server", args.server]
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
