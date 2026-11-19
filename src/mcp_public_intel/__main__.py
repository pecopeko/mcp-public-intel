"""Allow launching the MCP stdio server via `python -m mcp_public_intel`."""

from __future__ import annotations

from mcp_public_intel.server import main

if __name__ == "__main__":
    raise SystemExit(main())
