"""Tests for the MCP server tool definitions."""

import sys

import pytest

# MCP SDK requires Python 3.10+
_HAS_MCP = sys.version_info >= (3, 10)
if _HAS_MCP:
    try:
        import mcp  # noqa: F401

        _HAS_MCP = True
    except ImportError:
        _HAS_MCP = False


@pytest.mark.skipif(not _HAS_MCP, reason="MCP SDK not installed or Python < 3.10")
class TestMCPServer:
    def test_server_creates(self):
        from zugashield_mcp.server import create_server

        server = create_server()
        assert server is not None

    def test_server_has_name(self):
        from zugashield_mcp.server import create_server

        server = create_server()
        assert server.name == "zugashield"
