"""Tests for the MCP server tool definitions."""

import pytest

# Only test MCP if the SDK is installed
try:
    from zugashield_mcp.server import create_server

    _HAS_MCP = True
except ImportError:
    _HAS_MCP = False


@pytest.mark.skipif(not _HAS_MCP, reason="MCP SDK not installed")
class TestMCPServer:
    def test_server_creates(self):
        server = create_server()
        assert server is not None

    def test_server_has_name(self):
        server = create_server()
        assert server.name == "zugashield"
