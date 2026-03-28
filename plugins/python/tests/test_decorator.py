"""Tests for the @guarded decorator."""

import pytest

from agentguard import Guard, guarded
from tests.conftest import MockAgentGuardHandler


class TestGuardedDecorator:
    def test_allows_execution(self, mock_server):
        MockAgentGuardHandler.check_response = {
            "decision": "ALLOW",
            "reason": "ok",
        }
        g = Guard(mock_server)

        @guarded("shell", guard=g)
        def my_func(cmd):
            return f"executed: {cmd}"

        assert my_func("ls") == "executed: ls"

    def test_blocks_on_deny(self, mock_server):
        MockAgentGuardHandler.check_response = {
            "decision": "DENY",
            "reason": "not allowed",
        }
        g = Guard(mock_server)

        @guarded("shell", guard=g)
        def my_func(cmd):
            return f"executed: {cmd}"

        with pytest.raises(PermissionError, match="Action denied"):
            my_func("rm -rf /")

    def test_blocks_on_approval_needed(self, mock_server):
        MockAgentGuardHandler.check_response = {
            "decision": "REQUIRE_APPROVAL",
            "reason": "needs review",
            "approval_url": "http://example.com/approve/123",
        }
        g = Guard(mock_server)

        @guarded("shell", guard=g)
        def my_func(cmd):
            return f"executed: {cmd}"

        with pytest.raises(PermissionError, match="requires approval"):
            my_func("sudo reboot")

    def test_preserves_function_metadata(self, mock_server):
        g = Guard(mock_server)

        @guarded("shell", guard=g)
        def documented_function(cmd):
            """This function has docs."""
            return cmd

        assert documented_function.__name__ == "documented_function"
        assert documented_function.__doc__ == "This function has docs."

    def test_passes_first_arg_as_command(self, mock_server):
        """The decorator should send args[0] as the 'command' in the check."""
        MockAgentGuardHandler.check_response = {
            "decision": "ALLOW",
            "reason": "ok",
        }
        g = Guard(mock_server)

        @guarded("shell", guard=g)
        def run(cmd):
            return cmd

        run("echo hello")

        import json
        body = json.loads(MockAgentGuardHandler.last_request_body)
        assert body["command"] == "echo hello"
