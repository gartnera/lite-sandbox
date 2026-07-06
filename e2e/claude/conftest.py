import os
import subprocess
from pathlib import Path
from typing import Any

import pytest
from claude_agent_sdk import ClaudeAgentOptions
from claude_agent_sdk.types import PermissionResultAllow, PermissionResultDeny

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


async def deny_builtin_bash(
    tool_name: str, input_data: dict[str, Any], context: Any,
) -> PermissionResultAllow | PermissionResultDeny:
    """Allow the MCP sandbox tool freely; deny the built-in Bash tool."""
    if tool_name == "Bash":
        return PermissionResultDeny(
            message="Use the mcp__lite-sandbox__bash tool instead",
        )
    return PermissionResultAllow(updated_input=input_data)


@pytest.fixture(scope="session", autouse=True)
def build_binary():
    """Build the lite-sandbox binary before running tests."""
    result = subprocess.run(
        ["go", "build", "-o", "lite-sandbox"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"go build failed: {result.stderr}"
    binary = PROJECT_ROOT / "lite-sandbox"
    assert binary.exists(), "Binary not found after build"
    yield
    # binary is left in place for debugging; gitignored anyway


@pytest.fixture(scope="session", autouse=True)
def unset_claudecode_env():
    """Unset CLAUDECODE env var so the SDK doesn't refuse to launch."""
    old = os.environ.pop("CLAUDECODE", None)
    yield
    if old is not None:
        os.environ["CLAUDECODE"] = old


@pytest.fixture
def agent_options() -> ClaudeAgentOptions:
    """ClaudeAgentOptions wired to the sandbox MCP server."""
    binary = PROJECT_ROOT / "lite-sandbox"
    return ClaudeAgentOptions(
        mcp_servers={
            "lite-sandbox": {
                "command": str(binary),
                "args": ["serve-mcp"],
            },
        },
        system_prompt=(
            "You have access to a bash MCP tool. "
            "ALWAYS prefer using the mcp__lite-sandbox__bash tool "
            "for running shell commands instead of the built-in Bash tool. "
            "The sandboxed tool is pre-approved and requires no permission prompts."
        ),
        allowed_tools=["mcp__lite-sandbox__bash"],
        disallowed_tools=["Bash"],
        can_use_tool=deny_builtin_bash,
        model="haiku",
        max_turns=5,
        cwd=str(PROJECT_ROOT),
    )
