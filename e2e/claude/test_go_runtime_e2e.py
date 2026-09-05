"""E2E test for Go runtime workflow demonstrating full dev cycle with MCP tool."""

import pytest
from claude_agent_sdk import ClaudeAgentOptions

from conftest import PROJECT_ROOT, deny_builtin_bash
from test_sandbox_e2e import assert_used_sandbox_tool, run_prompt


@pytest.fixture
def go_runtime_agent_options(tmp_path) -> ClaudeAgentOptions:
    """ClaudeAgentOptions with Go runtime enabled via custom config."""
    binary = PROJECT_ROOT / "lite-sandbox"
    config_path = PROJECT_ROOT / "e2e" / "claude" / "config_go_runtime.yaml"

    return ClaudeAgentOptions(
        mcp_servers={
            "lite-sandbox": {
                "command": str(binary),
                "args": ["serve-mcp"],
                "env": {"LITE_SANDBOX_CONFIG": str(config_path)},
            },
        },
        system_prompt=(
            "You have access to a bash MCP tool for running shell commands. "
            "You also have access to Read, Write, and Edit tools for file operations. "
            "ALWAYS use the mcp__lite-sandbox__bash tool for running commands "
            "(like go, git) instead of the built-in Bash tool. "
            "ALWAYS use the Write tool to create new files instead of shell commands. "
            "The sandboxed tool is pre-approved and requires no permission prompts."
        ),
        allowed_tools=[
            "mcp__lite-sandbox__bash",
            "Read",
            "Write",
            "Edit",
        ],
        disallowed_tools=["Bash"],
        can_use_tool=deny_builtin_bash,
        model="haiku",
        max_turns=15,
        cwd=str(tmp_path),
    )


@pytest.mark.asyncio
async def test_go_project_workflow(go_runtime_agent_options):
    """
    Test a complete Go development workflow:
    - Initialize a Go module
    - Create main.go with an Add function
    - Create main_test.go with a test
    - Run go test
    - Initialize git
    - Commit the project

    All commands should use the sandbox tool (no built-in Bash).
    """
    prompt = """
Please complete the following Go project workflow:

1. Run 'go mod init testproject' to initialize a Go module
2. Create a file main.go with:
   - A package main
   - A simple Add function that takes two ints and returns their sum
   - A main function that calls Add and prints the result
3. Create a file main_test.go with:
   - A package main
   - A test function TestAdd that verifies Add(2, 3) returns 5
4. Run 'go test ./...' to verify the test passes
5. Run 'git init' to initialize a git repository
6. Run 'git add .' to stage all files
7. Run 'git commit -m "initial commit"' to create the first commit

Use the Write tool to create files and the bash tool for commands.
Show me the results of the go test and git commit commands.
"""

    response = await run_prompt(prompt, go_runtime_agent_options)

    # Assert the sandbox tool was used
    assert_used_sandbox_tool(response)

    # Verify no built-in Bash was used (enforced by disallowed_tools and the
    # can_use_tool callback). Harness-internal tools such as ToolSearch may
    # appear depending on the CLI version, so don't assert a strict whitelist.
    tool_names = [tc.name for tc in response["tool_calls"]]
    assert "Bash" not in tool_names, "Built-in Bash should not be used"

    # Check for evidence of successful test run
    combined_output = response["text"] + " ".join(response["tool_results"])

    # Test should have passed (look for common go test success indicators)
    assert "PASS" in combined_output or "ok" in combined_output, (
        f"Expected test to pass. Output: {combined_output}"
    )

    # Commit should have been created (look for commit indicators)
    # Git commit usually outputs something like "initial commit" or a commit hash
    assert (
        "initial commit" in combined_output
        or "1 file changed" in combined_output
        or "files changed" in combined_output
        or "create mode" in combined_output
    ), f"Expected git commit to succeed. Output: {combined_output}"
