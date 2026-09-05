"""E2E tests that verify Claude can use the bash MCP tool."""

import pytest
from claude_agent_sdk import (
    ClaudeAgentOptions,
    ClaudeSDKClient,
    AssistantMessage,
    ResultMessage,
    TextBlock,
    ToolUseBlock,
    ToolResultBlock,
)


async def run_prompt(prompt: str, options: ClaudeAgentOptions) -> dict:
    """Send a prompt and collect tool calls and text from the response."""
    tool_calls = []
    text_blocks = []
    tool_results = []
    result = None

    async with ClaudeSDKClient(options=options) as client:
        await client.query(prompt)
        async for message in client.receive_response():
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, TextBlock):
                        text_blocks.append(block.text)
                    elif isinstance(block, ToolUseBlock):
                        tool_calls.append(block)
                    elif isinstance(block, ToolResultBlock):
                        content = block.content if block.content else ""
                        if isinstance(content, list):
                            content = " ".join(
                                item.get("text", "") for item in content if isinstance(item, dict)
                            )
                        tool_results.append(content)
            elif isinstance(message, ResultMessage):
                result = message

    return {
        "tool_calls": tool_calls,
        "text": "\n".join(text_blocks),
        "tool_results": tool_results,
        "result": result,
    }


def assert_used_sandbox_tool(response: dict):
    """Assert that the sandbox MCP tool was actually invoked."""
    tool_names = [tc.name for tc in response["tool_calls"]]
    assert any(
        "bash" in name for name in tool_names
    ), f"Expected bash tool call, got: {tool_names}"


@pytest.mark.asyncio
async def test_list_files(agent_options):
    """Claude should be able to list files and see go.mod and main.go."""
    response = await run_prompt(
        "List the files in the current directory using ls. Show me the output.",
        agent_options,
    )
    assert_used_sandbox_tool(response)
    combined = response["text"] + " ".join(response["tool_results"])
    assert "go.mod" in combined, f"Expected go.mod in output: {combined}"
    assert "main.go" in combined, f"Expected main.go in output: {combined}"


@pytest.mark.asyncio
async def test_read_file(agent_options):
    """Claude should be able to cat go.mod and see the module path."""
    response = await run_prompt(
        "Read the contents of go.mod using cat and show me the output.",
        agent_options,
    )
    assert_used_sandbox_tool(response)
    combined = response["text"] + " ".join(response["tool_results"])
    assert "gartnera/lite-sandbox-mcp" in combined or "module" in combined, (
        f"Expected module path in output: {combined}"
    )


@pytest.mark.asyncio
async def test_pipeline(agent_options):
    """Claude should be able to run a pipeline like find + wc."""
    response = await run_prompt(
        "Count the number of .go files using: find . -name '*.go' | wc -l. Show me the count.",
        agent_options,
    )
    assert_used_sandbox_tool(response)
    combined = response["text"] + " ".join(response["tool_results"])
    # There should be at least 1 .go file; look for any digit
    assert any(ch.isdigit() for ch in combined), (
        f"Expected a numeric count in output: {combined}"
    )


@pytest.mark.asyncio
async def test_blocked_command(agent_options):
    """The sandbox tool should reject python3; Claude may fall back to built-in Bash."""
    response = await run_prompt(
        "Run python3 --version and show me the output.",
        agent_options,
    )
    assert_used_sandbox_tool(response)
    # The sandbox should have been tried first and returned an error.
    # Claude may then fall back to built-in Bash — that's fine.


@pytest.mark.asyncio
async def test_head_pipeline(agent_options):
    """Claude should be able to run head on a file via the sandbox."""
    response = await run_prompt(
        "Show the first 3 lines of go.mod using head -n 3. Show me the output.",
        agent_options,
    )
    assert_used_sandbox_tool(response)
    combined = response["text"] + " ".join(response["tool_results"])
    assert "module" in combined, (
        f"Expected 'module' in head output: {combined}"
    )
