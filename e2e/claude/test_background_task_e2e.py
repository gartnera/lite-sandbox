"""E2E test that a background bash command runs as an MCP task in Claude Code.

A client that declares the MCP tasks extension gets run_in_background
commands as tasks: Claude Code follows the task, shows it in /tasks, and
wakes Claude with the result when it finishes. Such a client is not offered
the kill_shell and list_shells tools.
"""

import asyncio
import dataclasses

import pytest
from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ClaudeSDKClient,
    ResultMessage,
    SystemMessage,
    TextBlock,
    ToolResultBlock,
    ToolUseBlock,
    UserMessage,
)
from claude_agent_sdk.types import TaskNotificationMessage

MARKER = "bg-task-marker-7c1f"

# How long to wait for the whole exchange: the command sleeps a few seconds,
# then Claude Code's next poll picks up the result and Claude answers.
TIMEOUT_S = 180


def block_text(block: ToolResultBlock) -> str:
    content = block.content or ""
    if isinstance(content, list):
        return " ".join(item.get("text", "") for item in content if isinstance(item, dict))
    return str(content)


@pytest.mark.asyncio
async def test_background_command_runs_as_task(agent_options: ClaudeAgentOptions):
    options = dataclasses.replace(
        agent_options,
        # Agent SDK sessions run MCP calls as tasks only with this set.
        env={**agent_options.env, "CLAUDE_AUTO_BACKGROUND_TASKS": "1"},
        max_turns=10,
    )
    prompt = (
        "Use the mcp__lite-sandbox__bash tool with run_in_background set to true "
        f"to run exactly: sleep 5; echo {MARKER}\n"
        "Do not run any other command or poll it. Wait until you are notified "
        "that it finished, then tell me exactly what it printed."
    )

    session_tools: list[str] = []
    bash_calls: list[ToolUseBlock] = []
    tool_results: list[str] = []
    notifications: list[TaskNotificationMessage] = []
    final_text = ""

    async def converse() -> None:
        nonlocal final_text
        async with ClaudeSDKClient(options=options) as client:
            await client.query(prompt)
            async for message in client.receive_messages():
                if isinstance(message, TaskNotificationMessage):
                    notifications.append(message)
                elif isinstance(message, SystemMessage) and message.subtype == "init":
                    session_tools.extend(message.data.get("tools", []))
                elif isinstance(message, AssistantMessage):
                    for block in message.content:
                        if isinstance(block, ToolUseBlock) and block.name == "mcp__lite-sandbox__bash":
                            bash_calls.append(block)
                        elif isinstance(block, TextBlock):
                            final_text += block.text + "\n"
                elif isinstance(message, UserMessage) and isinstance(message.content, list):
                    for block in message.content:
                        if isinstance(block, ToolResultBlock):
                            tool_results.append(block_text(block))
                elif isinstance(message, ResultMessage):
                    final_text += (message.result or "") + "\n"
                    # The first result ends the turn that started the task;
                    # the task's completion starts another.
                    if notifications and MARKER in final_text:
                        return

    try:
        await asyncio.wait_for(converse(), TIMEOUT_S)
    except TimeoutError:
        pytest.fail(
            f"no answer quoting {MARKER!r} within {TIMEOUT_S}s; "
            f"bash calls: {[c.input for c in bash_calls]}, tool results: {tool_results}, "
            f"notifications: {[n.summary for n in notifications]}, text: {final_text!r}"
        )

    assert "mcp__lite-sandbox__bash" in session_tools, session_tools
    for hidden in ("mcp__lite-sandbox__kill_shell", "mcp__lite-sandbox__list_shells"):
        assert hidden not in session_tools, f"{hidden} offered to a task client: {session_tools}"

    assert any(c.input.get("run_in_background") for c in bash_calls), [c.input for c in bash_calls]
    assert not any("shell id" in r for r in tool_results), (
        f"background command answered with a shell id, not a task: {tool_results}"
    )
    assert any(n.status == "completed" for n in notifications), [
        (n.status, n.summary) for n in notifications
    ]
    assert MARKER in final_text, final_text
