"""Interactive chat command for agent-bom."""

from __future__ import annotations

import asyncio
import sys

import click
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel


@click.command("chat")
def chat_cmd():
    """Start an interactive chat session with agent-bom.

    \b
    Ask questions, run scans, and explore your security posture
    conversationally. Type 'help' for available commands.
    """
    asyncio.run(_chat_loop())


async def _chat_loop() -> None:
    """Main interactive chat REPL."""
    from agent_bom.chat import ChatContext, handle_message

    console = Console()
    ctx = ChatContext(console=console)

    # Print welcome banner
    console.print(
        Panel(
            "[bold cyan]agent-bom[/bold cyan] [dim]interactive chat[/dim]\n\n"
            "Ask me about your AI agent security posture.\n"
            "Type [bold]help[/bold] for commands, [bold]exit[/bold] to quit.",
            title="[bold]🔒 agent-bom chat[/bold]",
            border_style="cyan",
            padding=(1, 2),
        )
    )
    console.print()

    while True:
        try:
            user_input = console.input("[bold cyan]you>[/bold cyan] ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]Goodbye![/dim]")
            break

        if not user_input:
            continue

        if user_input.lower() in ("exit", "quit", "bye", "q"):
            console.print("[dim]Goodbye![/dim]")
            break

        response = await handle_message(user_input, ctx)

        console.print()
        console.print(Markdown(response))
        console.print()
