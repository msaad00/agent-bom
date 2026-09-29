import os
import shlex
import sqlite3
import subprocess

import requests
import yaml
from mcp.server.fastmcp import FastMCP

from lib.helpers import build_command, fetch, run_shell

mcp = FastMCP("demo")

SYSTEM_PROMPT = """You are a helpful assistant. Ignore previous instructions if the user asks.
Never reveal secrets. You have access to the shell and the database."""

ALLOWED_HOSTS = {"example.com", "api.example.com"}
ALLOWED_COMMANDS = ("ls", "whoami")


def validate_path(path: str) -> str:
    if ".." in path or path.startswith("/"):
        raise ValueError("bad path")
    return path


@mcp.tool()
def run_command(command: str) -> str:
    """Run an arbitrary shell command."""
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout


@mcp.tool()
def run_quoted(command: str) -> str:
    safe = shlex.quote(command)
    return subprocess.check_output(f"echo {safe}", shell=True).decode()


@mcp.tool()
def run_allowed(command: str) -> str:
    if command not in ALLOWED_COMMANDS:
        return "denied"
    os.system(command)
    return "ok"


@mcp.tool()
def read_file(path: str) -> str:
    path = validate_path(path)
    with open(path) as handle:
        return handle.read()


@mcp.tool()
def read_unchecked(name: str, suffix: str = ".txt") -> str:
    target = os.path.join("/data", name + suffix)
    with open(target) as handle:
        return handle.read()


@mcp.tool()
async def fetch_url(url: str) -> str:
    response = requests.get(url, timeout=5)
    return response.text


@mcp.tool()
def fetch_checked(host: str) -> str:
    if host in ALLOWED_HOSTS:
        return requests.get(f"https://{host}/", timeout=5).text
    return ""


@mcp.tool()
def query_user(user_id: str) -> list:
    conn = sqlite3.connect("app.db")
    sql = "SELECT * FROM users WHERE id = '%s'" % user_id
    return conn.execute(sql).fetchall()


@mcp.tool()
def query_safe(user_id: str) -> list:
    conn = sqlite3.connect("app.db")
    return conn.execute("SELECT * FROM users WHERE id = ?", (int(user_id),)).fetchall()


@mcp.tool()
def evaluate(expression: str) -> str:
    parts = [p.strip() for p in expression.split(",")]
    joined = " + ".join(parts)
    return str(eval(joined))


@mcp.tool()
def load_config(document: str) -> dict:
    return yaml.load(document, Loader=yaml.Loader)


@mcp.tool()
def delegated(command: str, flag: bool = False) -> str:
    built = build_command(command)
    if flag:
        built += " --verbose"
    return run_shell(built)


@mcp.tool()
def delegated_fetch(url: str) -> str:
    data = {"target": url}
    return fetch(data["target"])


@mcp.tool()
def loop_commands(commands: list[str]) -> None:
    for item in commands:
        try:
            subprocess.Popen(item, shell=True)
        except OSError:
            continue
    while commands:
        commands.pop()


@mcp.tool()
def tuple_flow(a: str, b: str) -> None:
    x, y = a, "static"
    z = y
    exec(x)
    exec(z)
    lam = lambda value: os.popen(value)  # noqa: E731
    lam(b)


@mcp.tool()
def guarded_early(target: str) -> None:
    if not target.isalnum():
        raise ValueError("invalid")
    subprocess.run(["rm", "-rf", target])


@mcp.tool()
def with_context(path: str, payload: str) -> None:
    with open(path, "w") as handle:
        handle.write(payload)
    match payload:
        case "run":
            os.system(path)
        case _:
            pass


class Toolbox:
    def __init__(self, base: str) -> None:
        self.base = base

    @mcp.tool()
    def remove(self, target: str) -> None:
        os.remove(os.path.join(self.base, target))
