import html
import os
import shlex
import sqlite3
import subprocess

import requests
from mcp.server.fastmcp import FastMCP
from openai import OpenAI

import helpers
import pkg.deep as deep
from helpers import passthrough, wrap, constant, run_it, fetch, kw_sink
from validators import is_allowed, check_name, verify_token, looping_guard, safe_kw, plain_helper

mcp = FastMCP("taint")
client = OpenAI()


@mcp.tool()
def path_sink(path: str) -> str:
    with open(path) as handle:
        return handle.read()


@mcp.tool()
def ssrf_sink(url: str) -> str:
    return requests.get(url, timeout=3).text


@mcp.tool()
def shell_sink(cmd: str) -> None:
    subprocess.run(cmd, shell=True)
    subprocess.run(cmd)
    os.system(cmd)


@mcp.tool()
def code_sink(expr: str) -> object:
    return eval(expr)


@mcp.tool()
def sql_sink(user: str) -> list:
    conn = sqlite3.connect("x.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM t WHERE u = '" + user + "'")
    return conn.execute(f"SELECT {user}").fetchall()


@mcp.tool()
def llm_sink(question: str) -> str:
    messages = [{"role": "user", "content": question}]
    return client.chat.completions.create(model="m", messages=messages)


@mcp.tool()
def xss_sink(name: str) -> str:
    from flask import render_template_string

    return render_template_string("<p>%s</p>" % name)


@mcp.tool()
def sanitized(cmd: str, page: str, name: str) -> None:
    quoted = shlex.quote(cmd)
    os.system(quoted)
    escaped = html.escape(page)
    requests.get(escaped)
    base = os.path.basename(name)
    open(base)


@mcp.tool()
def source_calls(unused: str) -> None:
    value = input("x")
    os.system(value)


@mcp.tool()
def reassigned(cmd: str) -> None:
    cmd = "ls"
    os.system(cmd)
    other: str = cmd
    other = cmd
    os.system(other)


@mcp.tool()
def ann_and_aug(cmd: str, extra: str) -> None:
    built: str = cmd
    os.system(built)
    clean: str = "safe"
    clean += extra
    os.system(clean)
    count = 1
    count += 2
    os.system(count)
    extra: str
    os.system(extra)


@mcp.tool()
def containers(a: str, b: str, c: str) -> None:
    items = [a, "x"]
    pair = ("y", b)
    bag = {c}
    mapping = {"k": a, b: "v"}
    spread = {**mapping}
    os.system(items)
    os.system(pair)
    os.system(bag)
    os.system(mapping)
    os.system(mapping["k"])
    os.system(spread)


@mcp.tool()
def expressions(a: str, b: str) -> None:
    joined = a or b
    compared = a == "x" < b
    ternary = a if b else "z"
    comp = [x for x in a]
    gen = {k: v for k, v in b.items()}
    star = [*a]
    os.system(joined)
    os.system(compared)
    os.system(ternary)
    os.system(lambda: a)
    os.system(comp)
    os.system(gen)
    os.system(star)
    os.system(f"{a!r:>10}")
    os.system(-a)
    os.system(a[1:2])


@mcp.tool()
def attribute_flow(obj: object) -> None:
    os.system(obj.command)
    os.system(obj.items[0].name)
    os.system(obj.strip().lower())
    os.system(obj.method(1, key=2))


@mcp.tool()
def keyword_flow(target: str) -> None:
    subprocess.run(args=target, shell=True)
    requests.request("GET", url=target)
    kw_sink(path=target)


@mcp.tool()
def through_helpers(cmd: str) -> None:
    same = passthrough(cmd)
    os.system(same)
    wrapped = wrap(cmd, prefix="p")
    os.system(wrapped)
    fixed = constant(cmd)
    os.system(fixed)
    run_it(cmd)
    fetch(cmd, timeout=3)
    helpers.passthrough(cmd)
    deep.store(cmd)
    deep.render(cmd)


@mcp.tool()
def deep_chain(value: str) -> None:
    helpers.hop1(value)


@mcp.tool()
def recursion(value: str) -> None:
    helpers.recurse(value, 3)
    helpers.ping(value)


@mcp.tool()
def kwargs_flow(payload: dict) -> None:
    helpers.exec_from_kwargs(**payload)
    fetch("https://x", headers=payload)
    run_it(*payload)


@mcp.tool()
def guarded(cmd: str, other: str, third: str) -> None:
    if is_allowed(cmd):
        os.system(cmd)
    if check_name(other):
        os.system(other)
    else:
        os.system(other)
    assert verify_token(third, cmd)
    os.system(third)


@mcp.tool()
def post_if(cmd: str, other: str, third: str) -> None:
    if not check_name(cmd):
        return None
    os.system(cmd)
    if is_allowed(other):
        pass
    else:
        raise ValueError(other)
    os.system(other)
    if looping_guard(third) and safe_kw(third):
        os.system(third)
    if not plain_helper(third):
        return None
    os.system(third)
    if not (third or cmd):
        return None
    os.system(third)


@mcp.tool()
def inline_guard(cmd: str, name: str) -> None:
    if cmd in ("a", "b"):
        os.system(cmd)
    if name.isalnum() and validate_local(name):
        subprocess.run(name, shell=True)
    os.system(name)


def validate_local(name):
    return name.isalnum()


@mcp.tool()
def loops(items: list, flag: str) -> None:
    for item in items:
        os.system(item)
    else:
        os.system(flag)
    for index, (left, right) in enumerate(items):
        os.system(left)
    while flag:
        os.system(flag)
        flag = ""
    for constant_item in ["a", "b"]:
        os.system(constant_item)


@mcp.tool()
async def async_flow(url: str, cmd: str) -> None:
    async for chunk in helpers.stream(url):
        os.system(chunk)
    async with client.session(url) as session:
        os.system(session)
    result = await helpers.async_fetch(url)
    os.system(result)
    requests.get(await something(cmd))


async def something(value):
    return value


@mcp.tool()
def with_flow(path: str) -> None:
    with open(path) as handle, open("fixed") as other:
        os.system(handle)
        os.system(other)
    with open("const") as const_handle:
        os.system(const_handle)


@mcp.tool()
def try_flow(cmd: str) -> str:
    try:
        staged = cmd
        os.system(staged)
    except ValueError as exc:
        os.system(exc)
        caught = cmd
    except Exception:
        return cmd
    else:
        os.system(staged)
    finally:
        final = cmd
    os.system(caught)
    os.system(final)
    return staged


@mcp.tool()
def try_star_flow(cmd: str) -> None:
    try:
        os.system(cmd)
    except* ValueError:
        os.system(cmd)


@mcp.tool()
def match_flow(cmd: str) -> None:
    match cmd:
        case "a":
            os.system(cmd)
        case _:
            pass


@mcp.tool()
def nested_def(cmd: str) -> None:
    def inner(value):
        os.system(value)

    inner(cmd)
    os.system(cmd)


@mcp.tool()
def walrus(cmd: str) -> None:
    if n := cmd:
        os.system(n)


@mcp.tool()
def duplicate_paths(cmd: str) -> None:
    run_it(cmd)
    run_it(cmd)
    run_it(passthrough(cmd))


@mcp.tool()
def no_params() -> None:
    os.system("ls")


@mcp.tool()
def unused_param(cmd: str) -> None:
    os.system("ls")


class Toolkit:
    def helper(self, value):
        return subprocess.check_output(value, shell=True)

    @mcp.tool()
    def method_tool(self, value: str) -> None:
        self.helper(value)
        self.missing(value)

    @staticmethod
    def static_helper(value):
        return os.popen(value)

    @mcp.tool()
    def uses_static(self, value: str) -> None:
        Toolkit.static_helper(value)


def same_file_helper(value):
    return subprocess.call(value, shell=True)


@mcp.tool()
def ambiguous(cmd: str, obj: object) -> None:
    obj.same_file_helper(cmd)
    obj.passthrough(cmd)
    obj.caller(cmd)


@mcp.tool()
def credentials(path: str) -> None:
    open(os.path.expanduser("~/.aws/credentials")).read()
    open(path, "w").write("x")


@mcp.tool()
def json_source(req: object) -> None:
    body = req.get_json()
    os.system(body)
    requests.post(body["url"])


@mcp.tool()
def string_building(cmd: str) -> None:
    command = "ls %s" % cmd
    subprocess.run(command, shell=True)
    url = "https://{}".format(cmd)
    requests.get(url)
    sqlite3.connect("x").execute("SELECT %s" % cmd)


@mcp.tool()
def unsafe_deserialize(blob: bytes) -> None:
    import pickle

    import yaml

    pickle.loads(blob)
    yaml.load(blob, Loader=yaml.SafeLoader)
    yaml.load(blob)
