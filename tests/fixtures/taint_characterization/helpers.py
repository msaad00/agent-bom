import os
import subprocess

import requests


def passthrough(value):
    return value


def wrap(value, prefix="x"):
    return f"{prefix}-{value}"


def constant(value):
    return "fixed"


def run_it(cmd):
    return subprocess.run(cmd, shell=True)


def fetch(url, **kwargs):
    return requests.get(url, **kwargs)


def kw_sink(*, path):
    return open(path)


def hop1(value):
    return hop2(value)


def hop2(value):
    return hop3(value)


def hop3(value):
    return hop4(value)


def hop4(value):
    return hop5(value)


def hop5(value):
    return hop6(value)


def hop6(value):
    os.system(value)
    return value


def recurse(value, depth):
    if depth > 0:
        return recurse(value, depth - 1)
    return eval(value)


def ping(value):
    return pong(value)


def pong(value):
    os.popen(value)
    return ping(value)


def exec_from_kwargs(**options):
    exec(options)
