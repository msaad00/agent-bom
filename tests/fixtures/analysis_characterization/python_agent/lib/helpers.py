import subprocess
import urllib.request


def build_command(value: str) -> str:
    return "grep " + value


def run_shell(cmd: str) -> str:
    return subprocess.getoutput(cmd)


def fetch(url: str) -> bytes:
    return urllib.request.urlopen(url).read()


def unused_sink(value: str) -> None:
    subprocess.call(value, shell=True)
