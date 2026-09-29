import pickle
import subprocess

import click
from fastapi import FastAPI
from flask import Flask, request

api = FastAPI()
web = Flask(__name__)


@api.get("/run")
def run(cmd: str):
    return subprocess.run(cmd, shell=True).returncode


@api.post("/load")
async def load(blob: bytes):
    return pickle.loads(blob)


@web.route("/ping")
def ping():
    host = request.args.get("host", "")
    return subprocess.check_output("ping -c1 " + host, shell=True)


@click.command()
@click.argument("path")
def cli(path):
    with open(path) as handle:
        print(handle.read())


if __name__ == "__main__":
    cli()
