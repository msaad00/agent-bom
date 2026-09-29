import os
import subprocess

import requests
from fastapi import Depends, FastAPI
from flask import Flask, request

from helpers import run_it

api = FastAPI()
app = Flask(__name__)


def get_db():
    return None


@api.get("/items/{item_id}")
def read_item(item_id: str, q: str = "", db=Depends(get_db), *, token: str = "", user=Depends(get_db)):
    os.system(item_id)
    os.system(q)
    os.system(db)
    os.system(token)
    os.system(user)


@api.post("/run")
async def run_route(self, cmd: str):
    run_it(cmd)


@app.route("/flask")
def flask_route():
    target = request.args.get("target")
    requests.get(target)
    os.system(request.form["cmd"])
    subprocess.run(request.json, shell=True)
    os.system(request.method)


@app.route("/shadow")
def shadowed():
    request = {"args": "x"}
    os.system(request.args)


@app.route("/shadow-param")
def shadow_param(request):
    os.system(request.args)


@app.get("/both")
def both_route(cmd):
    os.system(cmd)


@app.route("/ann")
def ann_shadow():
    request: dict = {}
    os.system(request.args)


@app.route("/walrus")
def walrus_shadow():
    if request := None:
        os.system(request.args)
