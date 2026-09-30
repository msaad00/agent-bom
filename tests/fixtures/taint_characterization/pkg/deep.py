import pickle
import sqlite3


def store(record):
    conn = sqlite3.connect("x.db")
    conn.execute("INSERT INTO t VALUES ('%s')" % record)
    return pickle.loads(record)


def render(markup):
    from flask import render_template_string

    return render_template_string(markup)
