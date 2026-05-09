import os
import pickle
import sqlite3
import subprocess
from flask import request

API_KEY = "sk_live_this_is_a_demo_secret_value"


def user_lookup(conn: sqlite3.Connection):
    user_id = request.args.get("id")
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return conn.execute(query).fetchall()


def run_backup():
    name = request.args.get("name")
    subprocess.run("tar czf /tmp/" + name + ".tgz ./data", shell=True)


def read_file():
    filename = request.args.get("file")
    with open(os.path.join("/srv/app/uploads", filename), "r") as f:
        return f.read()


def load_cache(raw):
    return pickle.loads(raw)


def dynamic(expr):
    return eval(expr)


def swallow():
    try:
        raise RuntimeError("demo")
    except Exception:
        pass
