"""SYNTHETIC vulnerable sample app — the target the AI code-audit demo maps.

This file is DELIBERATELY insecure. It exists only so the /code-scan AI-audit demo has a small,
public, synthetic repo to fan out over (never a real client's private source in a screenshot).
Each route carries one classic, attacker-reachable bug so the enumerate -> flows -> verify
pipeline has something concrete to find. Do not deploy this. It is not imported by HackPit.
"""

import os
import sqlite3
import subprocess

from flask import Flask, request, send_file

app = Flask(__name__)


@app.route("/fetch")
def fetch():
    # SSRF: attacker controls the outbound URL, no allow-list.
    import requests

    url = request.args.get("url")
    return requests.get(url).text


@app.route("/ping")
def ping():
    # OS command injection: host is concatenated straight into a shell command.
    host = request.args.get("host")
    return subprocess.run("ping -c 1 " + host, shell=True, capture_output=True).stdout


@app.route("/user")
def user():
    # SQL injection: the id is string-formatted into the query.
    uid = request.args.get("id")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = '%s'" % uid)
    return str(cur.fetchall())


@app.route("/download")
def download():
    # Path traversal: filename is opened with no canonicalisation.
    name = request.args.get("file")
    return send_file(open(name, "rb"))


@app.route("/admin")
def admin():
    # Broken auth: compares against a constant secret baked into source.
    if request.args.get("token") == "letmein":
        return "welcome, admin"
    return "denied", 403


@app.route("/calc")
def calc():
    # Code injection: request expression is evaluated.
    expr = request.args.get("expr")
    return str(eval(expr))


if __name__ == "__main__":
    app.run()
