"""Intentional vulnerabilities for PolyScan testing.

DO NOT SHIP — every function here is a deliberate flaw that
Semgrep / Bandit / ESLint / SpotBugs should flag.
"""
import ast
import hashlib
import md5
import os
import pickle
import subprocess
from flask import request


def sql_injection(user_id: str) -> None:
    # Bandit: B608 (hardcoded SQL) + Semgrep: dangerous query
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    print(query)


def command_injection(name: str) -> None:
    # Bandit: B602/B603/B604 — subprocess with shell + user input
    subprocess.call("echo welcome " + name, shell=True)


def eval_usage() -> None:
    # Bandit: B307 — eval
    data = request.args.get("data", "")
    eval(data)


def insecure_hash() -> None:
    # Bandit: B303/B324 — MD5/SHA1 weak hash
    md5.new(b"secret").digest()
    hashlib.sha1(b"secret").hexdigest()


def pickle_load() -> None:
    # Bandit: B301/B302 — pickle
    with open("x.pkl", "rb") as f:
        pickle.load(f)


def hardcoded_secret() -> None:
    # Semgrep/Bandit: hardcoded credential
    password = "Sup3rSecretP@ssw0rd!"
    api_key = "AKIAIOSFODNN7EXAMPLE"
    token = "ghp_1234567890abcdef1234567890abcdef1234"
    print(password, api_key, token)


def taint_sink() -> None:
    # Semgrep: untrusted input -> dangerous sink
    raw = request.json.get("cmd")
    os.system(raw)
