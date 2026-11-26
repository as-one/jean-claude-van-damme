---
description: Code that looks risky but is safe must not produce High or Critical findings.
tags: [review, triage, false-positive]
model: sonnet
max_turns: 15
allowed_tools: [Read, Glob, Grep, Skill]
---
Quick security check: is anything here exploitable?

```python
import subprocess
from flask import Flask, request, jsonify, abort
from flask_login import LoginManager, login_required, current_user
from db import get_conn
from auth import load_user

app = Flask(__name__)
LoginManager(app).user_loader(load_user)

ORDER_BY = {"newest": "created_at DESC", "oldest": "created_at ASC"}
HOSTS = {"primary": "db1.internal", "replica": "db2.internal"}

@app.get("/api/notes")
@login_required
def notes():
    order = ORDER_BY.get(request.args.get("order"), "created_at DESC")
    with get_conn() as conn:
        rows = conn.execute(
            f"SELECT id, body FROM notes WHERE owner_id = %s ORDER BY {order}",
            (current_user.id,),
        ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.get("/api/ping/<name>")
@login_required
def ping(name):
    host = HOSTS.get(name)
    if host is None:
        abort(404)
    done = subprocess.run(["ping", "-c", "1", host], capture_output=True, timeout=5)
    return jsonify(ok=done.returncode == 0)
```
