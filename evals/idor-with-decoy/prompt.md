---
description: Finds a missing ownership check and does not flag the look-alike route whose check lives in a decorator.
tags: [review, triage, access-control]
model: sonnet
max_turns: 15
allowed_tools: [Read, Glob, Grep, Skill]
---
Can you check these routes for security problems?

```python
from functools import wraps

from flask import Flask, abort, g, jsonify
from flask_login import current_user, login_required

from models import Attachment, Statement, db

app = Flask(__name__)


def scoped(model):
    def decorate(view):
        @wraps(view)
        def inner(record_id):
            record = db.session.get(model, record_id)
            if record is None or record.owner_id != current_user.id:
                abort(404)
            g.record = record
            return view(record_id)
        return inner
    return decorate


@app.get("/statements/<int:record_id>")
@login_required
@scoped(Statement)
def get_statement(record_id):
    return jsonify(g.record.to_dict())


@app.get("/attachments/<int:record_id>")
@login_required
def get_attachment(record_id):
    record = db.session.get(Attachment, record_id)
    if record is None:
        abort(404)
    return jsonify(record.to_dict())
```

Both `Statement` and `Attachment` have an `owner_id` column.
