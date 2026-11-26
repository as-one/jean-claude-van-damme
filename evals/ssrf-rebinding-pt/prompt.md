---
description: A casual Portuguese request triggers the skill, and the review catches check-then-fetch SSRF.
tags: [trigger, review, ssrf]
model: sonnet
max_turns: 15
allowed_tools: [Read, Glob, Grep, Skill]
---
isso aqui tá seguro pra subir?

```python
import ipaddress, socket
from urllib.parse import urlparse
import requests
from flask import Flask, request, abort
from flask_login import login_required

app = Flask(__name__)

@app.post("/preview")
@login_required
def preview():
    url = request.json["url"]
    host = urlparse(url).hostname
    if host is None:
        abort(400)
    if not ipaddress.ip_address(socket.gethostbyname(host)).is_global:
        abort(403)
    return requests.get(url, timeout=5).text
```
