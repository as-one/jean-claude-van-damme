---
description: A finding that depends on an unseen condition must be labelled needs verification (triage rule 5).
tags: [review, triage]
model: sonnet
max_turns: 15
allowed_tools: [Read, Glob, Grep, Skill]
---
Can you security review this service? It runs somewhere behind our gateway.

```js
const express = require("express");
const { db } = require("./db");
const app = express();

app.get("/internal/reports", async (req, res) => {
  const tenant = req.headers["x-tenant-id"]; // set by the gateway after login
  if (!tenant) return res.sendStatus(401);
  const rows = await db.query("SELECT * FROM reports WHERE tenant_id = $1", [tenant]);
  res.json(rows.rows);
});

app.listen(8080);
```
