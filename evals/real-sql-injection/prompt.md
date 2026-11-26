---
description: Finds an unauthenticated SQL injection and reports it in the skill format.
tags: [review, triage]
model: sonnet
max_turns: 15
allowed_tools: [Read, Glob, Grep, Skill]
---
Please do a security review of this endpoint before I merge it.

```js
const express = require("express");
const { pool } = require("./db");
const router = express.Router();

router.get("/products/search", async (req, res) => {
  const term = req.query.q || "";
  const result = await pool.query(
    `SELECT id, name, price FROM products WHERE name ILIKE '%${term}%' LIMIT 50`
  );
  res.json(result.rows);
});

module.exports = router;
```
