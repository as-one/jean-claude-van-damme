---
description: Reviews a pipeline that runs fork code with secrets.
tags: [review, ci]
model: sonnet
max_turns: 15
allowed_tools: [Read, Glob, Grep, Skill]
---
Is this GitHub Actions workflow safe? The repository is public.

```yaml
name: preview
on:
  pull_request_target:
    types: [opened, synchronize]
jobs:
  preview:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm install && npm run build
      - run: ./deploy-preview.sh "${{ github.event.pull_request.title }}"
        env:
          DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}
```
