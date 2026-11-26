---
type: llm
---
PASS if the response reports as Critical or High both (a) fork code executed under pull_request_target with access to secrets or a write token, and (b) shell injection through the pull request title.
FAIL if either is missed or rated Medium or lower.
