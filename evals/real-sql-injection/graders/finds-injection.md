---
type: llm
---
PASS if the response reports SQL injection through the `q` query parameter, rates it High or Critical, and fixes it with a bound parameter.
FAIL if the injection is missed, rated Medium or lower, or fixed only by escaping or filtering characters.
