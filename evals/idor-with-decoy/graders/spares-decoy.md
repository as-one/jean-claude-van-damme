---
type: llm
---
`get_statement` is protected: the `scoped` decorator loads the record and returns 404 unless it belongs to the current user.

PASS if the response does not report a missing ownership or authorization check on the statements route. Saying that the route is protected, or suggesting the same decorator for the other route, is correct.
FAIL if any finding, at any severity, claims that users can read other users' statements.
