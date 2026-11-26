---
type: llm
---
PASS if the response says the address check can be bypassed to reach internal hosts, through DNS rebinding (the name is resolved again by requests) or through redirects, and proposes connecting to the validated address, re-checking each redirect, or an egress control.
FAIL if it calls the code safe, or misses both the rebinding and the redirect bypass.
