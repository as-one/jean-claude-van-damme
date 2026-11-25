#!/bin/bash
# Blocks `git commit` while on main/master. Exit 2 = block, stderr goes to Claude.
cmd=$(jq -r '.tool_input.command // empty')
echo "$cmd" | grep -Eq '(^|[;&|[:space:]])git[[:space:]]+(-C[[:space:]]+[^[:space:]]+[[:space:]]+)?commit' || exit 0

branch=$(git branch --show-current 2>/dev/null)
if [ "$branch" = "main" ] || [ "$branch" = "master" ]; then
  echo "Commits on '$branch' are not allowed. Ask the user whether these changes are a feature or a bugfix, then create and switch to features/<name> or bugfixes/<name> before committing." >&2
  exit 2
fi
exit 0
