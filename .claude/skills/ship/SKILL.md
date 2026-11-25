---
name: ship
description: Commit pending changes on a new branch, open a PR, merge it, sync main, clean up
argument-hint: feature|bugfix <short-name> [commit message]
disable-model-invocation: true
allowed-tools: Bash(git:*), Bash(gh:*), Bash(graphify:*)
---

Ship the current uncommitted changes. Arguments: $ARGUMENTS

1. Parse the arguments as `<feature|bugfix> <short-name> [message]`.
   If the type is missing, ask the user. Don't guess.
   If the name is missing, derive a short one from the context of the changes.
2. Run `git status` and `git diff` so you know what is being shipped.
   If there is nothing to commit, stop.
3. Create the branch as its own Bash call: `features/<name>` or `bugfixes/<name>`.
   (The block-main-commit hook checks the branch before a command runs,
   so checkout and commit can't be chained.)
4. Stage the specific files and commit with a clear message ending with the
   Co-Authored-By line. Don't use `git add -A`.
5. Push with `-u`, then `gh pr create --base main` with a short summary body.
6. `gh pr merge --merge`.
7. `git checkout main`, `git fetch --prune`, `git pull origin main`.
8. Delete the branch locally (`git branch -d`) and on the remote.
9. Report the PR URL, the new `main` commit and `git status`.

If any step fails, stop and report it. Don't force anything.
