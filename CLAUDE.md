Read AGENTS.md and follow it.



Agent protections: follow AGENTS.md and review .agent-guard/README.md.


Read AGENTS.md and follow it. Then read SPEC.md; it is the contract.

Work one milestone per branch and PR, in SPEC.md order, starting at M1. Do not begin M(n+1) until the human has merged M(n). Section 1 constraints are hard failures.

Git: new commits only, fast-forward only. Never amend, rebase, reset --hard, force-push, delete branches, change remotes, or touch git identity or config. Hooks will refuse these and log the attempt; if one refuses you, report the message and stop.

Never modify .agent-guard/, .claude/, .cursor/, .github/workflows/, AGENTS.md, or this file.

Record non-obvious decisions in docs/adr/ when you make them. Write tests with the code. Do not weaken or skip tests to pass.
