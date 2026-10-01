---
name: dualship
description: Check a plugin folder against the Claude plugin directory checks and the ChatGPT plugin guidelines before submitting it. Use when the user wants to submit, publish, list or cross-list a plugin, asks whether a plugin will pass review, or asks what to change to ship the same plugin to both Claude and ChatGPT.
---

# dualship

Lint one plugin folder against both directories' published rules, then help the
user fix what blocks submission.

## Steps

1. Find the plugin folder: the folder holding `.claude-plugin/plugin.json`, a root
   `plugin.json`, or `skills/<name>/SKILL.md`. If the user named a repository with
   several plugins, check each plugin folder on its own.
2. Run the checker from this skill's folder:

   ```bash
   python3 scripts/check.py <plugin-folder>
   ```

   Add `--target claude` or `--target openai` when the user only cares about one
   directory. Add `--json` when you need to process the findings.
3. Read the result. Each line is `SEVERITY TARGET RULE message (path)`:
   - `BLOCK`: the directory refuses the submission until this is fixed.
   - `HOLD`: submission goes through, but a human reviewer reads it first. Slower.
   - `WARN`: allowed, but worth fixing; most OpenAI portability items land here.
   - `NOTE`: information only.
4. Fix BLOCK findings first, then HOLD, then WARN. Propose each fix as a concrete
   edit and make it when the user agrees. Re-run the checker after edits.
5. Report what still fails, and say plainly that a clean run is a heuristic, not
   an approval. Both directories run more checks (security scans, human review,
   policy review) than this script can.

## What the checker does not cover

- Policy judgement calls: whether the plugin is useful beyond what the model
  already does natively, impersonation, IP, commerce rules beyond keyword checks.
- Remote MCP server behaviour: OAuth, domain verification, test credentials.
- Whether tool descriptions are accurate. Read them yourself against the code.

See `references/rules.md` for the source of each rule.
