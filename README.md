# Dualship

Check a plugin folder against the Claude plugin directory checks and the ChatGPT
plugin guidelines before you submit it to either one. One plugin folder can now
ship to both: Claude's directory reads `.claude-plugin/plugin.json`, and OpenAI's
importer reads the portable root `plugin.json` (Agent Plugins format) or converts
the Claude manifest for you. The rules differ, and each portal only tells you
after you upload. Dualship tells you before.

## Use it

As a skill: install the plugin and ask "check this plugin before I submit it".

As a script, no install needed (Python 3.9+, standard library only):

```bash
python3 skills/dualship/scripts/check.py path/to/plugin
python3 skills/dualship/scripts/check.py path/to/plugin --target openai --json
```

Each finding is `BLOCK` (portal refuses it), `HOLD` (a human reviewer reads it
first), `WARN` or `NOTE`. The exit code is 1 when anything blocks, so it works in CI.

## What it checks

Names and reserved words, README length, license, junk files, symlinks, file
sizes and binaries, unpinned `npx`/`uvx` launchers, secrets, non-https MCP
servers, credentials read from the environment, hooks and front matter syntax,
pricing or promo words in descriptions, missing MCP tool annotations, and the
parts of a Claude plugin that OpenAI drops or needs converted. Sources are listed
in `skills/dualship/references/rules.md`.

## What it does not do

It is a heuristic. A clean run is not approval. Both directories also run
security scans and human or policy review that a local script can't reproduce.

## Privacy

Runs locally. Collects and sends nothing. See `PRIVACY.md`.
