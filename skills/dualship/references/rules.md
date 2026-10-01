# Rule sources

Rules were transcribed on 2026-10-02 from:

- Claude plugin pre-submission checklist: https://claude.com/docs/plugins/pre-submission-checklist
- Claude component support by surface: https://claude.com/docs/plugins/platform-support
- Anthropic Software Directory Policy: https://support.claude.com/en/articles/13145358-anthropic-software-directory-policy
- OpenAI plugin guidelines: https://developers.openai.com/plugins/plugin-guidelines
- OpenAI "Submit your Claude Code plugin": https://developers.openai.com/plugins/guides/submit-claude-plugin
- OpenAI plugin package format: https://developers.openai.com/plugins/build/plugins

| Rule id prefix | Target | Source section |
| - | - | - |
| manifest.* | claude | Manifest and plugin name |
| readme.*, license.* | claude | README and license |
| files.* | claude | Files in the plugin folder, repository layout |
| launcher.*, mcp.* | claude | Review what the plugin runs and connects to |
| hooks.*, frontmatter.* | claude | Hooks, skills, commands, and agents |
| metadata.promo | openai | Naming & metadata: no pricing, trials, discounts, promotions |
| metadata.name-suffix | openai | Do not append "MCP"/"Plugin" to names |
| tools.* | openai | MCP tool naming and required annotations |
| mcp.local, mcp.json-dropped | openai | Claude plugin import: remote HTTPS endpoint only |
| commands.convert, agents.convert, skills.neutral-language, userconfig | openai | Claude plugin import: what requires conversion |
| listing.* | openai | Privacy policy and support contact |

Both directories change their rules. Re-check the sources before relying on a rule.
