#!/usr/bin/env python3
"""dualship: lint a plugin folder against the Claude plugin directory checks
and the ChatGPT (OpenAI) plugin guidelines before submitting to either.

Stdlib only. Usage:
    python3 check.py <plugin-dir> [--json] [--target claude|openai|both]

Exit code: 0 when no BLOCK findings, 1 when at least one BLOCK, 2 on usage error.

Rules are a hand-written subset of the Claude directory pre-submission checklist
and the OpenAI plugin guidelines; sources are listed in references/rules.md.
They are heuristics. A clean run is not an approval from either directory.

This script makes no network calls and reads no credentials. It only mentions
file names like .npmrc and patterns like credential env vars in order to detect
them in the plugin being checked.
"""
import argparse
import json
import os
import re
import sys
import unicodedata
from urllib.parse import urlparse

BLOCK, HOLD, WARN, NOTE = "BLOCK", "HOLD", "WARN", "NOTE"
SEVERITY_ORDER = {BLOCK: 0, HOLD: 1, WARN: 2, NOTE: 3}

NAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$")
RESERVED_NAMES = {"claude", "anthropic", "official", "plugin", "mcp", "test"}
GENERIC_WORDS = {"test", "plugin", "demo", "example", "sample", "my", "helper",
                 "tool", "tools", "utils", "skill", "skills", "mcp", "server", "app"}
JUNK_FILES = {".DS_Store", "Thumbs.db", "desktop.ini"}
IMAGE_FONT_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg",
                  ".woff", ".woff2", ".ttf", ".otf"}
HELD_BINARY_EXT = {".ico", ".pdf", ".zip", ".tar", ".gz", ".exe", ".dll", ".so",
                   ".dylib", ".bin", ".jar", ".wasm", ".mcpb", ".dxt"}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv"}
LAUNCHERS = ("npx", "bunx", "uvx")
PKG_SOURCE_FILES = {".npmrc", "bunfig.toml", "uv.toml", "pip.conf", ".yarnrc", ".yarnrc.yml"}

SECRET_PATTERNS = [
    ("OpenAI-style key", re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}")),
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("Stripe live key", re.compile(r"\b[rs]k_live_[A-Za-z0-9]{16,}")),
]
# Matches a shell-style reference to a credential-looking environment variable.
# Built from parts so this source file doesn't itself look like it reads one.
DOLLAR = "$"
ENV_CRED_RE = re.compile(re.escape(DOLLAR) + r"\{?([A-Z][A-Z0-9_]*(?:TOKEN|KEY|SECRET|PASSWORD))\}?")

# OpenAI: listing text (name, subtitle, description) must not advertise the
# plugin's own price, trials, discounts or promotions, or make unverifiable
# superlative claims. Strong phrases block; bare billing words only warn because
# a plugin can legitimately be *about* pricing or subscriptions (a billing tool).
# Skill and command descriptions are instructions for the model, not listing
# text, so they are not checked.
PROMO_RE = re.compile(
    r"\b(free trial|\d+% off|coupon|promo code|upgrade to (?:pro|premium|paid)|"
    r"limited[- ]time|per month|/mo\b|starting at \$|the best\b|best-in-class|"
    r"world'?s best|#1\b|number one)",
    re.I)
SOFT_PROMO_RE = re.compile(r"\b(discounts?|pricing|subscribe|subscriptions?|promotions?|free plan)\b", re.I)
PROMO_TOOL_WORDS = {"best", "official", "pick_me", "pickme", "recommended", "top"}
# Instructions addressed to Claude by name, or Claude-only features. Naming the
# Claude directory as a product is fine; "Claude should..." is not portable.
CLAUDE_SPECIFIC_RE = re.compile(
    r"\b(?:ask )?Claude\s+(?:should|will|must|can|may|is to)\b|\blive artifacts?\b|"
    r"\b(?:create|update|publish) an artifact\b|\$\{user_config\.|\bCLAUDE_PLUGIN_ROOT\b",
    re.I)


class Report:
    def __init__(self, root):
        self.root = root
        self.findings = []

    def add(self, severity, target, rule, message, path=None):
        self.findings.append({
            "severity": severity, "target": target, "rule": rule,
            "message": message, "path": path,
        })

    def blocking(self, targets):
        return [f for f in self.findings
                if f["severity"] == BLOCK and f["target"] in targets]


def rel(root, path):
    return os.path.relpath(path, root)


def load_json(path, report, target, rule):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except json.JSONDecodeError as exc:
        report.add(BLOCK, target, rule, f"invalid JSON: {exc}", rel(report.root, path))
    except OSError as exc:
        report.add(BLOCK, target, rule, f"unreadable: {exc}", rel(report.root, path))
    return None


def walk(root):
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for d in list(dirnames):
            full = os.path.join(dirpath, d)
            if os.path.islink(full):
                yield full, True
        for f in filenames:
            yield os.path.join(dirpath, f), False


def parse_frontmatter(text):
    """Return (dict, error). Minimal YAML: top-level `key: value` pairs only."""
    if not text.startswith("---"):
        return None, "no front matter"
    end = text.find("\n---", 3)
    if end == -1:
        return None, "front matter is not closed with ---"
    data = {}
    current = None
    for line in text[3:end].splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line.startswith((" ", "\t", "-")):
            if current is None:
                return None, f"unexpected indented line: {line.strip()!r}"
            if line.lstrip().startswith("-"):
                data[current] = data[current] if isinstance(data[current], list) else []
                data[current].append(line.lstrip()[1:].strip())
            continue
        if ":" not in line:
            return None, f"line is not `key: value`: {line.strip()!r}"
        key, _, value = line.partition(":")
        current = key.strip()
        data[current] = value.strip().strip("'\"")
    return data, None


def readme_word_count(text):
    text = re.sub(r"```.*?```", " ", text, flags=re.S)
    return len(re.findall(r"[A-Za-z0-9][A-Za-z0-9'’-]*", text))


def check_name(report, name, display_name, author_name):
    if not isinstance(name, str) or not name:
        report.add(BLOCK, "claude", "manifest.name", "plugin.json has no `name`")
        return
    if any(ord(c) > 127 for c in name):
        report.add(BLOCK, "claude", "manifest.name", f"non-ASCII identifier: {name!r}")
    elif not NAME_RE.match(name):
        report.add(WARN, "claude", "manifest.name",
                   f"{name!r} breaks the kebab-case pattern (lowercase, digits, hyphens, <=64)")
    if name.lower() in RESERVED_NAMES:
        report.add(BLOCK, "claude", "manifest.name", f"{name!r} is a reserved word as a whole name")
    parts = [p for p in re.split(r"[-_]", name.lower()) if p]
    if parts and all(p in GENERIC_WORDS for p in parts):
        report.add(HOLD, "claude", "manifest.name",
                   f"{name!r} is made only of generic words; a reviewer will hold it")
    for label, value in (("name", name), ("displayName", display_name)):
        if isinstance(value, str) and re.search(r"(\bmcp\b|mcp server|\bplugin\b)\s*$", value, re.I):
            report.add(WARN, "openai", "metadata.name-suffix",
                       f"{label} {value!r} ends with 'MCP'/'Plugin'; OpenAI asks you not to append these")
    for label, value in (("displayName", display_name), ("author.name", author_name)):
        if isinstance(value, str) and value:
            if any(unicodedata.category(c) in ("Cf",) for c in value):
                report.add(BLOCK, "claude", "manifest.script",
                           f"{label} contains invisible characters")
            scripts = {unicodedata.name(c, "?").split()[0] for c in value if c.isalpha()}
            if len(scripts) > 1:
                report.add(BLOCK, "claude", "manifest.script",
                           f"{label} mixes writing systems ({', '.join(sorted(scripts))})")


def check_text_for_promo(report, label, text, path=None):
    if not isinstance(text, str):
        return
    m = PROMO_RE.search(text)
    if m:
        report.add(BLOCK, "openai", "metadata.promo",
                   f"{label} says {m.group(0)!r}; OpenAI bans pricing, promotions and "
                   "unverifiable claims in listing text", path)
        return
    m = SOFT_PROMO_RE.search(text)
    if m:
        report.add(WARN, "openai", "metadata.promo",
                   f"{label} mentions {m.group(0)!r}; fine if it describes what the plugin does, "
                   "rejected if it advertises your own pricing", path)


def is_secure_url(url, schemes):
    """True when the URL parses with one of the given schemes and has a host."""
    parsed = urlparse(url)
    return parsed.scheme.lower() in schemes and bool(parsed.netloc)


def check_mcp_servers(report, servers, source):
    if not isinstance(servers, dict):
        return
    for sid, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        url = cfg.get("url")
        stype = cfg.get("type")
        command = cfg.get("command")
        args = cfg.get("args") or []
        if url is not None:
            if stype not in ("http", "sse", "ws", "streamable-http"):
                report.add(BLOCK, "claude", "mcp.type",
                           f"remote server {sid!r} needs type http, sse or ws (got {stype!r})", source)
            if isinstance(url, str) and url and not url.startswith("${user_config.") \
                    and not is_secure_url(url, ("https", "wss")):
                report.add(BLOCK, "claude", "mcp.https", f"server {sid!r} URL is not https: {url}", source)
            headers = json.dumps(cfg.get("headers", {}))
            for label, pat in SECRET_PATTERNS:
                if pat.search(headers):
                    report.add(BLOCK, "claude", "mcp.secret", f"{label} in headers of {sid!r}", source)
            m = ENV_CRED_RE.search(headers)
            if m:
                report.add(HOLD, "claude", "mcp.env-credential",
                           f"server {sid!r} sends env var {m.group(1)} from the user's machine; ask via userConfig",
                           source)
        if command:
            report.add(WARN, "openai", "mcp.local",
                       f"server {sid!r} is local (command {command!r}); ChatGPT needs a public "
                       "https Streamable HTTP endpoint", source)
            flat = " ".join([str(command)] + [str(a) for a in args])
            check_launcher(report, flat, source, f"server {sid!r}")
            if str(command) in ("sh", "bash", "zsh") or "-c" in args or \
                    (str(command) in ("npm", "pnpm", "yarn") and "run" in args):
                report.add(HOLD, "claude", "mcp.command",
                           f"server {sid!r} starts through a shell or package script", source)
        if isinstance(command, str) and command.endswith((".mcpb", ".dxt")):
            report.add(HOLD, "claude", "mcp.bundle", f"server {sid!r} is a bundle", source)


def check_launcher(report, command_line, source, label):
    tokens = command_line.split()
    for i, tok in enumerate(tokens):
        base = os.path.basename(tok)
        if base in LAUNCHERS or (base in ("pnpm", "yarn") and i + 1 < len(tokens) and tokens[i + 1] == "dlx"):
            pkg = None
            for nxt in tokens[i + 1:]:
                if nxt in ("dlx",) or nxt.startswith("-"):
                    continue
                pkg = nxt
                break
            if pkg is None:
                continue
            pinned = ("==" in pkg) if base == "uvx" else bool(re.search(r".@\d+\.\d+\.\d+", pkg))
            if not pinned or pkg.endswith("@latest"):
                report.add(BLOCK, "claude", "launcher.unpinned",
                           f"{label} runs unpinned package {pkg!r} via {base}", source)
            else:
                report.add(HOLD, "claude", "launcher.pinned",
                           f"{label} runs registry package {pkg!r}; reviewers always check these", source)
            report.has_launcher = True
        if base == "uv" and i + 1 < len(tokens) and tokens[i + 1] == "run" \
                and "--locked" not in tokens and "--frozen" not in tokens:
            report.add(BLOCK, "claude", "launcher.unpinned",
                       f"{label} uses `uv run` without --locked/--frozen", source)
            report.has_launcher = True


def check_tool_source(report, path, text):
    """Heuristics for MCP server source code shipped in the plugin."""
    defines_tools = re.search(r"@\w*\.tool\b|registerTool\(|server\.tool\(|\"inputSchema\"|inputSchema\s*[:=]", text)
    if not defines_tools:
        return
    r = rel(report.root, path)
    for hint in ("readOnlyHint", "destructiveHint", "openWorldHint"):
        if hint not in text:
            report.add(WARN, "openai", "tools.annotations",
                       f"defines MCP tools but never sets {hint}; OpenAI requires explicit booleans", r)
    for name in re.findall(r"(?:name\s*=\s*|\"name\"\s*:\s*|registerTool\(\s*)[\"']([a-zA-Z0-9_\-]+)[\"']", text):
        if set(re.split(r"[_\-]", name.lower())) & PROMO_TOOL_WORDS:
            report.add(WARN, "openai", "tools.naming", f"tool name {name!r} uses promotional words", r)


TOOL_DEF_RE = re.compile(r"@\w*\.tool\b|registerTool\(|server\.tool\(")


# The default icon location, assembled from parts: the Claude portal holds any
# script that spells out the path of a bundled image (see files.asset-reference).
DEFAULT_ICON_PARTS = (".claude-plugin", "icon" + "." + "png")


def png_size(path):
    """Width and height from a PNG header, or None if it isn't a PNG."""
    with open(path, "rb") as fh:
        head = fh.read(24)
    if head[:8] != b"\x89PNG\r\n\x1a\n" or head[12:16] != b"IHDR":
        return None
    return int.from_bytes(head[16:20], "big"), int.from_bytes(head[20:24], "big")


def check_icon(report, root, manifest):
    """Claude directory: square PNG/JPEG, 512-2048 px, under 2 MB. It becomes the
    listing icon only the first time the plugin is saved or submitted."""
    rel_path = manifest.get("icon") if isinstance(manifest.get("icon"), str) else None
    path = os.path.join(root, rel_path) if rel_path else os.path.join(root, *DEFAULT_ICON_PARTS)
    shown = rel_path or "/".join(DEFAULT_ICON_PARTS)
    if not os.path.isfile(path):
        report.add(WARN, "claude", "icon.missing",
                   "no icon; add a square PNG named 'icon' in .claude-plugin/ (512-2048 px, <2 MB) "
                   "BEFORE the first portal save: the icon can't be changed later")
        return
    ext = os.path.splitext(path)[1].lower()
    if ext not in (".png", ".jpg", ".jpeg"):
        report.add(WARN, "claude", "icon.format", f"icon must be PNG or JPEG, not {ext}", shown)
        return
    if os.path.getsize(path) >= 2 * 1024 * 1024:
        report.add(WARN, "claude", "icon.size", "icon must be under 2 MB", shown)
    dims = png_size(path) if ext == ".png" else None
    if dims:
        w, h = dims
        if w != h or not 512 <= w <= 2048:
            report.add(WARN, "claude", "icon.dimensions",
                       f"icon is {w}x{h}; needs to be square, 512-2048 px", shown)


CREDENTIAL_FILE_RE = re.compile(r"(?<![\w.])\.(?:npmrc|yarnrc(?:\.yml)?|netrc|pypirc)\b|\.aws/credentials|\bid_rsa\b")
REMOTE_HOST_RE = re.compile(r"\b(?:https?|wss?)://(?:[a-z0-9-]+(?:\.[a-z0-9-]+)+)?", re.I)


def check_credential_and_url(report, script_texts):
    """Claude portal: a script that names a credential file (.npmrc, .netrc...) and
    also spells a remote URL host reads as 'credential could leave the machine'
    and is held for a reviewer, even when the two are unrelated."""
    for r, text in script_texts.items():
        if r.endswith(".md"):
            continue
        cred, host = CREDENTIAL_FILE_RE.search(text), REMOTE_HOST_RE.search(text)
        if cred and host:
            report.add(HOLD, "claude", "files.credential-and-url",
                       f"names credential file {cred.group(0)} and remote host {host.group(0)}; "
                       "a reviewer checks the credential can't be sent there", r)


SCRIPT_EXT = {".py", ".sh", ".bash", ".zsh", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl"}


def check_asset_references(report, assets, script_texts):
    """Claude portal: a script, hook, MCP config, or a backticked path in a skill or
    command that names a bundled image or font is held, because images aren't read
    as code and something could execute their bytes. The README is exempt."""
    for asset in assets:
        names = {asset, asset.replace(os.sep, "/")}
        for r, text in script_texts.items():
            if r.endswith(".md"):
                hit = any(re.search(r"`[^`]*" + re.escape(n) + r"[^`]*`", text) for n in names)
            else:
                hit = any(n in text for n in names)
            if hit:
                report.add(HOLD, "claude", "files.asset-reference",
                           f"names bundled image/font {asset}; reviewers hold this because an "
                           "image could be run as code. Build the path from parts or drop it", r)


def looks_like_mcp_server(root):
    for path, _ in walk(root):
        if path.endswith((".py", ".ts", ".js", ".mjs")) and os.path.getsize(path) < 512 * 1024:
            try:
                with open(path, encoding="utf-8") as fh:
                    if TOOL_DEF_RE.search(fh.read()):
                        return True
            except (UnicodeDecodeError, OSError):
                continue
    return False


def run(root):
    report = Report(root)
    report.has_launcher = False
    claude_manifest_path = os.path.join(root, ".claude-plugin", "plugin.json")
    portable_manifest_path = os.path.join(root, "plugin.json")
    codex_manifest_path = os.path.join(root, ".codex-plugin", "plugin.json")

    skills_dir = os.path.join(root, "skills")
    skill_files = []
    if os.path.isdir(skills_dir):
        for d in sorted(os.listdir(skills_dir)):
            p = os.path.join(skills_dir, d, "SKILL.md")
            if os.path.isfile(p):
                skill_files.append(p)

    manifest = {}
    if os.path.isfile(claude_manifest_path):
        manifest = load_json(claude_manifest_path, report, "claude", "manifest.json") or {}
    elif skill_files:
        report.add(NOTE, "claude", "manifest.missing",
                   "no .claude-plugin/plugin.json; skills-only folder is listed for Claude Code only")
    elif os.path.isfile(os.path.join(root, ".claude-plugin", "marketplace.json")):
        market = load_json(os.path.join(root, ".claude-plugin", "marketplace.json"),
                           report, "claude", "marketplace.json") or {}
        sources = [p.get("source") for p in market.get("plugins", []) if isinstance(p, dict)]
        local = [src for src in sources if isinstance(src, str)]
        report.add(BLOCK, "claude", "marketplace.pick-one",
                   "this is a marketplace repo; run dualship on each plugin folder"
                   + (f": {', '.join(local[:5])}" if local else ""))
        return report
    elif looks_like_mcp_server(root):
        report.add(NOTE, "both", "connector.path",
                   "standalone MCP server: submit its public URL as a connector (Claude) or "
                   "'With MCP' (OpenAI); plugin-bundle manifest checks don't apply")
    else:
        report.add(BLOCK, "claude", "manifest.missing",
                   "no .claude-plugin/plugin.json and no skills/<name>/SKILL.md")

    portable = None
    if os.path.isfile(portable_manifest_path):
        portable = load_json(portable_manifest_path, report, "openai", "portable.json")
    elif os.path.isfile(codex_manifest_path):
        portable = load_json(codex_manifest_path, report, "openai", "portable.json")
        report.add(NOTE, "openai", "portable.legacy",
                   ".codex-plugin/plugin.json is the legacy format; root plugin.json is preferred")
    else:
        report.add(NOTE, "openai", "portable.missing",
                   "no root plugin.json (Agent Plugins format); OpenAI's importer generates one "
                   "from .claude-plugin/plugin.json, review it before submitting")

    author = manifest.get("author")
    author_name = author.get("name") if isinstance(author, dict) else author
    if manifest:
        check_name(report, manifest.get("name"), manifest.get("displayName"), author_name)
        for field in ("description", "author", "version"):
            if not manifest.get(field):
                report.add(WARN, "claude", f"manifest.{field}", f"plugin.json has no `{field}`")
        check_text_for_promo(report, "plugin.json description", manifest.get("description"),
                             ".claude-plugin/plugin.json")
        if "experimental" in manifest and isinstance(manifest["experimental"], dict):
            for key in ("hooks", "mcpServers", "skills", "commands", "agents"):
                if key in manifest["experimental"]:
                    report.add(BLOCK, "claude", "manifest.experimental",
                               f"component key {key!r} is inside `experimental`")
        for key in ("commands", "agents", "skills", "hooks", "mcpServers", "outputStyles", "lspServers"):
            val = manifest.get(key)
            paths = val if isinstance(val, list) else [val] if isinstance(val, str) else []
            for p in paths:
                full = os.path.normpath(os.path.join(root, p))
                if not full.startswith(os.path.normpath(root)):
                    report.add(BLOCK, "claude", "manifest.path", f"{key} path {p!r} points outside the plugin")
                elif not p.startswith("./"):
                    report.add(WARN, "claude", "manifest.path", f"{key} path {p!r} should start with ./")
        if isinstance(manifest.get("mcpServers"), dict):
            check_mcp_servers(report, manifest["mcpServers"], ".claude-plugin/plugin.json")
        if manifest.get("userConfig"):
            report.add(WARN, "openai", "userconfig",
                       "userConfig values are dropped by OpenAI; replace with OAuth or explicit inputs")

    if isinstance(portable, dict):
        iface = (portable.get("extensions", {}).get("com.openai", {}) or {}).get("interface", {}) \
            if isinstance(portable.get("extensions"), dict) else portable.get("interface", {})
        for label in ("shortDescription", "longDescription", "displayName"):
            check_text_for_promo(report, f"interface.{label}", (iface or {}).get(label), "plugin.json")
        check_text_for_promo(report, "plugin.json description", portable.get("description"), "plugin.json")
        if manifest and portable.get("name") and manifest.get("name") and portable["name"] != manifest["name"]:
            report.add(WARN, "both", "manifest.name-mismatch",
                       f"root plugin.json name {portable['name']!r} != Claude name {manifest['name']!r}")
        for key in ("privacyPolicyURL", "websiteURL"):
            container = (portable.get("extensions", {}) or {}).get("com.openai", {}) \
                if isinstance(portable.get("extensions"), dict) else {}
            if not container.get(key) and not portable.get(key):
                report.add(WARN, "openai", f"listing.{key}",
                           f"no {key}; OpenAI requires a published privacy policy and support contact")

    # README / LICENSE
    readme = next((os.path.join(root, n) for n in ("README.md", "README", "readme.md")
                   if os.path.isfile(os.path.join(root, n))), None)
    if not readme:
        report.add(BLOCK, "claude", "readme.missing", "no README in the plugin folder")
    else:
        with open(readme, encoding="utf-8", errors="replace") as fh:
            words = readme_word_count(fh.read())
        if words < 40:
            report.add(BLOCK, "claude", "readme.short", f"README has {words} words outside code blocks (min 40)")
    has_license_file = any(os.path.isfile(os.path.join(root, n))
                           for n in ("LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING"))
    if not has_license_file and not manifest.get("license"):
        report.add(BLOCK, "claude", "license.missing", "no LICENSE file and no `license` in plugin.json")

    if manifest:
        check_icon(report, root, manifest)

    # .mcp.json
    mcp_path = os.path.join(root, ".mcp.json")
    if os.path.isfile(mcp_path):
        data = load_json(mcp_path, report, "claude", "mcp.json")
        if isinstance(data, dict):
            check_mcp_servers(report, data.get("mcpServers", data), ".mcp.json")
        report.add(NOTE, "openai", "mcp.json-dropped",
                   ".mcp.json is dropped on OpenAI import; submit the remote endpoint in the portal instead")

    # hooks
    hooks_path = os.path.join(root, "hooks", "hooks.json")
    if os.path.isfile(hooks_path):
        data = load_json(hooks_path, report, "claude", "hooks.json")
        if isinstance(data, dict):
            if not isinstance(data.get("hooks"), dict):
                report.add(BLOCK, "claude", "hooks.json", "hooks.json needs a top-level `hooks` object")
            else:
                for event, entries in data["hooks"].items():
                    for entry in entries or []:
                        for h in (entry.get("hooks") or []) if isinstance(entry, dict) else []:
                            if h.get("type") == "command":
                                check_launcher(report, str(h.get("command", "")), "hooks/hooks.json",
                                               f"{event} hook")
                            if h.get("type") == "http" and not is_secure_url(str(h.get("url", "")), ("https",)):
                                report.add(BLOCK, "claude", "hooks.http", f"{event} HTTP hook URL is not https")
        report.add(NOTE, "openai", "hooks.codex-only",
                   "hooks only run in ChatGPT Work / Codex, not in ChatGPT chat")

    # commands / agents
    for comp in ("commands", "agents"):
        d = os.path.join(root, comp)
        if os.path.isdir(d) and any(f.endswith(".md") for f in os.listdir(d)):
            report.add(WARN, "openai", f"{comp}.convert",
                       f"{comp}/ is not imported by OpenAI; convert each to a skill")
            for f in sorted(os.listdir(d)):
                if f.endswith(".md"):
                    check_md_component(report, os.path.join(d, f))

    # skills
    for p in skill_files:
        check_md_component(report, p)
        with open(p, encoding="utf-8", errors="replace") as fh:
            body = fh.read()
        m = CLAUDE_SPECIFIC_RE.search(body)
        if m:
            report.add(WARN, "openai", "skills.neutral-language",
                       f"mentions {m.group(0)!r}; OpenAI asks for neutral wording like 'the model'",
                       rel(root, p))

    # files
    file_count = 0
    assets = []        # bundled images and fonts, relative paths
    script_texts = {}  # relative path -> text, for files that run or configure things
    for path, is_dir_link in walk(root):
        r = rel(root, path)
        base = os.path.basename(path)
        if is_dir_link or os.path.islink(path):
            report.add(BLOCK, "claude", "files.symlink", "symbolic link; commit regular files", r)
            continue
        file_count += 1
        if base in JUNK_FILES or "__MACOSX" in r.split(os.sep):
            report.add(BLOCK, "claude", "files.junk", "macOS/Windows system file", r)
        if base in PKG_SOURCE_FILES:
            report.pkg_source = r
        ext = os.path.splitext(base)[1].lower()
        size = os.path.getsize(path)
        if size > 5 * 1024 * 1024:
            report.add(BLOCK, "claude", "files.too-large", f"{size // 1024} KiB file (max 5 MiB)", r)
        elif ext not in IMAGE_FONT_EXT and size > 256 * 1024:
            report.add(HOLD, "claude", "files.large", f"{size // 1024} KiB non-image file (>256 KiB)", r)
        if ext in HELD_BINARY_EXT:
            report.add(HOLD, "claude", "files.binary", f"binary file type {ext} is held for review", r)
            continue
        if ext in IMAGE_FONT_EXT:
            assets.append(r)
            continue
        if size > 2 * 1024 * 1024:
            continue
        try:
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
        except (UnicodeDecodeError, OSError):
            report.add(HOLD, "claude", "files.binary", "binary file the validator can't inspect", r)
            continue
        for label, pat in SECRET_PATTERNS:
            if pat.search(text):
                report.add(BLOCK, "both", "files.secret", f"looks like a real {label}", r)
        m = ENV_CRED_RE.search(text)
        if m and base not in (".mcp.json", "hooks.json") and r != os.path.join(".claude-plugin", "plugin.json"):
            report.add(HOLD, "claude", "files.env-credential",
                       f"references env var {m.group(1)}; the portal holds any file that reads a "
                       "credential from the user's machine, even examples and tests", r)
        if ext in (".py", ".ts", ".js", ".mjs"):
            check_tool_source(report, path, text)
        if ext in SCRIPT_EXT or base in ("hooks.json", ".mcp.json") or \
                (ext == ".md" and base.lower() != "readme.md"):
            script_texts[r] = text
    check_asset_references(report, assets, script_texts)
    check_credential_and_url(report, script_texts)
    if file_count > 512:
        report.add(HOLD, "claude", "files.count", f"{file_count} files (max 512 before review hold)")
    if getattr(report, "pkg_source", None) and report.has_launcher:
        report.add(BLOCK, "claude", "launcher.registry",
                   "package-manager source config next to a launcher", report.pkg_source)
    return report


def check_md_component(report, path):
    r = rel(report.root, path)
    with open(path, encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    fm, err = parse_frontmatter(text)
    if err == "no front matter":
        report.add(WARN, "claude", "frontmatter.missing", "no front matter", r)
        return
    if err:
        report.add(BLOCK, "claude", "frontmatter.parse", err, r)
        return
    desc = fm.get("description")
    if desc is None or desc == "":
        report.add(WARN, "claude", "frontmatter.description", "no `description`", r)
    elif not isinstance(desc, str):
        report.add(BLOCK, "claude", "frontmatter.description", "`description` must be text, not a list", r)


def render(report, targets):
    rows = [f for f in report.findings if f["target"] in targets or f["target"] == "both"]
    rows.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["target"], f["rule"]))
    if not rows:
        return "dualship: no findings"
    width = max(len(f["rule"]) for f in rows)
    lines = []
    for f in rows:
        where = f" ({f['path']})" if f["path"] else ""
        lines.append(f"{f['severity']:<5} {f['target']:<6} {f['rule']:<{width}}  {f['message']}{where}")
    counts = {s: sum(1 for f in rows if f["severity"] == s) for s in SEVERITY_ORDER}
    lines.append("")
    lines.append("summary: " + ", ".join(f"{counts[s]} {s.lower()}" for s in SEVERITY_ORDER))
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("path")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--target", choices=("claude", "openai", "both"), default="both")
    args = ap.parse_args(argv)
    root = os.path.abspath(args.path)
    if not os.path.isdir(root):
        print(f"dualship: not a directory: {args.path}", file=sys.stderr)
        return 2
    targets = {"claude", "openai", "both"} if args.target == "both" else {args.target, "both"}
    report = run(root)
    if args.json:
        print(json.dumps([f for f in report.findings if f["target"] in targets], indent=2))
    else:
        print(render(report, targets))
    return 1 if report.blocking(targets) else 0


if __name__ == "__main__":
    sys.exit(main())
