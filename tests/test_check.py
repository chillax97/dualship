"""Tests for skills/dualship/scripts/check.py.

Fixtures are built in temp dirs so the repo itself never contains the junk
files, secrets, or broken manifests the checker is supposed to flag.
Run: python3 -m unittest discover -s tests -v
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCRIPT = os.path.join(ROOT, "skills", "dualship", "scripts", "check.py")
sys.path.insert(0, os.path.dirname(SCRIPT))
import check  # noqa: E402

GOOD_README = " ".join(["This plugin turns weekly client notes into a tidy report."] * 8)


def write(root, rel, content):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    mode = "wb" if isinstance(content, bytes) else "w"
    with open(path, mode) as fh:
        fh.write(content if isinstance(content, (str, bytes)) else json.dumps(content))
    return path


def read_manifest(root):
    with open(os.path.join(root, ".claude-plugin/plugin.json")) as fh:
        return json.load(fh)


def make_good(root, name="weekly-client-report"):
    write(root, ".claude-plugin/plugin.json", {
        "name": name, "version": "1.0.0", "description": "Turns notes into a weekly client report.",
        "author": {"name": "Ada"}, "license": "MIT"})
    write(root, "README.md", GOOD_README)
    write(root, "skills/report/SKILL.md",
          "---\nname: report\ndescription: Build a weekly client report from notes.\n---\n\nSteps.\n")


def rules(report, severity=None, target=None):
    return {f["rule"] for f in report.findings
            if (severity is None or f["severity"] == severity)
            and (target is None or f["target"] == target)}


class GoodPlugin(unittest.TestCase):
    def test_good_plugin_has_no_blocks(self):
        with tempfile.TemporaryDirectory() as d:
            make_good(d)
            report = check.run(d)
            self.assertEqual(report.blocking({"claude", "openai", "both"}), [])

    def test_repo_plugin_passes_itself(self):
        report = check.run(ROOT)
        self.assertEqual([f for f in report.findings if f["severity"] in ("BLOCK", "HOLD")], [])

    def test_cli_exit_codes(self):
        with tempfile.TemporaryDirectory() as d:
            make_good(d)
            ok = subprocess.run([sys.executable, SCRIPT, d], capture_output=True, text=True)
            self.assertEqual(ok.returncode, 0, ok.stdout)
            os.remove(os.path.join(d, "README.md"))
            bad = subprocess.run([sys.executable, SCRIPT, d], capture_output=True, text=True)
            self.assertEqual(bad.returncode, 1)
            self.assertIn("readme.missing", bad.stdout)
        missing = subprocess.run([sys.executable, SCRIPT, "/nonexistent/x"], capture_output=True, text=True)
        self.assertEqual(missing.returncode, 2)

    def test_json_output_and_target_filter(self):
        with tempfile.TemporaryDirectory() as d:
            make_good(d)
            write(d, "commands/go.md", "---\ndescription: go\n---\nGo.\n")
            out = subprocess.run([sys.executable, SCRIPT, d, "--json", "--target", "claude"],
                                 capture_output=True, text=True)
            data = json.loads(out.stdout)
            self.assertTrue(all(f["target"] in ("claude", "both") for f in data))
            out = subprocess.run([sys.executable, SCRIPT, d, "--json", "--target", "openai"],
                                 capture_output=True, text=True)
            self.assertIn("commands.convert", {f["rule"] for f in json.loads(out.stdout)})


class ClaudeRules(unittest.TestCase):
    def check_with(self, mutate):
        with tempfile.TemporaryDirectory() as d:
            make_good(d)
            mutate(d)
            return check.run(d)

    def test_missing_readme_and_license(self):
        def m(d):
            os.remove(os.path.join(d, "README.md"))
            write(d, ".claude-plugin/plugin.json", {"name": "foo-bar", "version": "1", "description": "x",
                                                    "author": "a"})
        r = self.check_with(m)
        self.assertTrue({"readme.missing", "license.missing"} <= rules(r, "BLOCK"))

    def test_short_readme_ignores_code_blocks(self):
        r = self.check_with(lambda d: write(d, "README.md", "Short.\n```\n" + "word " * 100 + "\n```\n"))
        self.assertIn("readme.short", rules(r, "BLOCK"))

    def test_license_file_satisfies(self):
        def m(d):
            data = read_manifest(d)
            del data["license"]
            write(d, ".claude-plugin/plugin.json", data)
            write(d, "LICENSE", "MIT")
        self.assertNotIn("license.missing", rules(self.check_with(m)))

    def test_reserved_and_generic_names(self):
        with tempfile.TemporaryDirectory() as d:
            make_good(d, name="claude")
            self.assertIn("manifest.name", rules(check.run(d), "BLOCK"))
        with tempfile.TemporaryDirectory() as d:
            make_good(d, name="test-plugin")
            self.assertIn("manifest.name", rules(check.run(d), "HOLD"))
        with tempfile.TemporaryDirectory() as d:
            make_good(d, name="Weekly_Report")
            self.assertIn("manifest.name", rules(check.run(d), "WARN"))
        with tempfile.TemporaryDirectory() as d:
            make_good(d, name="café-report")
            self.assertIn("manifest.name", rules(check.run(d), "BLOCK"))

    def test_junk_files_and_symlinks(self):
        def m(d):
            write(d, ".DS_Store", b"\x00\x01")
            os.symlink(os.path.join(d, "README.md"), os.path.join(d, "link.md"))
        r = self.check_with(m)
        self.assertTrue({"files.junk", "files.symlink"} <= rules(r, "BLOCK"))

    def test_large_and_binary_files_are_held(self):
        def m(d):
            write(d, "data/big.txt", "a" * (300 * 1024))
            write(d, "assets/icon.ico", b"\x00\x00\x01\x00")
        r = self.check_with(m)
        self.assertTrue({"files.large", "files.binary"} <= rules(r, "HOLD"))

    def test_large_image_is_not_held(self):
        r = self.check_with(lambda d: write(d, "assets/shot.png", b"\x89PNG" + b"0" * (300 * 1024)))
        self.assertNotIn("files.large", rules(r))

    def test_unpinned_and_pinned_launchers(self):
        def m(d):
            write(d, ".mcp.json", {"mcpServers": {
                "a": {"command": "npx", "args": ["-y", "some-server"]},
                "b": {"command": "npx", "args": ["-y", "other-server@1.2.3"]},
                "c": {"command": "uvx", "args": ["tool==0.4.1"]},
                "d": {"command": "uvx", "args": ["tool"]},
            }})
        r = self.check_with(m)
        msgs = [f["message"] for f in r.findings if f["rule"] == "launcher.unpinned"]
        self.assertEqual(len(msgs), 2, msgs)
        self.assertEqual(len([f for f in r.findings if f["rule"] == "launcher.pinned"]), 2)
        self.assertIn("mcp.local", rules(r, "WARN", "openai"))

    def test_registry_config_with_launcher_blocks(self):
        def m(d):
            write(d, ".mcp.json", {"mcpServers": {"a": {"command": "npx", "args": ["x@1.0.0"]}}})
            write(d, ".npmrc", "registry=https://evil.example\n")
        self.assertIn("launcher.registry", rules(self.check_with(m), "BLOCK"))

    def test_remote_server_rules(self):
        def m(d):
            write(d, ".mcp.json", {"mcpServers": {
                "plain": {"type": "http", "url": "http://api.example.com/mcp"},
                "envtok": {"type": "http", "url": "https://api.example.com/mcp",
                           "headers": {"Authorization": "Bearer ${GITHUB_TOKEN}"}},
                "ok": {"type": "http", "url": "https://api.example.com/mcp"},
                "cfg": {"type": "http", "url": "${user_config.endpoint}"},
            }})
        r = self.check_with(m)
        https = [f for f in r.findings if f["rule"] == "mcp.https"]
        self.assertEqual(len(https), 1)
        self.assertIn("mcp.env-credential", rules(r, "HOLD"))

    def test_secret_in_file(self):
        r = self.check_with(lambda d: write(d, "notes.md", "key: " + "sk-" + "proj-" + "abcdefghijklmnopqrstuvwxyz123456"))
        self.assertIn("files.secret", rules(r, "BLOCK"))

    def test_broken_hooks_and_frontmatter(self):
        def m(d):
            write(d, "hooks/hooks.json", "{not json")
            write(d, "skills/bad/SKILL.md", "---\nname: bad\ndescription:\n  - a\n  - b\n---\nx\n")
            write(d, "skills/open/SKILL.md", "---\nname: open\ndescription: never closed\n")
        r = self.check_with(m)
        self.assertIn("hooks.json", rules(r, "BLOCK"))
        self.assertIn("frontmatter.description", rules(r, "BLOCK"))
        self.assertIn("frontmatter.parse", rules(r, "BLOCK"))

    def test_hooks_without_hooks_object(self):
        r = self.check_with(lambda d: write(d, "hooks/hooks.json", {"SessionStart": []}))
        self.assertIn("hooks.json", rules(r, "BLOCK"))

    def test_component_path_outside_plugin(self):
        def m(d):
            data = read_manifest(d)
            data["commands"] = "../elsewhere"
            write(d, ".claude-plugin/plugin.json", data)
        self.assertIn("manifest.path", rules(self.check_with(m), "BLOCK"))

    def test_skills_only_folder_is_a_note(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "README.md", GOOD_README)
            write(d, "LICENSE", "MIT")
            write(d, "skills/a/SKILL.md", "---\nname: a\ndescription: does a\n---\n")
            r = check.run(d)
            self.assertIn("manifest.missing", rules(r, "NOTE"))
            self.assertEqual(r.blocking({"claude", "openai", "both"}), [])

    def test_standalone_mcp_server_is_connector_path(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "README.md", GOOD_README)
            write(d, "LICENSE", "MIT")
            write(d, "server.py", "@server.tool(name='get_x', annotations=dict(readOnlyHint=True, "
                                  "destructiveHint=False, openWorldHint=False))\ndef get_x(): ...\n")
            r = check.run(d)
            self.assertIn("connector.path", rules(r, "NOTE"))
            self.assertNotIn("manifest.missing", rules(r))
            self.assertEqual(r.blocking({"claude", "openai", "both"}), [])

    def test_marketplace_repo_asks_to_pick_one(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, ".claude-plugin/marketplace.json",
                  {"name": "m", "owner": {"name": "a"}, "plugins": [{"name": "p", "source": "./plugin"}]})
            r = check.run(d)
            self.assertIn("marketplace.pick-one", rules(r, "BLOCK"))
            self.assertIn("./plugin", r.findings[-1]["message"])

    def test_empty_folder_blocks(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertIn("manifest.missing", rules(check.run(d), "BLOCK"))


class OpenAIRules(unittest.TestCase):
    def check_with(self, mutate):
        with tempfile.TemporaryDirectory() as d:
            make_good(d)
            mutate(d)
            return check.run(d)

    def test_promo_words_in_description_block(self):
        def m(d):
            data = read_manifest(d)
            data["description"] = "The best report tool. Free trial available!"
            write(d, ".claude-plugin/plugin.json", data)
        self.assertIn("metadata.promo", rules(self.check_with(m), "BLOCK", "openai"))

    def test_best_practices_is_not_promo(self):
        r = self.check_with(lambda d: write(
            d, "skills/report/SKILL.md",
            "---\nname: report\ndescription: Apply best practices to weekly reports.\n---\nx\n"))
        self.assertNotIn("metadata.promo", rules(r))

    def test_skill_about_billing_is_not_promo(self):
        r = self.check_with(lambda d: write(
            d, "skills/report/SKILL.md",
            "---\nname: report\ndescription: Update a customer subscription and pricing page.\n---\nx\n"))
        self.assertNotIn("metadata.promo", rules(r))

    def test_soft_billing_words_in_listing_warn(self):
        def m(d):
            data = read_manifest(d)
            data["description"] = "Manage Stripe subscriptions from chat."
            write(d, ".claude-plugin/plugin.json", data)
        r = self.check_with(m)
        self.assertIn("metadata.promo", rules(r, "WARN"))
        self.assertNotIn("metadata.promo", rules(r, "BLOCK"))

    def test_promo_in_portable_interface(self):
        def m(d):
            write(d, "plugin.json", {"name": "weekly-client-report", "extensions": {"com.openai": {
                "interface": {"shortDescription": "Upgrade to Pro, 50% off this week"}}}})
        r = self.check_with(m)
        self.assertIn("metadata.promo", rules(r, "BLOCK"))
        self.assertIn("listing.privacyPolicyURL", rules(r, "WARN"))

    def test_name_suffix_warning(self):
        def m(d):
            data = read_manifest(d)
            data["displayName"] = "Weekly Report MCP"
            write(d, ".claude-plugin/plugin.json", data)
        self.assertIn("metadata.name-suffix", rules(self.check_with(m), "WARN"))

    def test_commands_agents_userconfig_need_conversion(self):
        def m(d):
            write(d, "commands/go.md", "---\ndescription: go\n---\nGo.\n")
            write(d, "agents/helper.md", "---\nname: helper\ndescription: helps\n---\nHelp.\n")
            data = read_manifest(d)
            data["userConfig"] = {"token": {"type": "string", "sensitive": True}}
            write(d, ".claude-plugin/plugin.json", data)
        r = self.check_with(m)
        self.assertTrue({"commands.convert", "agents.convert", "userconfig"} <= rules(r, "WARN", "openai"))

    def test_claude_specific_language(self):
        r = self.check_with(lambda d: write(
            d, "skills/report/SKILL.md",
            "---\nname: report\ndescription: d\n---\nClaude should create an artifact.\n"))
        self.assertIn("skills.neutral-language", rules(r, "WARN"))

    def test_naming_the_claude_directory_is_fine(self):
        r = self.check_with(lambda d: write(
            d, "skills/report/SKILL.md",
            "---\nname: report\ndescription: d\n---\nSubmit to the Claude directory. Build artifacts go in dist/.\n"))
        self.assertNotIn("skills.neutral-language", rules(r))

    def test_tool_annotations_missing(self):
        src = "@mcp.tool(name='best_report')\ndef best_report():\n    pass\n"
        r = self.check_with(lambda d: write(d, "server/main.py", src))
        self.assertIn("tools.annotations", rules(r, "WARN"))
        self.assertIn("tools.naming", rules(r, "WARN"))

    def test_tool_annotations_present(self):
        src = ("@mcp.tool(name='get_report', annotations={'readOnlyHint': True, "
               "'destructiveHint': False, 'openWorldHint': False})\n")
        self.assertNotIn("tools.annotations", rules(self.check_with(lambda d: write(d, "server/main.py", src))))

    def test_name_mismatch_between_manifests(self):
        r = self.check_with(lambda d: write(d, "plugin.json", {"name": "other-name"}))
        self.assertIn("manifest.name-mismatch", rules(r, "WARN"))


if __name__ == "__main__":
    unittest.main()
