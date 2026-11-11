"""Team features: settings file, SARIF, the pull request summary, audits."""

import json

import pytest

from pushwatch.audit import audit_repo
from pushwatch.cli import main
from pushwatch.config import Allow, Config, ConfigError, parse
from pushwatch.gitio import FileChange
from pushwatch.config import rule_config_change
from pushwatch.rules import Finding

from tests.test_git import CFG, PAYLOAD, git, write


@pytest.fixture
def repo(tmp_path):
    git(tmp_path, "init", "-q", "-b", "main")
    write(tmp_path, "postcss.config.mjs", CFG)
    write(tmp_path, "package.json", '{"scripts":{"build":"vite build"}}')
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-qm", "init")
    return tmp_path


HUSKY = '{"scripts":{"build":"vite build","prepare":"husky","postinstall":"node -e \\"console.log(1)\\""}}'
ALLOW_HOOK = 'fail_on = "high"\n[[allow]]\nrule = "install-hook"\npath = "package.json"\nreason = "reviewed: husky and a build step"\n'


def test_parse_requires_a_reason():
    with pytest.raises(ConfigError, match="needs a reason"):
        parse('[[allow]]\nrule = "install-hook"\n')
    with pytest.raises(ConfigError, match="fail_on"):
        parse('fail_on = "never"\n')


def test_allow_matches_rule_and_glob():
    cfg = Config(allow=[Allow("install-hook", "packages/*/package.json", "ok")])
    f1 = Finding("install-hook", "high", "packages/web/package.json", None, "t", "e")
    f2 = Finding("install-hook", "high", "package.json", None, "t", "e")
    kept, allowed = cfg.filter([f1, f2])
    assert kept == [f2] and allowed[0][0] is f1


def test_allowlist_from_the_base_applies(repo):
    write(repo, ".pushwatch.toml", ALLOW_HOOK)
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "settings")
    base = git(repo, "rev-parse", "HEAD")
    write(repo, "package.json", HUSKY)
    git(repo, "commit", "-qam", "add hooks")
    assert main(["--repo", str(repo), "push", "--before", base, "--after", "HEAD"]) == 0


def test_a_push_cannot_bring_its_own_allowlist(repo):
    base = git(repo, "rev-parse", "HEAD")
    write(repo, ".pushwatch.toml", ALLOW_HOOK)       # the attacker adds an exception...
    write(repo, "package.json", HUSKY)               # ...in the same push as the hook
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "chore")
    assert main(["--repo", str(repo), "push", "--before", base, "--after", "HEAD"]) == 1


def test_loosening_settings_is_reported():
    old = FileChange(".pushwatch.toml", "M", old=b'fail_on = "medium"\n', new=ALLOW_HOOK.encode())
    f = rule_config_change(old)
    assert f and f[0].rule == "config-change"
    assert "allows install-hook" in f[0].evidence and "medium to high" in f[0].evidence


def test_sarif_and_summary_files(repo, tmp_path_factory):
    base = git(repo, "rev-parse", "HEAD")
    write(repo, "postcss.config.mjs", CFG.replace("export default config;", PAYLOAD))
    git(repo, "commit", "-qam", "Update README.md")
    out = tmp_path_factory.mktemp("out")
    sarif, md = out / "r.sarif", out / "r.md"
    rc = main(["--repo", str(repo), "--sarif", str(sarif), "--summary-file", str(md), "push", "--before", base, "--after", "HEAD"])
    assert rc == 1
    doc = json.loads(sarif.read_text())
    assert doc["version"] == "2.1.0"
    res = doc["runs"][0]["results"]
    assert {r["ruleId"] for r in res} >= {"config-injection"}
    assert all(r["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1 for r in res)
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    assert all("security-severity" in r["properties"] for r in rules)
    text = md.read_text()
    assert text.startswith("<!-- pushwatch -->") and "blocked" in text and "config-injection" in text


def test_fail_on_from_settings(repo):
    write(repo, ".pushwatch.toml", 'fail_on = "medium"\n')
    write(repo, ".gitignore", ".env\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "settings")
    base = git(repo, "rev-parse", "HEAD")
    write(repo, ".gitignore", "node_modules\n")  # medium: stops ignoring .env
    git(repo, "commit", "-qam", "tidy")
    assert main(["--repo", str(repo), "push", "--before", base, "--after", "HEAD"]) == 1
    assert main(["--repo", str(repo), "--fail-on", "high", "push", "--before", base, "--after", "HEAD"]) == 0


def test_audit_finds_a_live_payload_on_a_side_branch(repo):
    git(repo, "checkout", "-qb", "feature/rating")
    write(repo, "postcss.config.mjs", CFG.replace("export default config;", PAYLOAD))
    git(repo, "commit", "-qam", "rating screen")
    git(repo, "checkout", "-q", "main")
    ra = audit_repo(repo / ".git", "demo", history=True)
    assert ra.branches == 2
    assert list(ra.live) == ["feature/rating"] and ra.live_high >= 1
    assert len(ra.history) == 1 and ra.history[0]["subject"] == "rating screen"
