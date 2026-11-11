"""End-to-end on throwaway git repos: force-push rewrites, evil merges, the CLI."""

import os
import subprocess

import pytest

from pushwatch.cli import main
from pushwatch.gitio import Repo
from pushwatch.scan import scan_commit, scan_push, scan_range, scan_tree

ENV = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
       "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com", "GIT_CONFIG_GLOBAL": "/dev/null"}
PAYLOAD = "export default config;" + "\t" * 300 + "global.i='A8-0000';console.log(1);"
CFG = "const config = {};\nexport default config;\n"


def git(repo, *args, env=None):
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True,
                          env={**ENV, **(env or {})}).stdout.strip()


def write(repo, path, text):
    p = repo / path
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


@pytest.fixture
def repo(tmp_path):
    git(tmp_path, "init", "-q", "-b", "main")
    write(tmp_path, "postcss.config.mjs", CFG)
    write(tmp_path, "README.md", "hi\n")
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-qm", "init")
    return tmp_path


def test_force_push_that_keeps_message_and_date_is_caught(repo):
    write(repo, "README.md", "hi there\n")
    git(repo, "commit", "-qam", "Update README.md")
    before = git(repo, "rev-parse", "HEAD")
    date = git(repo, "show", "-s", "--format=%aI", "HEAD")
    # the attacker amends the same commit, keeping its message and author date
    write(repo, "postcss.config.mjs", CFG.replace("export default config;", PAYLOAD))
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "--amend", "--no-edit", env={"GIT_AUTHOR_DATE": date})
    after = git(repo, "rev-parse", "HEAD")
    with Repo(repo) as r:
        rep = scan_push(r, before, after)
    assert rep.forced
    assert rep.rewritten and rep.rewritten[0]["replaced"] == before
    assert any("postcss.config.mjs" in line for line in rep.rewritten[0]["files_changed"])
    assert rep.worst == "high"
    notes = rep.commits[0].notes
    assert any("Update README.md" in n for n in notes)


def test_evil_merge_is_compared_with_first_parent(repo):
    git(repo, "checkout", "-qb", "feature")
    write(repo, "a.txt", "feature\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "feature work")
    git(repo, "checkout", "-q", "main")
    git(repo, "merge", "-q", "--no-ff", "--no-commit", "feature")
    write(repo, "postcss.config.mjs", CFG.replace("export default config;", PAYLOAD))  # added only in the merge
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "Merge pull request #2 from someone/fix")
    with Repo(repo) as r:
        rep = scan_commit(r, "HEAD")
    assert rep.is_merge and rep.worst == "high"
    assert any("merge commit" in n for n in rep.notes)


def test_range_tree_and_cli_exit_codes(repo, capsys):
    clean = git(repo, "rev-parse", "HEAD")
    write(repo, "postcss.config.mjs", CFG.replace("export default config;", PAYLOAD))
    git(repo, "commit", "-qam", "Revise README")
    with Repo(repo) as r:
        assert [x.worst for x in scan_range(r, "HEAD")] == ["high", None]
        assert {f.rule for f in scan_tree(r)} >= {"config-injection"}
    assert main(["--repo", str(repo), "commit", clean]) == 0
    assert main(["--repo", str(repo), "commit", "HEAD"]) == 1
    assert main(["--repo", str(repo), "range", "HEAD"]) == 1
    assert main(["--repo", str(repo), "push", "--before", clean, "--after", "HEAD"]) == 1
    out = capsys.readouterr().out
    assert "config-injection" in out and "Revise README" in out


def test_github_mode_annotates_and_writes_summary(repo, tmp_path_factory, monkeypatch, capsys):
    before = git(repo, "rev-parse", "HEAD")
    write(repo, ".vscode/tasks.json", '{"tasks":[{"label":"x","command":"node","args":["a.ttf"],"runOptions":{"runOn":"folderOpen"}}]}')
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "chore")
    after = git(repo, "rev-parse", "HEAD")
    d = tmp_path_factory.mktemp("gh")
    event, summary = d / "event.json", d / "summary.md"
    event.write_text(f'{{"before":"{before}","after":"{after}","forced":false}}')
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))
    monkeypatch.setenv("GITHUB_EVENT_NAME", "push")
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    assert main(["--repo", str(repo), "github"]) == 1
    out = capsys.readouterr().out
    assert "::error file=.vscode/tasks.json" in out
    assert "vscode-autorun" in summary.read_text()


def test_clean_push_passes(repo):
    before = git(repo, "rev-parse", "HEAD")
    write(repo, "postcss.config.mjs", CFG.replace("{}", "{ plugins: {} }"))
    git(repo, "commit", "-qam", "tweak config")
    assert main(["--repo", str(repo), "push", "--before", before, "--after", "HEAD"]) == 0
