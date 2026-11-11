"""Audit every repository of a GitHub user or organization.

    pushwatch audit --owner my-org [--history] [--cache ~/.cache/pushwatch]

For each repository (forks and archived repos skipped unless asked) it keeps a bare,
blob-filtered mirror in the cache, then scans:
  - the tip of every branch as a snapshot: anything there is live and would run on checkout or build;
  - with --history, every commit on every branch: when a payload arrived and whether it was cleaned up.

Uses the `gh` CLI for the repository list and git for cloning, so it sees exactly
what the signed-in account can see. Nothing is checked out or executed.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from pushwatch.gitio import Repo
from pushwatch.rules import HIGH, RANK, Finding
from pushwatch.scan import scan_commit, scan_tree


@dataclass
class RepoAudit:
    name: str
    branches: int = 0
    commits: int = 0
    live: dict[str, list[Finding]] = field(default_factory=dict)  # branch -> findings at its tip
    history: list[dict] = field(default_factory=list)              # commits that ever added a high finding
    error: str | None = None

    @property
    def live_high(self) -> int:
        return sum(1 for fs in self.live.values() for f in fs if f.severity == HIGH)

    def as_dict(self) -> dict:
        return {"name": self.name, "branches": self.branches, "commits": self.commits, "error": self.error,
                "live": {b: [f.as_dict() for f in fs] for b, fs in self.live.items()}, "history": self.history}


def list_repos(owner: str, forks: bool = False, archived: bool = False) -> list[dict]:
    out = subprocess.run(["gh", "repo", "list", owner, "--limit", "1000", "--json", "name,isFork,isArchived,url"],
                         check=True, capture_output=True, text=True).stdout
    return [r for r in json.loads(out) if (forks or not r["isFork"]) and (archived or not r["isArchived"])]


def mirror(url: str, dest: Path, history: bool = False) -> Path:
    """Bare mirror; without history only each branch tip is fetched (much smaller)."""
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    depth = [] if history else ["--depth", "1"]
    if dest.exists():
        unshallow = ["--unshallow"] if history and (dest / "shallow").exists() else []
        subprocess.run(["git", "-C", str(dest), "fetch", "-q", "--prune", *depth, *unshallow, "origin", "+refs/heads/*:refs/heads/*"],
                       check=True, capture_output=True, env=env)
    else:
        dest.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "clone", "-q", "--bare", "--filter=blob:limit=2m", *depth, "--no-single-branch", url, str(dest)],
                       check=True, capture_output=True, env=env)
    return dest


def audit_repo(path: Path, name: str, history: bool = False) -> RepoAudit:
    ra = RepoAudit(name)
    with Repo(path) as repo:
        branches = [b for b in repo.git("for-each-ref", "--format=%(refname:short)", "refs/heads").split() if b]
        ra.branches = len(branches)
        for b in branches:
            fs = [f for f in scan_tree(repo, b) if RANK[f.severity] >= RANK["medium"]]
            if fs:
                ra.live[b] = fs
        if history:
            shas = repo.rev_list("", all_refs=True)
            ra.commits = len(shas)
            for s in shas:
                r = scan_commit(repo, s)
                if r.worst == HIGH:
                    ra.history.append({"sha": r.sha, "date": r.date[:10], "subject": r.subject[:80],
                                       "rules": sorted({f.rule for f in r.findings if f.severity == HIGH})})
    return ra


def audit_owner(owner: str, cache: Path | None, history: bool = False, forks: bool = False, archived: bool = False,
                progress=print) -> tuple[list[RepoAudit], float]:
    """cache=None: download each repository to a temporary folder and delete it after scanning."""
    started = time.time()
    results = []
    for r in list_repos(owner, forks, archived):
        tmp = None if cache else Path(tempfile.mkdtemp(prefix="pushwatch-"))
        try:
            path = mirror(r["url"] + ".git", (cache / owner if cache else tmp) / f"{r['name']}.git", history)
            results.append(audit_repo(path, r["name"], history))
        except subprocess.CalledProcessError as exc:
            results.append(RepoAudit(r["name"], error=(exc.stderr or b"").decode(errors="replace").strip()[:200] or str(exc)))
        finally:
            if tmp:
                shutil.rmtree(tmp, ignore_errors=True)
        a = results[-1]
        progress(f"  {a.name:40} {'error' if a.error else f'{a.branches} branches'}"
                 f"{'' if a.error else f', {a.live_high} live high' + (f', {len(a.history)} infected commits in history' if history else '')}")
    return results, time.time() - started
