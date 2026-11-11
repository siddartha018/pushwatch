"""Scan commits, ranges, pushes and snapshots."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from pushwatch.config import rule_config_change
from pushwatch.gitio import Commit, Repo
from pushwatch.rules import HIGH, MEDIUM, RANK, Finding, scan_change

DOCS_MSG = re.compile(r"\b(readme|docs?|typo|comment|changelog|license)\b", re.I)


@dataclass
class CommitReport:
    sha: str
    subject: str
    author: str
    date: str
    is_merge: bool
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    allowed: list[tuple[Finding, object]] = field(default_factory=list)  # (finding, Allow) suppressed by settings

    @property
    def worst(self) -> str | None:
        return max((f.severity for f in self.findings), key=RANK.get, default=None)

    def as_dict(self) -> dict:
        return {"sha": self.sha, "subject": self.subject, "author": self.author, "date": self.date,
                "is_merge": self.is_merge, "worst": self.worst, "notes": self.notes,
                "skipped": self.skipped, "findings": [f.as_dict() for f in self.findings],
                "allowed": [{**f.as_dict(), "reason": getattr(a, "reason", "")} for f, a in self.allowed]}


def scan_commit(repo: Repo, sha: str) -> CommitReport:
    c: Commit = repo.commit(sha)
    rep = CommitReport(c.sha, c.subject, c.author, c.author_date, c.is_merge)
    for fc in c.changes:
        if fc.skipped:
            rep.skipped.append(f"{fc.path}: {fc.skipped}")
        rep.findings.extend(scan_change(fc))
        rep.findings.extend(rule_config_change(fc))
    if rep.worst == HIGH:
        flagged = {f.path for f in rep.findings if f.severity == HIGH}
        if DOCS_MSG.search(c.subject) and not any(p.lower().endswith((".md", ".txt", ".rst")) for p in flagged):
            rep.notes.append(f"The message says '{c.subject}', but the risky change is in {', '.join(sorted(flagged))}.")
        if c.is_merge:
            rep.notes.append("This is a merge commit: the change was compared with its first parent.")
    return rep


def scan_range(repo: Repo, spec: str | None = None, all_refs: bool = False) -> list[CommitReport]:
    return [scan_commit(repo, s) for s in repo.rev_list(spec or "HEAD", all_refs=all_refs)]


@dataclass
class PushReport:
    before: str
    after: str
    forced: bool
    rewritten: list[dict] = field(default_factory=list)
    commits: list[CommitReport] = field(default_factory=list)

    @property
    def worst(self) -> str | None:
        sev = [c.worst for c in self.commits if c.worst] + ([HIGH] if self.rewritten else [])
        return max(sev, key=RANK.get, default=None)

    def rewritten_findings(self) -> list[Finding]:
        out = []
        for r in self.rewritten:
            for line in r["files_changed"][:20] or ["?"]:
                path = line.split("\t")[-1]
                out.append(Finding("rewritten-history", HIGH, path, None,
                                   "A force-push replaced a commit with a look-alike that changed this file",
                                   f"{r['replaced'][:10]} -> {r['by'][:10]} '{r['subject']}'"))
        return out

    def all_findings(self) -> list[Finding]:
        return self.rewritten_findings() + [f for c in self.commits for f in c.findings]

    def as_dict(self) -> dict:
        return {"before": self.before, "after": self.after, "forced": self.forced, "worst": self.worst,
                "rewritten": self.rewritten, "commits": [c.as_dict() for c in self.commits]}


def scan_push(repo: Repo, before: str, after: str) -> PushReport:
    """What a push changed, including commits a force-push replaced.

    A force-push that swaps a commit for one with the same message and author date
    but different content is how the 2026-11 agentdock injection hid: the history
    looked unchanged unless you compared the trees.
    """
    zero = set(before) == {"0"}
    after = repo.resolve(after)
    if zero:
        return PushReport(before, after, False, commits=scan_range(repo, after))
    before = repo.resolve(before)
    forced = repo.git("merge-base", before, after).strip() != before if before != after else False
    rep = PushReport(before, after, forced)
    new = repo.rev_list(f"{before}..{after}")
    rep.commits = [scan_commit(repo, s) for s in new]
    if forced:
        gone = repo.rev_list(f"{after}..{before}")
        old_meta = {s: repo.commit(s, with_content=False) for s in gone}
        for s in new:
            c = repo.commit(s, with_content=False)
            for o in old_meta.values():
                if o.message == c.message and o.author_date == c.author_date and o.sha != c.sha:
                    paths = repo.git("diff", "--name-status", o.sha, c.sha).strip().splitlines()
                    rep.rewritten.append({
                        "replaced": o.sha, "by": c.sha, "subject": c.subject,
                        "files_changed": paths[:20],
                    })
    return rep


def scan_tree(repo: Repo, ref: str = "HEAD") -> list[Finding]:
    out: list[Finding] = []
    for fc in repo.tree_files(ref):
        out.extend(scan_change(fc))
    return out


def worst_of(findings: list[Finding]) -> str | None:
    return max((f.severity for f in findings), key=RANK.get, default=None)


__all__ = ["CommitReport", "PushReport", "scan_commit", "scan_range", "scan_push", "scan_tree", "worst_of", "HIGH", "MEDIUM"]
