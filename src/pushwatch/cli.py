"""pushwatch command line.

  pushwatch commit <sha>                         one commit
  pushwatch range <a..b | --all>                 a range, or every commit on every branch
  pushwatch push --before SHA --after SHA        what a (force-)push changed
  pushwatch tree [REF]                           a whole snapshot
  pushwatch github                               inside GitHub Actions, reads the event
  pushwatch audit --owner NAME [--history]       every repository of a user or organization

Common options: --repo PATH, --json, --sarif FILE, --summary-file FILE, --fail-on LEVEL,
--config-ref REF (where to read .pushwatch.toml; default: the trusted side of the change).
Exit code 1 when anything at or above the fail level is found.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from pushwatch import __version__
from pushwatch.config import CONFIG_PATH, Config, ConfigError, load
from pushwatch.gitio import Repo
from pushwatch.rules import RANK, Finding
from pushwatch.sarif import to_sarif
from pushwatch.scan import CommitReport, PushReport, scan_commit, scan_push, scan_range, scan_tree, worst_of

SEV_MARK = {"high": "HIGH", "medium": "MED ", "low": "low "}
COMMENT_MARKER = "<!-- pushwatch -->"


# ---------------------------------------------------------------- output ----
def _print_findings(findings: list[Finding], indent: str = "  ") -> None:
    for f in findings:
        where = f"{f.path}:{f.line}" if f.line else f.path
        print(f"{indent}{SEV_MARK[f.severity]} {f.rule:22} {where}")
        print(f"{indent}     {f.title}")
        print(f"{indent}     {f.evidence}")


def _print_commit(r: CommitReport, quiet_clean: bool) -> None:
    if not r.findings and not r.allowed and quiet_clean:
        return
    print(f"{r.sha[:10]}  {r.date[:10]}  {r.subject[:70]}{'  (merge)' if r.is_merge else ''}")
    _print_findings(r.findings)
    for f, a in r.allowed:
        print(f"  allowed {f.rule} in {f.path}: {a.reason}")
    for n in r.notes:
        print(f"  note {n}")


def _annotate(findings: list[Finding]) -> None:
    """GitHub Actions workflow commands, so findings show on the diff."""
    for f in findings:
        level = "error" if f.severity == "high" else "warning"
        loc = f"file={f.path},line={f.line or 1}"  # whole-file findings point at line 1 so they show on the diff
        msg = f"{f.title}: {f.evidence}".replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        print(f"::{level} {loc},title=pushwatch {f.rule}::{msg}")


def _append(path: str | None, text: str) -> None:
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(text + "\n")


def _md_push(rep: PushReport, cfg: Config, threshold: int) -> str:
    worst = rep.worst
    failed = RANK.get(worst or "", 0) >= threshold
    head = "🛑 blocked" if failed else ("⚠️ passed with warnings" if worst else "✅ clean")
    lines = [COMMENT_MARKER, f"## pushwatch: {head}", ""]
    if rep.rewritten:
        lines.append("**History was rewritten by a force-push.** These commits kept their message and date but changed content:")
        for r in rep.rewritten:
            lines.append(f"- `{r['replaced'][:10]}` → `{r['by'][:10]}` {r['subject']}: " + ", ".join(f"`{p}`" for p in r["files_changed"][:8]))
        lines.append("")
    bad = [c for c in rep.commits if c.findings]
    if not bad and not rep.rewritten:
        lines.append(f"No findings in {len(rep.commits)} commit(s).")
    else:
        lines += ["| Severity | Rule | Where | What |", "|---|---|---|---|"]
        for c in bad:
            for f in c.findings:
                where = f"`{f.path}{':' + str(f.line) if f.line else ''}`"
                lines.append(f"| **{f.severity}** | `{f.rule}` | {where} | {f.title}. <sub>{_md_escape(f.evidence)}</sub> |")
        notes = [n for c in bad for n in c.notes]
        if notes:
            lines += [""] + [f"> {n}" for n in notes]
    allowed = [(f, a) for c in rep.commits for f, a in c.allowed]
    if allowed:
        lines += ["", f"<details><summary>{len(allowed)} finding(s) allowed by <code>{cfg.source or CONFIG_PATH}</code></summary>", ""]
        lines += [f"- `{f.rule}` in `{f.path}`: {a.reason}" for f, a in allowed] + ["", "</details>"]
    lines += ["", f"<sub>pushwatch {__version__} · {len(rep.commits)} commit(s) scanned · fails on {_level_name(threshold)} · "
                  f"[what each rule means](https://github.com/siddartha018/pushwatch#what-it-checks)</sub>"]
    return "\n".join(lines)


def _md_escape(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ")[:220]


def _level_name(threshold: int) -> str:
    return next(k for k, v in RANK.items() if v == threshold)


# ---------------------------------------------------------------- config ----
def _apply(cfg: Config, reports: list[CommitReport]) -> None:
    for r in reports:
        r.findings, allowed = cfg.filter(r.findings)
        r.allowed.extend(allowed)


def _threshold(cli_level: str | None, cfg: Config) -> int:
    return RANK[cli_level or cfg.fail_on]


# ------------------------------------------------------------------ main ----
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="pushwatch", description="Catch malicious code in pushes before it runs.")
    ap.add_argument("--version", action="version", version=f"pushwatch {__version__}")
    ap.add_argument("--repo", default=".", help="path to a git repository (bare is fine)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--sarif", help="also write findings as SARIF 2.1.0 to this file (GitHub code scanning)")
    ap.add_argument("--summary-file", help="also write a Markdown report to this file (pull request comment)")
    ap.add_argument("--fail-on", choices=["high", "medium", "low"], help="default: fail_on in .pushwatch.toml, else high")
    ap.add_argument("--config-ref", help=f"git ref to read {CONFIG_PATH} from (default: the trusted side of the change)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("commit"); p.add_argument("sha")
    p = sub.add_parser("range"); p.add_argument("spec", nargs="?", default="HEAD"); p.add_argument("--all", action="store_true")
    p.add_argument("--show-clean", action="store_true")
    p = sub.add_parser("push"); p.add_argument("--before", required=True); p.add_argument("--after", required=True)
    p = sub.add_parser("tree"); p.add_argument("ref", nargs="?", default="HEAD")
    sub.add_parser("github", help="run inside GitHub Actions on a push or pull_request event")
    p = sub.add_parser("audit", help="every repository of a GitHub user or organization (uses the gh CLI)")
    p.add_argument("--owner", required=True); p.add_argument("--history", action="store_true")
    p.add_argument("--forks", action="store_true"); p.add_argument("--archived", action="store_true")
    p.add_argument("--cache", default=str(Path.home() / ".cache" / "pushwatch"))
    a = ap.parse_args(argv)

    if a.cmd == "audit":
        return _audit(a)

    try:
        with Repo(a.repo) as repo:
            return _run(a, repo)
    except ConfigError as exc:
        print(f"pushwatch: {exc}", file=sys.stderr)
        return 2


def _run(a, repo: Repo) -> int:
    if a.cmd == "commit":
        r = scan_commit(repo, a.sha)
        # trusted settings: the commit's parent, never the commit itself
        ref = a.config_ref or (f"{r.sha}^" if _has_parent(repo, r.sha) else None)
        cfg = load(repo, ref)
        _apply(cfg, [r])
        threshold = _threshold(a.fail_on, cfg)
        _write_sarif(a.sarif, r.findings, r.sha)
        if a.json:
            print(json.dumps(r.as_dict(), indent=2))
        else:
            _print_commit(r, quiet_clean=False)
            if not r.findings:
                print("  no findings")
        return int(RANK.get(r.worst or "", 0) >= threshold)

    if a.cmd == "range":
        cfg = load(repo, a.config_ref or "HEAD")
        reps = scan_range(repo, a.spec, all_refs=a.all)
        _apply(cfg, reps)
        threshold = _threshold(a.fail_on, cfg)
        _write_sarif(a.sarif, [f for r in reps for f in r.findings])
        if a.json:
            print(json.dumps([r.as_dict() for r in reps if r.findings or a.show_clean], indent=2))
        else:
            for r in reps:
                _print_commit(r, quiet_clean=not a.show_clean)
            print(f"\n{len(reps)} commits scanned, {sum(1 for r in reps if r.findings)} with findings")
        return int(any(RANK.get(r.worst or "", 0) >= threshold for r in reps))

    if a.cmd == "tree":
        cfg = load(repo, a.config_ref or a.ref)
        fs, _ = cfg.filter(scan_tree(repo, a.ref))
        threshold = _threshold(a.fail_on, cfg)
        _write_sarif(a.sarif, fs)
        if a.json:
            print(json.dumps([f.as_dict() for f in fs], indent=2))
        else:
            _print_findings(fs, indent="")
            print(f"\n{len(fs)} findings at {a.ref}")
        return int(RANK.get(worst_of(fs) or "", 0) >= threshold)

    if a.cmd == "push":
        rep = scan_push(repo, a.before, a.after)
        return _report_push(repo, rep, a, trusted=a.before)

    if a.cmd == "github":
        return _github(repo, a)
    return 2


def _has_parent(repo: Repo, sha: str) -> bool:
    try:
        repo.git("rev-parse", "-q", "--verify", f"{sha}^")
        return True
    except Exception:
        return False


def _write_sarif(path: str | None, findings: list[Finding], commit: str | None = None) -> None:
    if path:
        Path(path).write_text(json.dumps(to_sarif(findings, commit), indent=2))


def _report_push(repo: Repo, rep: PushReport, a, trusted: str | None, annotate: bool = False) -> int:
    cfg = load(repo, a.config_ref or trusted)
    _apply(cfg, rep.commits)
    threshold = _threshold(a.fail_on, cfg)
    _write_sarif(a.sarif, rep.all_findings(), rep.after)
    md = _md_push(rep, cfg, threshold)
    if a.summary_file:
        Path(a.summary_file).write_text(md + "\n")
    if a.json:
        print(json.dumps(rep.as_dict(), indent=2))
    else:
        if rep.rewritten:
            print("HIGH force-push rewrote history: commits kept their message and date but changed content")
            for r in rep.rewritten:
                print(f"     {r['replaced'][:10]} -> {r['by'][:10]}  {r['subject'][:60]}")
                for line in r["files_changed"][:10]:
                    print(f"        {line}")
        for c in rep.commits:
            _print_commit(c, quiet_clean=True)
        print(f"\n{len(rep.commits)} new commit(s){' after a force-push' if rep.forced else ''}, "
              f"{sum(1 for c in rep.commits if c.findings)} with findings"
              + (f" (settings from {cfg.source})" if cfg.source else ""))
    if annotate:
        for c in rep.commits:
            _annotate(c.findings)
        if rep.rewritten:
            print("::error title=pushwatch rewritten-history::A force-push replaced commits with look-alikes that changed content")
        _append(os.environ.get("GITHUB_STEP_SUMMARY"), md)
    return int(RANK.get(rep.worst or "", 0) >= threshold)


def _github(repo: Repo, a) -> int:
    event = json.load(open(os.environ["GITHUB_EVENT_PATH"], encoding="utf-8"))
    name = os.environ.get("GITHUB_EVENT_NAME", "")
    trusted = None
    if name in ("pull_request", "pull_request_target", "merge_group"):
        pr = event.get("pull_request") or {}
        base = pr.get("base", {}).get("sha") or event.get("merge_group", {}).get("base_sha")
        head = pr.get("head", {}).get("sha") or event.get("merge_group", {}).get("head_sha")
        mb = repo.git("merge-base", base, head).strip()
        rep, trusted = scan_push(repo, mb, head), base
    elif name == "push":
        before, after = event.get("before", "0" * 40), event["after"]
        if set(after) == {"0"}:
            print("branch deleted, nothing to scan")
            return 0
        trusted = before
        try:
            rep = scan_push(repo, before, after)
        except Exception as exc:  # the old commit may be gone after a force-push; the action fetches it when it can
            print(f"::warning title=pushwatch::could not compare with {before[:10]} ({exc}); scanning the new head only")
            rep = PushReport(before, after, bool(event.get("forced")), commits=[scan_commit(repo, after)])
            trusted = None
        rep.forced = rep.forced or bool(event.get("forced"))
    else:
        print(f"unsupported event {name!r}; scanning HEAD")
        rep = PushReport("", "HEAD", False, commits=[scan_commit(repo, "HEAD")])
    return _report_push(repo, rep, a, trusted, annotate=True)


def _audit(a) -> int:
    from pushwatch.audit import audit_owner

    print(f"pushwatch audit of {a.owner}{' (with history)' if a.history else ''}")
    results, secs = audit_owner(a.owner, Path(a.cache).expanduser(), a.history, a.forks, a.archived)
    live = [r for r in results if r.live]
    if a.json:
        print(json.dumps({"owner": a.owner, "seconds": round(secs, 1), "repos": [r.as_dict() for r in results]}, indent=2))
    else:
        print(f"\n{len(results)} repositories, {sum(r.branches for r in results)} branches"
              + (f", {sum(r.commits for r in results)} commits" if a.history else "") + f" in {secs:.0f} s")
        errors = [r for r in results if r.error]
        if errors:
            print(f"{len(errors)} could not be read: " + ", ".join(r.name for r in errors))
        if not live:
            print("No live findings at any branch tip.")
        for r in live:
            for b, fs in r.live.items():
                print(f"\n{r.name} [{b}]")
                _print_findings(fs)
        if a.history:
            hist = [(r.name, h) for r in results for h in r.history]
            print(f"\n{len(hist)} commit(s) in history ever added a high finding")
            for n, h in hist:
                print(f"  {n:30} {h['sha'][:10]} {h['date']} {', '.join(h['rules'])}  {h['subject'][:50]}")
    threshold = RANK[a.fail_on or "high"]
    return int(any(RANK[f.severity] >= threshold for r in results for fs in r.live.values() for f in fs))


if __name__ == "__main__":
    sys.exit(main())
