"""pushwatch command line.

  pushwatch commit <sha> [--repo PATH]
  pushwatch range <a..b | --all> [--repo PATH]
  pushwatch push --before SHA --after SHA [--repo PATH]   # what a (force-)push changed
  pushwatch tree [REF] [--repo PATH]                       # a whole snapshot
  pushwatch github                                         # inside GitHub Actions, reads the event

Exit code 1 when anything at or above --fail-on (default: high) is found.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from pushwatch.gitio import Repo
from pushwatch.rules import RANK, Finding
from pushwatch.scan import CommitReport, PushReport, scan_commit, scan_push, scan_range, scan_tree, worst_of

SEV_MARK = {"high": "HIGH", "medium": "MED ", "low": "low "}


def _print_findings(findings: list[Finding], indent: str = "  ") -> None:
    for f in findings:
        where = f"{f.path}:{f.line}" if f.line else f.path
        print(f"{indent}{SEV_MARK[f.severity]} {f.rule:22} {where}")
        print(f"{indent}     {f.title}")
        print(f"{indent}     {f.evidence}")


def _print_commit(r: CommitReport, quiet_clean: bool) -> None:
    if not r.findings and quiet_clean:
        return
    print(f"{r.sha[:10]}  {r.date[:10]}  {r.subject[:70]}{'  (merge)' if r.is_merge else ''}")
    _print_findings(r.findings)
    for n in r.notes:
        print(f"  note {n}")


def _annotate(findings: list[Finding]) -> None:
    """GitHub Actions workflow commands, so findings show on the diff."""
    for f in findings:
        level = "error" if f.severity == "high" else "warning"
        loc = f"file={f.path}" + (f",line={f.line}" if f.line else "")
        msg = f"{f.title}: {f.evidence}".replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        print(f"::{level} {loc},title=pushwatch {f.rule}::{msg}")


def _summary(md: str) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(md + "\n")


def _md_push(rep: PushReport) -> str:
    lines = ["## pushwatch", ""]
    if rep.rewritten:
        lines.append("**History was rewritten by a force-push.** These commits kept their message and date but changed content:")
        for r in rep.rewritten:
            lines.append(f"- `{r['replaced'][:10]}` → `{r['by'][:10]}` {r['subject']}: " + ", ".join(f"`{p}`" for p in r["files_changed"][:8]))
        lines.append("")
    bad = [c for c in rep.commits if c.findings]
    if not bad and not rep.rewritten:
        lines.append(f"No findings in {len(rep.commits)} commit(s).")
    for c in bad:
        lines.append(f"### `{c.sha[:10]}` {c.subject}")
        for f in c.findings:
            lines.append(f"- **{f.severity}** `{f.rule}` `{f.path}{':' + str(f.line) if f.line else ''}`: {f.title}. {f.evidence}")
        lines += [f"- note: {n}" for n in c.notes]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="pushwatch", description="Catch malicious code in pushes before it runs.")
    ap.add_argument("--repo", default=".", help="path to a git repository (bare is fine)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--fail-on", choices=["high", "medium", "low"], default="high")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("commit"); p.add_argument("sha")
    p = sub.add_parser("range"); p.add_argument("spec", nargs="?", default="HEAD"); p.add_argument("--all", action="store_true")
    p.add_argument("--show-clean", action="store_true")
    p = sub.add_parser("push"); p.add_argument("--before", required=True); p.add_argument("--after", required=True)
    p = sub.add_parser("tree"); p.add_argument("ref", nargs="?", default="HEAD")
    sub.add_parser("github", help="run inside GitHub Actions on a push or pull_request event")
    a = ap.parse_args(argv)
    threshold = RANK[a.fail_on]

    with Repo(a.repo) as repo:
        if a.cmd == "commit":
            r = scan_commit(repo, a.sha)
            print(json.dumps(r.as_dict(), indent=2)) if a.json else _print_commit(r, quiet_clean=False)
            if not a.json and not r.findings:
                print("  no findings")
            return int(RANK.get(r.worst or "", 0) >= threshold)

        if a.cmd == "range":
            reps = scan_range(repo, a.spec, all_refs=a.all)
            if a.json:
                print(json.dumps([r.as_dict() for r in reps if r.findings or a.show_clean], indent=2))
            else:
                for r in reps:
                    _print_commit(r, quiet_clean=not a.show_clean)
                n = sum(1 for r in reps if r.findings)
                print(f"\n{len(reps)} commits scanned, {n} with findings")
            return int(any(RANK.get(r.worst or "", 0) >= threshold for r in reps))

        if a.cmd == "tree":
            fs = scan_tree(repo, a.ref)
            if a.json:
                print(json.dumps([f.as_dict() for f in fs], indent=2))
            else:
                _print_findings(fs, indent="")
                print(f"\n{len(fs)} findings at {a.ref}")
            return int(RANK.get(worst_of(fs) or "", 0) >= threshold)

        if a.cmd == "push":
            rep = scan_push(repo, a.before, a.after)
            return _report_push(rep, a.json, threshold)

        if a.cmd == "github":
            return _github(repo, a.json, threshold)
    return 2


def _report_push(rep: PushReport, as_json: bool, threshold: int, annotate: bool = False) -> int:
    if as_json:
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
              f"{sum(1 for c in rep.commits if c.findings)} with findings")
    if annotate:
        for c in rep.commits:
            _annotate(c.findings)
        if rep.rewritten:
            print("::error title=pushwatch rewritten-history::A force-push replaced commits with look-alikes that changed content")
        _summary(_md_push(rep))
    return int(RANK.get(rep.worst or "", 0) >= threshold)


def _github(repo: Repo, as_json: bool, threshold: int) -> int:
    event = json.load(open(os.environ["GITHUB_EVENT_PATH"], encoding="utf-8"))
    name = os.environ.get("GITHUB_EVENT_NAME", "")
    if name == "pull_request" or name == "pull_request_target":
        base, head = event["pull_request"]["base"]["sha"], event["pull_request"]["head"]["sha"]
        mb = repo.git("merge-base", base, head).strip()
        rep = scan_push(repo, mb, head)
    elif name == "push":
        before, after = event.get("before", "0" * 40), event["after"]
        if set(after) == {"0"}:
            print("branch deleted, nothing to scan")
            return 0
        try:
            rep = scan_push(repo, before, after)
        except Exception as exc:  # the old commit may be gone after a force-push; fetch it in the workflow
            print(f"::warning title=pushwatch::could not compare with {before[:10]} ({exc}); scanning the new head only")
            rep = PushReport(before, after, bool(event.get("forced")), commits=[scan_commit(repo, after)])
        rep.forced = rep.forced or bool(event.get("forced"))
    else:
        print(f"unsupported event {name!r}; scanning HEAD")
        rep = PushReport("", "HEAD", False, commits=[scan_commit(repo, "HEAD")])
    return _report_push(rep, as_json, threshold, annotate=True)


if __name__ == "__main__":
    sys.exit(main())
