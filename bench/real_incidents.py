"""Score pushwatch on real incidents and on clean history.

  uv run python bench/real_incidents.py --corpus DIR --truth truth.tsv [--clean-root ~/me/repos]

DIR holds bare clones named <repo>.git. truth.tsv lists `repo<TAB>sha<TAB>kind`, one
per known malicious commit, labelled independently of pushwatch (by the campaign's
own marker string and by hand). The corpus is live malware, so it is not in this
repository; results are written to bench/results.json.

Every commit reachable from any ref is scanned. A known malicious commit counts as
caught when pushwatch reports at least one high finding on it. Every other commit
with a high finding is a false alarm.
"""

from __future__ import annotations

import argparse
import json
import time
from collections import Counter
from pathlib import Path

from pushwatch.gitio import Repo
from pushwatch.scan import scan_commit


def scan_repo(path: Path, newest: int | None = None) -> list[dict]:
    """Every commit on every ref, or the newest N on HEAD. Shallow-clone boundaries are skipped."""
    out = []
    shallow_file = path / "shallow" if (path / "shallow").exists() else path / ".git" / "shallow"
    boundary = set(shallow_file.read_text().split()) if shallow_file.exists() else set()
    with Repo(path) as repo:
        shas = repo.git("rev-list", "-n", str(newest), "HEAD").split() if newest else repo.rev_list("", all_refs=True)
        for sha in shas:
            if sha in boundary:
                continue
            r = scan_commit(repo, sha)
            out.append({"sha": r.sha, "worst": r.worst, "rules": sorted({f.rule for f in r.findings if f.severity == "high"}),
                        "subject": r.subject[:80], "merge": r.is_merge})
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--truth", required=True)
    ap.add_argument("--clean-root", help="folder of working repos believed clean, scanned for false alarms")
    ap.add_argument("--clean-corpus", help="folder of bare clones of public projects, scanned for false alarms")
    ap.add_argument("--newest", type=int, default=400, help="commits per public project (newest on HEAD)")
    a = ap.parse_args()
    truth: dict[str, set[str]] = {}
    for line in Path(a.truth).read_text().splitlines():
        if line.strip():
            repo, sha, _ = line.split("\t")
            truth.setdefault(repo, set()).add(sha)

    started = time.time()
    caught, missed, false_alarms, commits = [], [], [], 0
    rule_hits: Counter = Counter()
    for repo_dir in sorted(Path(a.corpus).glob("*.git")):
        name = repo_dir.name[:-4]
        rows = scan_repo(repo_dir)
        commits += len(rows)
        bad = truth.get(name, set())
        for row in rows:
            is_bad = any(row["sha"].startswith(b) for b in bad)
            if is_bad:
                (caught if row["worst"] == "high" else missed).append({"repo": name, **row})
                rule_hits.update(row["rules"])
            elif row["worst"] == "high":
                false_alarms.append({"repo": name, **row})
    clean_commits, clean_alarms = 0, []
    if a.clean_root:
        for d in sorted(Path(a.clean_root).expanduser().iterdir()):
            if (d / ".git").exists() and d.name != "pushwatch":
                rows = scan_repo(d)
                clean_commits += len(rows)
                clean_alarms += [{"repo": d.name, **r} for r in rows if r["worst"] == "high"]
    oss_commits, oss_alarms, oss_by_repo = 0, [], {}
    if a.clean_corpus:
        for d in sorted(Path(a.clean_corpus).glob("*.git")):
            rows = scan_repo(d, newest=a.newest)
            oss_by_repo[d.name[:-4]] = len(rows)
            oss_commits += len(rows)
            oss_alarms += [{"repo": d.name[:-4], **r} for r in rows if r["worst"] == "high"]
    clean_commits += oss_commits
    clean_alarms += oss_alarms
    known = sum(len(v) for v in truth.values())
    res = {
        "known_malicious": known,
        "caught": len(caught),
        "missed": missed,
        "incident_repo_commits": commits,
        "false_alarms_in_incident_repos": false_alarms,
        "clean_repo_commits": clean_commits,
        "false_alarms_in_clean_repos": clean_alarms,
        "public_projects": oss_by_repo,
        "rules_on_caught": dict(rule_hits),
        "seconds": round(time.time() - started, 1),
    }
    Path(__file__).with_name("results.json").write_text(json.dumps(res, indent=2))
    total = commits + clean_commits
    fa = len(false_alarms) + len(clean_alarms)
    print(f"caught {len(caught)}/{known} known malicious commits")
    print(f"false alarms: {fa} of {total - known} other commits ({fa / max(1, total - known):.2%})")
    print(f"  incident repos: {len(false_alarms)} of {commits - known}; clean repos: {len(clean_alarms)} of {clean_commits}")
    print(f"rules that fired on caught commits: {dict(rule_hits)}")
    print(f"{total} commits in {res['seconds']} s")


if __name__ == "__main__":
    main()
