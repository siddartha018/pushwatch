"""Team settings in `.pushwatch.toml`.

    fail_on = "high"            # lowest severity that fails the check

    [[allow]]                   # a known-safe exception, reviewed by a person
    rule = "install-hook"
    path = "package.json"       # glob, matched against the file path
    reason = "husky sets up git hooks in prepare"

The file is always read from the trusted side of a change: the commit before a
push, or the base of a pull request. It is never read from the commit being
scanned, so a malicious push can't bring its own exception. A change to the file
is itself reported, so a new exception gets a second pair of eyes.
"""

from __future__ import annotations

import fnmatch
import subprocess
import tomllib
from dataclasses import dataclass, field

from pushwatch.gitio import FileChange, Repo
from pushwatch.rules import MEDIUM, RANK, Finding

CONFIG_PATH = ".pushwatch.toml"


@dataclass
class Allow:
    rule: str
    path: str = "*"
    reason: str = ""

    def matches(self, f: Finding) -> bool:
        return (self.rule in ("*", f.rule)) and fnmatch.fnmatch(f.path, self.path)


@dataclass
class Config:
    fail_on: str = "high"
    allow: list[Allow] = field(default_factory=list)
    source: str | None = None  # "<ref>:.pushwatch.toml" when loaded

    def filter(self, findings: list[Finding]) -> tuple[list[Finding], list[tuple[Finding, Allow]]]:
        kept, allowed = [], []
        for f in findings:
            a = next((a for a in self.allow if a.matches(f)), None)
            (allowed.append((f, a)) if a else kept.append(f))
        return kept, allowed


class ConfigError(ValueError):
    pass


def parse(text: str, source: str | None = None) -> Config:
    try:
        doc = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{source or CONFIG_PATH}: {exc}") from exc
    fail_on = doc.get("fail_on", "high")
    if fail_on not in RANK:
        raise ConfigError(f"fail_on must be one of {sorted(RANK)}, got {fail_on!r}")
    allows = []
    for i, a in enumerate(doc.get("allow", [])):
        if not isinstance(a, dict) or not a.get("rule"):
            raise ConfigError(f"allow entry {i + 1} needs a rule")
        if not a.get("reason"):
            raise ConfigError(f"allow entry {i + 1} ({a['rule']}) needs a reason, so reviewers know why it's safe")
        allows.append(Allow(rule=a["rule"], path=a.get("path", "*"), reason=a["reason"]))
    return Config(fail_on=fail_on, allow=allows, source=source)


def load(repo: Repo, ref: str | None) -> Config:
    """Read the config at a trusted ref; no file (or no ref) means defaults."""
    if not ref or set(ref) == {"0"}:
        return Config()
    try:
        text = repo.git("show", f"{ref}:{CONFIG_PATH}")
    except subprocess.CalledProcessError:
        return Config()
    return parse(text, source=f"{ref[:10]}:{CONFIG_PATH}")


def rule_config_change(fc: FileChange) -> list[Finding]:
    """A change to the exceptions list is worth a second look."""
    if fc.path != CONFIG_PATH or fc.status == "D" or fc.new is None:
        return []
    try:
        new = parse(fc.new.decode("utf-8", "replace"))
        old = parse(fc.old.decode("utf-8", "replace")) if fc.old else Config()
    except ConfigError as exc:
        return [Finding("config-change", MEDIUM, fc.path, None, "pushwatch settings don't parse", str(exc))]
    added = [a for a in new.allow if (a.rule, a.path) not in {(o.rule, o.path) for o in old.allow}]
    weaker = RANK[new.fail_on] > RANK[old.fail_on]
    if not added and not weaker:
        return []
    bits = [f"allows {a.rule} in {a.path} ({a.reason})" for a in added]
    if weaker:
        bits.append(f"fail_on raised from {old.fail_on} to {new.fail_on}")
    return [Finding("config-change", MEDIUM, fc.path, None,
                    "pushwatch settings loosened; takes effect only after this merges", "; ".join(bits))]
