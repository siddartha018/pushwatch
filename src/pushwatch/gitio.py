"""Read commits straight from a git object database: no checkout, nothing executed.

Scanning malware means the scanner must never materialise or run the files it
inspects, so everything here goes through `git diff-tree` and one long-lived
`git cat-file --batch` process.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
MAX_BLOB = 2_000_000  # larger files are skipped (and reported as skipped)
# Never download objects while scanning (partial clones would otherwise fetch lazily).
GIT_ENV = {**os.environ, "GIT_NO_LAZY_FETCH": "1", "GIT_TERMINAL_PROMPT": "0"}


@dataclass
class FileChange:
    path: str
    status: str  # A, M, D, R, T
    old: bytes | None = None
    new: bytes | None = None
    old_path: str | None = None
    skipped: str | None = None  # why the content wasn't read


@dataclass
class Commit:
    sha: str
    parents: list[str]
    author: str
    author_date: str
    subject: str
    message: str
    changes: list[FileChange] = field(default_factory=list)

    @property
    def is_merge(self) -> bool:
        return len(self.parents) > 1


class Repo:
    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        self._cat: subprocess.Popen | None = None

    # -- plumbing ------------------------------------------------------------
    def git(self, *args: str) -> str:
        out = subprocess.run(
            ["git", "-C", self.path, "-c", "core.quotepath=off", *args],
            check=True, capture_output=True, env=GIT_ENV,
        )
        return out.stdout.decode("utf-8", "replace")

    def _batch(self) -> subprocess.Popen:
        if self._cat is None:
            self._cat = subprocess.Popen(
                ["git", "-C", self.path, "cat-file", "--batch"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=GIT_ENV,
            )
        return self._cat

    def blob(self, oid: str) -> tuple[bytes | None, str | None]:
        """Return (content, skip_reason)."""
        if set(oid) == {"0"}:
            return None, None
        p = self._batch()
        assert p.stdin and p.stdout
        try:
            p.stdin.write(oid.encode() + b"\n")
            p.stdin.flush()
            header = p.stdout.readline().decode().split()
        except BrokenPipeError:
            header = []
        if not header:  # the reader died (e.g. an object it couldn't get); start a fresh one
            self.close()
            return None, "object unavailable"
        if len(header) < 3 or header[1] == "missing":
            return None, "missing object"
        size = int(header[2])
        data = p.stdout.read(size)
        p.stdout.read(1)  # trailing newline
        if size > MAX_BLOB:
            return None, f"larger than {MAX_BLOB // 1_000_000} MB"
        return data, None

    def close(self) -> None:
        if self._cat is not None:
            try:
                if self._cat.stdin:
                    self._cat.stdin.close()
            except BrokenPipeError:
                pass
            try:
                self._cat.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._cat.kill()
            self._cat = None

    def __enter__(self) -> "Repo":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- commits -------------------------------------------------------------
    def rev_list(self, spec: str, all_refs: bool = False) -> list[str]:
        args = ["rev-list", "--all"] if all_refs else ["rev-list", spec]
        return [s for s in self.git(*args).split() if s]

    def resolve(self, ref: str) -> str:
        return self.git("rev-parse", "--verify", f"{ref}^{{commit}}").strip()

    def commit(self, sha: str, with_content: bool = True) -> Commit:
        meta = self.git("log", "-1", "--no-walk", "--no-mailmap", "--format=%H%x00%P%x00%an <%ae>%x00%aI%x00%s%x00%B", sha)
        full, parents, author, date, subject, message = meta.split("\x00", 5)
        c = Commit(full, parents.split(), author, date, subject, message.rstrip())
        # Merges are compared with their first parent: an "evil merge" that adds code
        # no branch ever had shows up here, and so does everything the merge brings in.
        base = c.parents[0] if c.parents else EMPTY_TREE
        try:
            raw = self.git("diff-tree", "-r", "--no-commit-id", "-M", "-z", "--raw", base, c.sha)
        except subprocess.CalledProcessError:
            # rename detection reads file contents; in a partial clone some may be absent
            raw = self.git("diff-tree", "-r", "--no-commit-id", "--no-renames", "-z", "--raw", base, c.sha)
        c.changes = list(self._parse_raw(raw, with_content))
        return c

    def _parse_raw(self, raw: str, with_content: bool):
        parts = raw.split("\x00")
        i = 0
        while i < len(parts) - 1:
            head = parts[i]
            if not head.startswith(":"):
                i += 1
                continue
            _, _, old_oid, new_oid, status = head[1:].split(" ", 4)
            kind = status[0]
            if kind in "RC":
                old_path, path = parts[i + 1], parts[i + 2]
                i += 3
            else:
                old_path, path = None, parts[i + 1]
                i += 2
            fc = FileChange(path=path, status=kind, old_path=old_path)
            if with_content:
                fc.old, s1 = self.blob(old_oid)
                fc.new, s2 = self.blob(new_oid)
                fc.skipped = s1 or s2
            yield fc

    def tree_files(self, ref: str = "HEAD") -> list[FileChange]:
        """Every file at `ref`, as if newly added (for scanning a whole snapshot)."""
        out = self.git("ls-tree", "-r", "-z", ref)
        files = []
        for entry in out.split("\x00"):
            if not entry:
                continue
            meta, path = entry.split("\t", 1)
            _, kind, oid = meta.split()
            if kind != "blob":
                continue
            data, skip = self.blob(oid)
            files.append(FileChange(path=path, status="A", new=data, skipped=skip))
        return files
