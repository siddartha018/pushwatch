"""Detection rules. Each one looks at a single changed file and returns findings.

The rules are written from real incidents (see README): code appended to build
configs after hundreds of whitespace characters, a VS Code task that runs a fake
font on folder open, and .gitignore edits that stop ignoring secrets. They look
only at what a commit *adds*, so the cleanup commit that removes a payload is
not flagged.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import PurePosixPath

from pushwatch.gitio import FileChange

HIGH, MEDIUM, LOW = "high", "medium", "low"
RANK = {HIGH: 3, MEDIUM: 2, LOW: 1}


@dataclass
class Finding:
    rule: str
    severity: str
    path: str
    line: int | None
    title: str
    evidence: str

    def as_dict(self) -> dict:
        return self.__dict__.copy()


# ---------------------------------------------------------------- helpers ----
def text_of(data: bytes | None) -> str | None:
    if data is None or b"\x00" in data[:8192]:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def added_lines(fc: FileChange) -> list[tuple[int, str]]:
    """(line number in the new file, text) for every line the change adds."""
    new = text_of(fc.new)
    if new is None:
        return []
    new_lines = new.splitlines()
    old = text_of(fc.old)
    if old is None:
        return list(enumerate(new_lines, 1))
    seen: dict[str, int] = {}
    for ln in old.splitlines():
        seen[ln] = seen.get(ln, 0) + 1
    out = []
    for i, ln in enumerate(new_lines, 1):
        if seen.get(ln, 0) > 0:
            seen[ln] -= 1
        else:
            out.append((i, ln))
    return out


def removed_lines(fc: FileChange) -> list[str]:
    old, new = text_of(fc.old), text_of(fc.new)
    if old is None:
        return []
    keep: dict[str, int] = {}
    for ln in (new or "").splitlines():
        keep[ln] = keep.get(ln, 0) + 1
    out = []
    for ln in old.splitlines():
        if keep.get(ln, 0) > 0:
            keep[ln] -= 1
        else:
            out.append(ln)
    return out


def clip(s: str, n: int = 120) -> str:
    s = s.replace("\t", "\\t")
    return s if len(s) <= n else s[: n - 1] + "…"


def show_padding(line: str, m: re.Match) -> str:
    before = line[: m.start()].rstrip()
    after = line[m.end():]
    return f"{clip(before, 50)} [{len(m.group(0))} whitespace chars] {clip(after, 60)}"


CODE_EXT = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx", ".py", ".json", ".sh", ".ps1",
            ".bat", ".cmd", ".vue", ".svelte", ".astro", ".rb", ".php", ".go", ".rs", ".java", ".kt", ".swift"}
# A project's own build configs. ".config" is required: a library file such as
# node_modules/prettier/plugins/babel.js is not a config, and vendored folders are skipped.
_BUILD_CONFIG = re.compile(
    r"(^|/)((postcss|vite|vitest|babel|next|webpack|tailwind|eslint|rollup|metro|nuxt|astro|svelte|jest|"
    r"tsup|esbuild|craco|quasar|remix|playwright|prettier)\.config|gatsby-config|gatsby-node)\.(js|mjs|cjs|ts|mts|cts)$"
    r"|(^|/)\.(babelrc|eslintrc|prettierrc)\.(js|cjs)$"
)
VENDORED = re.compile(r"(^|/)(node_modules|vendor|bower_components|\.pnpm|third_party)/")


class _BuildConfig:
    def search(self, path: str):
        return None if VENDORED.search(path) else _BUILD_CONFIG.search(path)


BUILD_CONFIG = _BuildConfig()
PAD = re.compile(r"[ \t  -​　]{200,}")
# Calls that run code: matched only outside string literals ("spawn() from x" in a label is not a call).
EXEC_CODE = re.compile(r"\beval\s*\(|new\s+Function\s*\(|\bexecSync\s*\(|\bspawn(Sync)?\s*\(|process\.binding\s*\(|\bFunction\s*\(")
# Modules that run code: matched as imports, where the name is necessarily a string.
EXEC_IMPORT = re.compile(r"""(require\s*\(|import\s*\(|from)\s*['"`](node:)?(child_process|vm|worker_threads)['"`]""")
STRINGS = re.compile(r"""'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*"|`(?:\\.|[^`\\])*`""")


def runs_code(line: str) -> bool:
    return bool(EXEC_IMPORT.search(line) or EXEC_CODE.search(STRINGS.sub('""', line)))
CAMPAIGN = re.compile(r"\bglobal\.[A-Za-z_$]{1,3}\s*=\s*['\"][A-Z]\d{1,2}-\d{3,5}['\"]")
OBF_ID = re.compile(r"\b_0x[0-9a-f]{4,6}\b")
CHAIN = re.compile(
    r"eth_getTransactionByHash|eth_getTransactionReceipt|api\.trongrid\.io|bsc-dataseed|"
    r"api\.etherscan\.io|fullnode\.mainnet\.aptoslabs|getTransactionsByAddress|api\.bscscan\.com"
)
ASSET_MAGIC = {
    ".ttf": [b"\x00\x01\x00\x00", b"true", b"OTTO", b"ttcf"],
    ".otf": [b"OTTO", b"\x00\x01\x00\x00"],
    ".woff": [b"wOFF"],
    ".woff2": [b"wOF2"],
    ".eot": None,  # EOT has a size header; checked by "is it text" below
    ".png": [b"\x89PNG"],
    ".jpg": [b"\xff\xd8\xff"],
    ".jpeg": [b"\xff\xd8\xff"],
    ".gif": [b"GIF8"],
    ".ico": [b"\x00\x00\x01\x00", b"\x00\x00\x02\x00", b"\x89PNG"],
    ".webp": [b"RIFF"],
    ".mp3": [b"ID3", b"\xff\xfb", b"\xff\xf3", b"\xff\xf2"],
    ".mp4": None,
    ".wasm": [b"\x00asm"],
    ".pdf": [b"%PDF"],
    ".zip": [b"PK\x03\x04", b"PK\x05\x06"],
}
JS_TOKENS = re.compile(r"\b(var|let|const|function|require|return|=>|import|module\.exports|process|Buffer)\b")


def _jsonc(text: str):
    """Parse VS Code's JSON-with-comments without executing anything."""
    out, i, n, in_str = [], 0, len(text), False
    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
            out.append(ch)
        elif text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
            continue
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
            continue
        else:
            out.append(ch)
        i += 1
    cleaned = re.sub(r",(\s*[}\]])", r"\1", "".join(out)).lstrip("﻿")
    return json.loads(cleaned)


# ------------------------------------------------------------------ rules ----
def rule_vscode_autorun(fc: FileChange) -> list[Finding]:
    if not fc.path.endswith(".vscode/tasks.json") or fc.new is None:
        return []
    text = text_of(fc.new) or ""
    try:
        doc = _jsonc(text)
    except (ValueError, RecursionError):
        if re.search(r'"runOn"\s*:\s*"folderOpen"', text):
            return [Finding("vscode-autorun", HIGH, fc.path, None, "A VS Code task runs when the folder is opened",
                            "runOn: folderOpen (file did not parse as JSON)")]
        return []
    old_labels = set()
    if fc.old is not None:
        try:
            old_labels = {t.get("label") for t in _jsonc(text_of(fc.old) or "{}").get("tasks", [])
                          if (t.get("runOptions") or {}).get("runOn") == "folderOpen"}
        except (ValueError, AttributeError):
            pass
    found = []
    for t in (doc.get("tasks") or []) if isinstance(doc, dict) else []:
        if not isinstance(t, dict) or (t.get("runOptions") or {}).get("runOn") != "folderOpen":
            continue
        if t.get("label") in old_labels:
            continue  # not new in this change
        cmd = " ".join(str(x) for x in [t.get("command", "")] + list(t.get("args") or []))
        pres = t.get("presentation") or {}
        hidden = t.get("hide") is True or pres.get("reveal") == "never" or pres.get("echo") is False
        why = [f"command: {clip(cmd, 80)}"]
        if hidden:
            why.append("hidden from the user")
        if re.search(r"\.(ttf|woff2?|eot|png|jpe?g|gif|ico|svg|txt|md|json)\b", cmd):
            why.append("runs a file that is not a script")
        found.append(Finding("vscode-autorun", HIGH, fc.path, _line_of(text, '"folderOpen"'),
                             f"VS Code task '{t.get('label', '?')}' runs automatically when the folder is opened",
                             "; ".join(why)))
    return found


def _line_of(text: str, needle: str) -> int | None:
    i = text.find(needle)
    return None if i < 0 else text.count("\n", 0, i) + 1


def rule_disguised_script(fc: FileChange) -> list[Finding]:
    ext = PurePosixPath(fc.path).suffix.lower()
    if ext not in ASSET_MAGIC or fc.new is None or len(fc.new) < 64:
        return []
    data = fc.new
    magics = ASSET_MAGIC[ext]
    if magics and any(data.startswith(m) for m in magics):
        return []
    sample = data[:65536]
    printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in sample) / len(sample)
    if printable < 0.95:
        return []  # binary of some other kind: odd, but not a script
    text = sample.decode("utf-8", "replace")
    if text.lstrip().startswith(("<svg", "<?xml")) and "<script" not in text.lower():
        return [Finding("disguised-script", LOW, fc.path, None, f"An SVG image saved with a {ext} name", "harmless unless something executes it")]
    tokens = len(JS_TOKENS.findall(text))
    sev = HIGH if tokens >= 5 else MEDIUM
    lead = len(text) - len(text.lstrip())
    detail = f"{printable:.0%} printable text, {tokens} script keywords"
    if lead >= 100:
        detail += f", starts with {lead} whitespace characters"
    return [Finding("disguised-script", sev, fc.path, None,
                    f"A {ext} file that is really text, likely a script in disguise", detail)]


def rule_config_injection(fc: FileChange) -> list[Finding]:
    if not BUILD_CONFIG.search(fc.path):
        return []
    found = []
    for n, line in added_lines(fc):
        m = PAD.search(line)
        if m and line[m.end():].strip():
            found.append(Finding("config-injection", HIGH, fc.path, n,
                                 "Code hidden off-screen in a build config, after a long run of whitespace",
                                 show_padding(line, m)))
            continue
        if runs_code(line) or CAMPAIGN.search(line):
            found.append(Finding("config-injection", HIGH, fc.path, n,
                                 "A build config that can run code: eval, new Function or child processes",
                                 clip(line.strip())))
        elif len(line) > 1000:
            found.append(Finding("config-injection", HIGH, fc.path, n,
                                 f"A {len(line):,}-character line in a build config", clip(line.strip())))
    return found[:5]


def rule_hidden_padding(fc: FileChange) -> list[Finding]:
    """Off-screen code anywhere else (outside build configs, which have their own rule)."""
    ext = PurePosixPath(fc.path).suffix.lower()
    if ext not in CODE_EXT or BUILD_CONFIG.search(fc.path) or _is_generated(fc.path):
        return []
    for n, line in added_lines(fc):
        m = PAD.search(line)
        if m and line[: m.start()].strip() and line[m.end():].strip():
            return [Finding("hidden-padding", HIGH, fc.path, n,
                            "Code pushed off-screen by a long run of whitespace", show_padding(line, m))]
    return []


def _is_generated(path: str) -> bool:
    p = path.lower()
    return any(s in p for s in ("/dist/", "/build/", "/vendor/", "node_modules/", ".min.", "/out/", "/.next/",
                                "lock.json", ".lock", "/generated/", ".snap"))


def rule_obfuscation(fc: FileChange) -> list[Finding]:
    ext = PurePosixPath(fc.path).suffix.lower()
    if ext not in {".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx"} and not BUILD_CONFIG.search(fc.path):
        return []
    if _is_generated(fc.path):
        return []
    adds = added_lines(fc)
    if not adds:
        return []
    blob = "\n".join(l for _, l in adds)
    camp = CAMPAIGN.search(blob)
    if camp:
        n = next(n for n, l in adds if CAMPAIGN.search(l))
        return [Finding("obfuscation", HIGH, fc.path, n, "A known malware campaign marker",
                        clip(camp.group(0)))]
    ids = len(OBF_ID.findall(blob))
    hexes = len(re.findall(r"\\x[0-9a-fA-F]{2}", blob))
    if ids >= 20 or hexes >= 200:
        return [Finding("obfuscation", MEDIUM, fc.path, adds[0][0], "Obfuscated JavaScript added",
                        f"{ids} _0x identifiers, {hexes} \\x escapes")]
    return []


INSTALL_HOOKS = ("preinstall", "install", "postinstall", "prepare", "prepublish")
RISKY_CMD = re.compile(r"node\s+-e|curl\s|wget\s|powershell|base64|\|\s*(ba)?sh\b|https?://|bash\s+-c|\.(ttf|woff2?|png|jpg)\b")


def rule_install_hook(fc: FileChange) -> list[Finding]:
    if PurePosixPath(fc.path).name != "package.json" or fc.new is None or "node_modules/" in fc.path:
        return []
    try:
        new = (json.loads(text_of(fc.new) or "{}").get("scripts") or {})
        old = (json.loads(text_of(fc.old) or "{}").get("scripts") or {}) if fc.old else {}
    except (ValueError, AttributeError):
        return []
    found = []
    for hook in INSTALL_HOOKS:
        cmd = new.get(hook)
        if not isinstance(cmd, str) or old.get(hook) == cmd:
            continue
        risky = RISKY_CMD.search(cmd)
        found.append(Finding("install-hook", HIGH if risky else LOW, fc.path, None,
                             f"package.json {'adds' if hook not in old else 'changes'} a '{hook}' script, which runs on npm install",
                             clip(cmd)))
    return found


def rule_blockchain_c2(fc: FileChange) -> list[Finding]:
    adds = added_lines(fc)
    for n, line in adds:
        m = CHAIN.search(line)
        if m:
            sev = HIGH if BUILD_CONFIG.search(fc.path) or fc.path.endswith(".vscode/tasks.json") else LOW
            return [Finding("blockchain-lookup", sev, fc.path, n,
                            "Code reads a blockchain transaction, a known way to hide a malware server address",
                            clip(m.group(0)))]
    return []


SECRETS = re.compile(r"^\s*!?/?(\.env[\w.*-]*|\*\.pem|\*\.key|\.npmrc|id_rsa\*?|secrets?[\w./*-]*|credentials[\w.*-]*)\s*$")
PUSHER = re.compile(r"(temp_?auto_?push|temp_?interactive_?push|auto_?push|config\.bat|branch_structure\.json|\.bat$)", re.I)


def rule_gitignore(fc: FileChange) -> list[Finding]:
    if PurePosixPath(fc.path).name != ".gitignore" or fc.new is None:
        return []
    found = []
    still = {l.strip() for l in (text_of(fc.new) or "").splitlines()}
    gone = [l.strip() for l in removed_lines(fc) if SECRETS.match(l) and l.strip() not in still]
    if gone:
        found.append(Finding("gitignore-secrets", MEDIUM, fc.path, None,
                             ".gitignore stops ignoring secret files, so they could be committed next",
                             "removed: " + ", ".join(gone[:5])))
    odd = [l.strip() for _, l in added_lines(fc) if PUSHER.search(l.strip())]
    if odd:
        found.append(Finding("gitignore-hides-tooling", MEDIUM, fc.path, None,
                             ".gitignore hides script files that match known auto-push tooling",
                             "added: " + ", ".join(odd[:5])))
    return found


RULES = [rule_vscode_autorun, rule_disguised_script, rule_config_injection, rule_hidden_padding,
         rule_obfuscation, rule_install_hook, rule_blockchain_c2, rule_gitignore]


def scan_change(fc: FileChange) -> list[Finding]:
    if fc.status == "D":
        return []
    out: list[Finding] = []
    for rule in RULES:
        out.extend(rule(fc))
    return out
