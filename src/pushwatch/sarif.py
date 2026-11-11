"""SARIF 2.1.0 output, so findings show up in GitHub's Security tab (code scanning)."""

from __future__ import annotations

from pushwatch import __version__
from pushwatch.rules import Finding

LEVEL = {"high": "error", "medium": "warning", "low": "note"}
SECURITY_SEVERITY = {"high": "8.5", "medium": "5.5", "low": "2.0"}
HELP = {
    "vscode-autorun": "A VS Code task with runOn: folderOpen runs as soon as someone opens the folder.",
    "disguised-script": "A file named like a font or image whose bytes are a script.",
    "config-injection": "Build configs run on every build; code hidden in them runs on every developer machine and CI job.",
    "hidden-padding": "Code pushed far to the right by whitespace so editors and diffs don't show it.",
    "obfuscation": "Obfuscated JavaScript or a known malware campaign marker.",
    "install-hook": "npm runs install hooks automatically on npm install.",
    "blockchain-lookup": "Reading a blockchain transaction is a known way to hide a malware server's address.",
    "gitignore-secrets": "Un-ignoring .env or keys lets secrets be committed next.",
    "gitignore-hides-tooling": "Hiding .bat files or auto-push scripts from git is a sign of an automated pusher.",
    "config-change": "Loosened pushwatch settings; they apply only after a person merges them.",
    "rewritten-history": "A force-push replaced commits with look-alikes that changed content.",
}


def to_sarif(findings: list[Finding], commit: str | None = None) -> dict:
    rules = sorted({f.rule for f in findings})
    results = []
    for f in findings:
        region = {"startLine": f.line or 1}
        results.append({
            "ruleId": f.rule,
            "level": LEVEL[f.severity],
            "message": {"text": f"{f.title}: {f.evidence}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.path}, "region": region}}],
            "partialFingerprints": {"pushwatch/v1": f"{f.rule}:{f.path}:{f.evidence[:80]}"},
            **({"properties": {"commit": commit}} if commit else {}),
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "pushwatch",
                "version": __version__,
                "informationUri": "https://github.com/siddartha018/pushwatch",
                "rules": [{
                    "id": r, "name": r,
                    "shortDescription": {"text": HELP.get(r, r)},
                    "help": {"text": HELP.get(r, r)},
                    "properties": {"tags": ["security", "supply-chain"], "security-severity": max(
                        (SECURITY_SEVERITY[f.severity] for f in findings if f.rule == r), key=float)},
                } for r in rules],
            }},
            "results": results,
        }],
    }
