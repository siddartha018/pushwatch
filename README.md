# pushwatch

Catches malicious code in a git push before anyone runs it. Runs as a GitHub Action on every push and pull request, or from the command line against any repository, bare clones included. It reads commits straight from git's object store, so it never checks out or executes what it scans.

```
$ pushwatch commit e97fbe4
e97fbe4b0d  2026-11-11  One-click Render deploy: blueprint + single-container Dockerfile
  HIGH vscode-autorun         .vscode/tasks.json:21
       VS Code task 'eslint-check' runs automatically when the folder is opened
       command: node ./public/fonts/fa-solid-600.ttf; hidden from the user; runs a file that is not a script
  HIGH disguised-script       public/fonts/fa-solid-600.ttf
       A .ttf file that is really text, likely a script in disguise
       100% printable text, 19 script keywords, starts with 262 whitespace characters
  MED  gitignore-secrets      .gitignore
       .gitignore stops ignoring secret files, so they could be committed next
       removed: .env
```

## Why it exists

My GitHub account was used to push malware twice.

- **April to October 2026:** an obfuscated loader was appended to the build configs (`postcss.config.mjs`, `babel.config.js`, `vite.config.js`) of 22 repositories. It sat after `export default config;` and about 400 tabs, so it was off-screen in every editor. It ran on every `npm run build` and fetched its next stage from an address stored in a blockchain transaction. The commits were titled "Update README.md" and "Revise README".
- **November 2026:** a force-push replaced a commit with a copy that kept its message, author and date. The copy added a VS Code task that runs `node ./public/fonts/fa-solid-600.ttf` whenever the folder is opened. That "font" is an obfuscated script. The copy also removed `.env` from `.gitignore`.

Code review missed both, because the changes were built not to be seen: hidden by whitespace, inside files nobody reads, under ordinary commit messages, or in a commit that looked identical to the one it replaced. pushwatch checks for exactly those tricks.

## Results on real attacks

Every commit on every branch of the 22 affected repositories was scanned, plus the November commit. The answer key was built without pushwatch: every commit whose added lines contain the campaign's marker (`global.i = '…'` or `global['!'] = '…'`), plus the November commit by hand.

| | Result |
|---|---|
| Known malicious commits caught | **27 / 27** |
| False alarms on the other 581 commits in those repositories | **0** |
| False alarms on 2,940 commits: 144 from my own repositories and the latest 400 of each of 7 public projects (Vite, Tailwind CSS, PostCSS, ESLint, webpack, VS Code, VS Code extension samples) | **0** |
| False alarms on a held-out set, scored once without changing any rule: 1,597 commits of React, Babel, SvelteKit and Nuxt | **0** |
| Speed | 3,548 commits in 106 s on a laptop |

An audit of 161 real repositories found two more false alarms: repositories that commit `node_modules`, where library files such as `prettier/plugins/babel.js` matched the build-config pattern. Build configs now need `.config` in the name and vendored folders are skipped. The real-attack score is unchanged at 27/27. The development set first had one false alarm: a webpack test config with the text `"spawn() from worker-lib"` inside a string. The rule now ignores code-like words inside strings. Since that 0 was reached after a fix, the held-out set is the fairer number.

What the scan also turned up:

- **The attacks started in April 2026,** months before anyone noticed.
- **Five more infected commits from three other variants of the campaign** that the first search for one marker had missed. One is titled "security: strip worm payload" and *adds* a payload.
- **One infection arrived inside a merge commit** ("Merge pull request #2 …"). pushwatch compares merges with their first parent, so code that only the merge adds is still seen.
- **Four feature branches still carried a live payload** after the default branches had been cleaned.

The corpus is live malware in private repositories, so it is not published. `bench/real_incidents.py` is the exact script that produced these numbers. Point it at any folder of bare clones and an answer key.

## What it checks

| Rule | Severity | What it looks for |
|---|---|---|
| `vscode-autorun` | high | A new VS Code task with `runOn: folderOpen`, noting if it is hidden or runs a non-script file |
| `disguised-script` | high | A font, image, audio or wasm file whose bytes are text with script keywords instead of the format's header |
| `config-injection` | high | In a build config: code after 200+ whitespace characters, `eval` / `new Function` / `child_process`, a campaign marker, or a 1,000+ character line |
| `hidden-padding` | high | The same off-screen trick in any other source file |
| `obfuscation` | high / medium | A known campaign marker, or heavy `_0x…` identifiers and `\x` escapes in added JavaScript |
| `install-hook` | high / low | A new `preinstall` / `postinstall` / `prepare` script; high if it runs `node -e`, `curl`, a URL or a non-script file |
| `blockchain-lookup` | high / low | Reading blockchain transactions (a way to hide a malware server's address); high inside build configs |
| `gitignore-secrets` | medium | `.gitignore` stops ignoring `.env`, keys or credentials |
| `gitignore-hides-tooling` | medium | `.gitignore` starts hiding `.bat` files or known auto-push tooling |
| `config-change` | medium | `.pushwatch.toml` loosened: a new exception or a higher fail level |
| rewritten history | high | A force-push replaces a commit with one that has the same message and author date but different files |

Only lines a commit **adds** count, so the commit that cleans up a payload is never flagged. When a high finding sits under a message like "Update README.md", the report says the message doesn't match the change.

## Use it

### In one repository

`.github/workflows/pushwatch.yml`:

```yaml
on: [push, pull_request]
permissions:
  contents: read
  pull-requests: write    # the summary comment
  security-events: write  # Security tab alerts
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: siddartha018/pushwatch@v1
        with:
          comment: true   # one comment per pull request, updated on every push
          sarif: true     # alerts in the repository's Security tab
```

Every finding is annotated on its line of the diff and listed in the job summary. The check fails on anything high, and `fail-on: medium` makes it stricter. After a force-push, the action fetches the commit that was replaced so it can compare the two.

### Across a team or an organization

The reusable workflow makes each repository a five-line file:

```yaml
on: [push, pull_request]
jobs:
  pushwatch:
    uses: siddartha018/pushwatch/.github/workflows/scan.yml@v1
    permissions: { contents: read, pull-requests: write, security-events: write }
```

On GitHub Team or Enterprise, an organization ruleset can require that workflow on every repository, so new repositories are covered without anyone remembering to add it. Mark the `scan` check as required in branch protection and a flagged pull request can't be merged.

Before rolling it out, audit what is already there:

```bash
pushwatch audit --owner my-org             # the tip of every branch of every repository: anything live
pushwatch audit --owner my-org --history   # also every commit: when each payload arrived, and if it was cleaned up
```

The audit lists repositories through the `gh` CLI, so it covers exactly what the signed-in account can see. It keeps bare mirrors in `~/.cache/pushwatch` (or, with `--no-cache`, deletes each one right after scanning) and never checks anything out. Branch tips matter most, because cleanups usually fix the default branch and miss the others.

### Team settings

`.pushwatch.toml` holds known-safe exceptions, and every exception needs a reason:

```toml
fail_on = "high"

[[allow]]
rule = "install-hook"
path = "package.json"
reason = "husky installs git hooks in prepare"
```

The settings are read from the **base** of a pull request or the commit **before** a push, never from the change being scanned. A malicious push can't bring its own exception. A change that loosens the settings is reported (`config-change`) and only takes effect once a reviewer merges it.

### From the command line

Python 3.13, no dependencies:

```bash
uv tool install git+https://github.com/siddartha018/pushwatch
pushwatch commit <sha>                       # one commit
pushwatch range main~50..main                # a range
pushwatch range --all                        # every commit on every branch
pushwatch push --before <old> --after <new>  # what a push changed, incl. rewritten history
pushwatch tree origin/feature                # a branch tip as a whole
pushwatch --sarif out.sarif --summary-file out.md push --before <old> --after <new>
pushwatch --repo /path/to/bare.git --json range --all
```

The exit code is 1 when anything at or above the fail level is found, and 2 when the settings file is invalid.

## How it works

- `git diff-tree` lists each commit's changes, and merges are compared with their first parent. One long-running `git cat-file --batch` reads file contents. Nothing is checked out or run, and lazy fetching is turned off, so a scan never touches the network.
- Every rule looks at one changed file and returns findings with the line and the evidence. Rules are plain functions in `src/pushwatch/rules.py`.
- Rewritten-history detection lists the commits a push removed and the ones it added, and matches them by message and author date.

## Limits

- **Rules, not a model.** A new technique that avoids every pattern here will pass. Every rule comes from a real attack and has a test, and adding one is a single function.
- **Files over 2 MB are skipped** and listed as skipped.
- **The force-push check needs the replaced commit.** GitHub usually still serves it by its ID; when it doesn't, the action warns and scans only the new commits.
- **The VS Code check covers `tasks.json`.** Other editors' autorun features, such as JetBrains startup tasks, aren't covered yet.

## Development

```bash
uv sync
uv run pytest -q          # 33 tests: defanged copies of each attack shape, git end-to-end cases, team settings, SARIF, audits
```
