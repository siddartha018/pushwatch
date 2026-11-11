"""Rule tests on defanged copies of real attack shapes (payloads replaced with console.log)."""

from pushwatch.gitio import FileChange
from pushwatch.rules import HIGH, LOW, MEDIUM, scan_change

PAD = "\t" * 300


def fc(path, new, old=None, status="M"):
    enc = lambda x: None if x is None else (x if isinstance(x, bytes) else x.encode())
    return FileChange(path=path, status=status if old is not None else "A", old=enc(old), new=enc(new))


def rules(findings, sev=None):
    return sorted({f.rule for f in findings if sev is None or f.severity == sev})


# -- VS Code autorun ------------------------------------------------------------
TASKS = """{
  // comments and trailing commas are legal here
  "version": "2.0.0",
  "tasks": [
    {
      "label": "eslint-check",
      "type": "shell",
      "command": "node",
      "args": ["./public/fonts/fa-solid-600.ttf"],
      "hide": true,
      "presentation": {"reveal": "never", "echo": false,},
      "runOptions": {"runOn": "folderOpen"},
    },
  ],
}"""


def test_folder_open_task_is_high_and_explained():
    f = scan_change(fc(".vscode/tasks.json", TASKS))
    assert rules(f, HIGH) == ["vscode-autorun"]
    ev = f[0].evidence
    assert "hidden from the user" in ev and "not a script" in ev


def test_existing_folder_open_task_is_not_reflagged():
    edited = TASKS.replace('"type": "shell"', '"type": "process"')
    assert scan_change(fc(".vscode/tasks.json", edited, old=TASKS)) == []


def test_ordinary_build_task_is_fine():
    plain = '{"version":"2.0.0","tasks":[{"label":"build","type":"npm","script":"build"}]}'
    assert scan_change(fc(".vscode/tasks.json", plain)) == []


# -- disguised scripts -------------------------------------------------------------
def test_text_font_is_a_disguised_script():
    body = "\t" * 262 + "var z = '-500';var a=function(){return require('x')};const b=1;let c=2;module.exports=a;"
    f = scan_change(fc("public/fonts/fa-solid-600.ttf", body))
    assert rules(f, HIGH) == ["disguised-script"]
    assert "262 whitespace" in f[0].evidence


def test_real_font_header_passes():
    assert scan_change(fc("public/fonts/x.woff2", b"wOF2" + bytes(range(256)) * 4)) == []
    assert scan_change(fc("public/fonts/x.ttf", b"\x00\x01\x00\x00" + bytes(range(256)) * 4)) == []


def test_svg_saved_as_png_is_only_low():
    svg = '<svg xmlns="http://www.w3.org/2000/svg" width="126" height="49"><path d="M46 36V13h3"/></svg>' * 2
    f = scan_change(fc("public/logo.png", svg))
    assert [x.severity for x in f] == [LOW]


# -- build-config injection ----------------------------------------------------------
CLEAN_CFG = 'const config = {\n  plugins: {\n    "@tailwindcss/postcss": {},\n  },\n};\n\nexport default config;\n'


def test_payload_after_whitespace_in_postcss_config():
    bad = CLEAN_CFG.replace("export default config;", "export default config;" + PAD + "global.i='A8-0000';console.log(1);")
    f = scan_change(fc("postcss.config.mjs", bad, old=CLEAN_CFG))
    assert "config-injection" in rules(f, HIGH)
    assert "[300 whitespace chars]" in f[0].evidence


def test_cleanup_commit_is_not_flagged():
    bad = CLEAN_CFG.replace("export default config;", "export default config;" + PAD + "console.log(1);")
    assert scan_change(fc("postcss.config.mjs", CLEAN_CFG, old=bad)) == []


def test_normal_config_edit_passes():
    new = CLEAN_CFG.replace("{},", "{},\n    autoprefixer: {},")
    assert scan_change(fc("postcss.config.mjs", new, old=CLEAN_CFG)) == []


def test_word_spawn_inside_a_string_is_not_code():
    cfg = 'module.exports = { worker: ["spawn() from worker-lib", "eval(x) label"] };\n'
    assert scan_change(fc("test/cases/webpack.config.js", cfg)) == []


def test_child_process_import_in_config_is_high():
    cfg = 'const { execSync } = require("child_process");\nexecSync("echo hi");\nmodule.exports = {};\n'
    assert "config-injection" in rules(scan_change(fc("vite.config.js", cfg)), HIGH)


def test_blockchain_lookup_in_config_is_high():
    cfg = 'fetch("https://api.trongrid.io/v1/accounts/x/transactions");\nexport default {};\n'
    assert "blockchain-lookup" in rules(scan_change(fc("babel.config.js", cfg)), HIGH)


def test_hidden_padding_in_ordinary_source():
    src = "export const a = 1;" + PAD + "console.log(1)\n"
    assert rules(scan_change(fc("src/util.ts", src)), HIGH) == ["hidden-padding"]


def test_generated_files_are_ignored_for_padding():
    src = "export const a = 1;" + PAD + "console.log(1)\n"
    assert scan_change(fc("dist/bundle.min.js", src)) == []


# -- package.json, .gitignore --------------------------------------------------------
def test_postinstall_with_node_e_is_high_and_husky_prepare_is_low():
    old = '{"scripts":{"build":"vite build"}}'
    bad = '{"scripts":{"build":"vite build","postinstall":"node -e \\"console.log(1)\\""}}'
    assert rules(scan_change(fc("package.json", bad, old=old)), HIGH) == ["install-hook"]
    husky = '{"scripts":{"build":"vite build","prepare":"husky"}}'
    assert [f.severity for f in scan_change(fc("package.json", husky, old=old))] == [LOW]


def test_gitignore_that_unignores_env_and_hides_pusher():
    old = ".venv/\n.env\nnode_modules\n"
    new = ".venv/\nnode_modules\nconfig.bat\ntemp_auto_push.bat\n"
    f = scan_change(fc(".gitignore", new, old=old))
    assert rules(f, MEDIUM) == ["gitignore-hides-tooling", "gitignore-secrets"]


def test_gitignore_line_ending_rewrite_is_not_a_removal():
    old = ".env\nnode_modules\n"
    new = ".env\r\nnode_modules\r\n"
    assert rules(scan_change(fc(".gitignore", new, old=old))) == []


def test_deleted_files_are_not_scanned():
    assert scan_change(FileChange(".vscode/tasks.json", "D", old=TASKS.encode(), new=None)) == []
