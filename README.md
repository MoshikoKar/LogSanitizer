# Log Sanitizer

Redact sensitive values from logs, config files and Office documents before sharing them.
Matches are replaced with placeholders such as `<EMAIL>` or `<IP>`, or with a keyed hash
(`<HASHED_PASSWORD_3F2A…>`) so that repeated values can still be correlated within one run.

![Log Sanitizer screenshot](screenshot.png)

Treat the output as **best-effort redaction**, not a guarantee of GDPR/HIPAA compliance. Always review it before release.

## Repository
- **GitHub:** [https://github.com/MoshikoKar/LogSanitizer](https://github.com/MoshikoKar/LogSanitizer)
- **Clone URL:** `https://github.com/MoshikoKar/LogSanitizer.git`

## Install and run

Requires Python 3.8+ with Tkinter (bundled on Windows/macOS; `python3-tk` on Debian/Ubuntu).

```bash
git clone https://github.com/MoshikoKar/LogSanitizer.git
cd log-sanitizer
pip install python-docx openpyxl python-pptx   # optional: .docx / .xlsx / .pptx support
pip install tkinterdnd2                       # optional: drag & drop files onto the window
python log_sanitizer.py                       # GUI
```

### GUI
1. **Open…** (Ctrl+O) a log, config or Office file, **Paste** from the clipboard, or type into *Input*.
2. **Sanitize** (Ctrl+Enter or F5). Replacements are highlighted in *Sanitized output*; per-pattern counts appear in the **Hits** column.
3. **Save…** (Ctrl+S; `.docx` saves a Word document) or **Copy**.

Pattern list: click the **On** cell or press Space to toggle, double-click or Enter to **Edit / Test**, Delete to remove.
The edit dialog has a live preview, so you can paste sample text and see exactly what a regex will redact before you save it.
Clipboard shortcuts also work with Hebrew and other non-Latin keyboard layouts.

Opening a file whose name looks sensitive (`.env`, `*secret*`, `*credential*`, `*password*`, `*key*`, `*token*`) re-enables any security patterns you had switched off.

### Command line
Useful for large files, scripts and CI. No GUI is opened when arguments are given.

```bash
python log_sanitizer.py app.log                 # writes app.sanitized.log
python log_sanitizer.py a.log b.log report.docx # several files at once
python log_sanitizer.py app.log -o clean.log -c team-config.json
type app.log | python log_sanitizer.py - -o -   # stdin -> stdout (cat on Linux/macOS)
```

A per-pattern summary is printed to stderr (`-q` to silence it). The exit code is non-zero if any input failed.

## What gets redacted

| Area | Built-in patterns |
|---|---|
| Secrets | `Password`, `APIKey`, `SecretKey`, `AccessToken`, `RefreshToken`, `DatabaseURL`, `ConnectionString` (key/value: `key=v`, `key: v`, `"key": "v"`, `DB_PASSWORD=v`, quoted values with spaces; explicit names like `api_key v` / `password v` also without `=`); `AuthHeader` (Bearer/Basic/NTLM…); `JWTToken`; `CloudToken` (AWS, GitHub, GitLab, Slack, Google, Stripe); `URLCredentials` (`scheme://user:pass@host`); `PrivateKey` (PEM/PGP blocks) |
| Network | `IP`, `IPPort`, `IPv6` (validated), `MACAddress`, `PortSpec` |
| Identity | `Email`, `UserField` (`user=`, `username:`, `User Id=`), `Username` / `Hostname` (this machine), `FilePath_Username` (any `C:\Users\<name>` or `/home/<name>`), `SID`, `GUID` |
| Directory (AD/LDAP) | `DistinguishedName_CN` (`CN=…`), `SAMAccountName`, `DisplayName`, `MailNickname`, `LegacyExchangeDN`, `ObjectCategory`, `ProxyAddresses`, `ShowInAddressBook` |
| Other | `CreditCard` (Luhn-checked), `Timestamp` (after `Logged at `) |

For key/value patterns only the **value** is replaced, so the output stays readable:

```
in : password: hunter2, user=jdoe from 192.168.1.100:8080, Authorization: Bearer eyJhbGciOi...
out: password: <HASHED_PASSWORD_18A216DD4D18>, user=<USER> from <IP>:<PORT>, Authorization: Bearer <HASHED_JWTTOKEN_5C3EB16D8E88>
```

## How matching works
- Every enabled pattern is matched against the **original** text, so a placeholder like `<EMAIL>` is never re-matched by a later pattern.
- When matches overlap, the higher **priority** wins (ties: longer regex first). A lower-priority match that completely *contains* higher-priority matches replaces them, because that redacts more. Example: `DisplayName=John Smith <john@corp.com>` becomes `DisplayName=<USER>`.
- **Hashing** uses HMAC-SHA256 with a fresh random key each run: the same value gets the same token within a run, but tokens cannot be linked across runs and the key is never written anywhere.

## Custom patterns and config files
Add patterns in the GUI (**Add**) or in a JSON config. `config.json` next to the script is loaded automatically; others can be loaded with **Load config…** or `-c`. See [config.json.example](config.json.example).

```json
{
  "patterns": [
    {"name": "Ticket", "regex": "TCK-\\d+", "replacement": "<TICKET>", "priority": 50},
    {"name": "UserID", "regex": "UserID=(?P<value>\\d+)", "replacement": "<ID>", "hash": true},
    {"name": "Hostname", "enabled": false}
  ]
}
```

| Field | Meaning |
|---|---|
| `name` | Required. Reusing a built-in name replaces that built-in. |
| `regex` | Python regex. Name a group `(?P<value>…)` to redact only that part of the match. Omit `regex` to override only `enabled` / `priority` / `hash` of an existing pattern. |
| `replacement` | Placeholder text (default `<REDACTED>`). May use `\1` / `\g<name>` group references. |
| `hash` | Replace with `<HASHED_NAME_…>` instead of the placeholder. |
| `priority` | Higher wins on overlap (built-ins: 30–110). If omitted when overriding a built-in, the built-in's priority is kept; otherwise 0. |
| `case_sensitive`, `enabled`, `comment`, `examples` | Optional. `examples` pre-fill the test box in the edit dialog. |

**Save config…** writes built-ins as overrides only (name, enabled, priority, hash), so improvements to the built-in regexes still apply after an upgrade. Custom and edited patterns are saved in full.
Old configs that copied the built-in regexes from an earlier `config.json.example` are recognised, and the improved built-ins are used instead of those copies.

Regexes with nested quantifiers such as `(a+)+` are rejected to avoid catastrophic backtracking (ReDoS). A pattern that takes longer than 5 s is reported after the run.

## Performance
- Built-in patterns are skipped instantly when their keywords (`password`, `@`, `eyJ`, `sAMAccountName`, …) do not appear in the input.
- Inputs of 4 MB or more are split on line boundaries and scanned in parallel worker processes. The output is identical to a single-process run.
- Roughly 1 MB/0.3 s on a single core; a 14 MB log takes about 2.4 s on 6 cores. That is 1.5–3× faster than the previous version, while running more patterns.
- Maximum input size is 100 MB per file.

## Logging
Operational events (files loaded and saved, counts, errors; never the text itself) go to `logs/sanitizer.log` next to the script, rotating at 5 MB with 3 backups.

## Limitations
- Only values matching an enabled pattern are redacted. Free-text names, addresses and unusual secret formats need custom patterns. Always spot-check the output.
- Office files are converted to plain text (Word: paragraphs and tables; Excel: one tab-separated line per row; PowerPoint: text and tables per slide). Formatting is not preserved, and legacy `.doc` / `.xls` / `.ppt` files are not supported.
- Python's `re` module cannot interrupt a single runaway match. The ReDoS check is a heuristic, so test new regexes in the edit dialog first.
- Highlighting in the GUI is limited to the first 50,000 replacements.

## Troubleshooting
- **"Reading this file needs python-docx" (or openpyxl / python-pptx):** install the package shown.
- **Garbled characters:** UTF-8, UTF-8-BOM, UTF-16 (with or without BOM) and Windows-1252 are detected automatically. Re-save the file as UTF-8 if it uses another encoding.
- **A pattern does not match:** open it with **Edit / Test**, paste a sample, and adjust the regex while watching the live preview. Check `logs/sanitizer.log` for patterns skipped while loading a config.
- **No GUI:** install Tkinter (`sudo apt-get install python3-tk`), or use the command line.

## Contributing
1. Clone [the repository](https://github.com/MoshikoKar/LogSanitizer) and create a branch: `git checkout -b feature/my-feature`
2. Run the tests: `python -m unittest -v`
3. Commit, push, and open a merge request.

Please follow the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/0/code_of_conduct/).

## License
MIT. See [LICENSE](LICENSE).

## Support
Open an issue: [https://github.com/MoshikoKar/LogSanitizer/issues](https://github.com/MoshikoKar/LogSanitizer/issues)
