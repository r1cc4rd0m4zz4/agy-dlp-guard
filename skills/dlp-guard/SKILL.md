---
name: dlp-guard
description: Configure, inspect, test, and troubleshoot Antigravity DLP Guard (agy-dlp-guard) for zero-trust Data Loss Prevention, secret redaction, protected file access, and shell command hardening.
---

# Antigravity DLP Guard (`agy-dlp-guard`)

Use this skill when the user wants to inspect, test, configure, or troubleshoot Data Loss Prevention (DLP) hooks and rules in Antigravity (`agy`).

## Architecture Overview

`agy-dlp-guard` enforces deterministic, zero-trust security boundaries using Antigravity's native lifecycle hooks:

1. **`PreToolUse` (`hooks/dlp-guard.mjs`)**:
   - **Integrity & Anti-Tampering Guard**: Blocks write, edit, delete, chmod, or redirect attempts targeting `~/.gemini/config/hooks.json`, `.agents/hooks.json`, `dlp-guard.json`, `plugin.json`, or the `agy-dlp-guard` directory itself, as well as self-disabling CLI invocations (`agy-dlp toggle off`, `agy-dlp uninstall`).
   - **Protected Path Guard (`lib/path-guard.mjs`)**: Blocks reading, writing, editing, or deleting sensitive files (`.env*` except safe templates, SSH/GPG/Age keys, AWS/GCP/Azure/K8s/Terraform/Vault/1Password credentials, `/etc/shadow*`, `/etc/sudoers*`, `.netrc`, `.npmrc`, `.pypirc`) with `fs.realpathSync` symlink resolution, single & double URL decoding, tilde/`$HOME`/`$PWD` expansion, recursive brace expansion (`.{env,bak}`), and shell glob expansion (`.en?`, `.e*`, `[.]env`).
   - **Pre-Execution Secret Prevention (`lib/secret-scanner.mjs`)**: Scans outbound `write_file`, `edit_file`, `multi_replace_file_content`, `send_message`, `search_web`, and `mcp:*` payloads to block accidental secret leaks or exfiltration before execution.
   - **Shell Obfuscation & Destructive Command Guard (`lib/bash-guard.mjs`)**: Inspects `run_command` / `Bash` commands across pipes, subshells `( ... )`, brace groups `{ ...; }`, process substitutions `<(...)` / `>(...)`, ANSI-C `$'\x2e...'` strings, cross-segment variable assignments (`A=.e; B=nv; cat $A$B`), command substitutions `$(echo .env)`, parameter expansions `${x:-.env}`, `xargs` pipelines, `base64 -d | sh`, `dd`, `source`, `grep`/`rg`/`sed`/`awk`/`jq`/`find`/`git`/`tar`/`zip`/`openssl`/`curl`/`wget`, and inline `python`/`node`/`ruby`/`perl` scripts.

2. **`PostToolUse` (`hooks/dlp-guard.mjs`)**:
   - Scans tool output (`read_file`, `run_command`, `grep_search`, `view_file_outline`, `view_code_item`, `mcp:*`, etc.) using 30+ high-precision regex rules and optional `gitleaks` integration.
   - If secrets are found in `read_file` / `grep_search` / `view_*` outputs, blocks the raw output and returns a sanitized `[REDACTED:...]` view via `reason` + `systemMessage` so raw credentials never enter model context.

3. **`UserPromptSubmit` (`hooks/dlp-guard.mjs`)**:
   - Scans user prompts before submission (default mode: `warn`, configurable to `block` in `dlp-guard.json`).

## CLI Commands

Run `agy-dlp` (or `node bin/agy-dlp.mjs`) to manage the hook:

```bash
# Check installation and protection status
node bin/agy-dlp.mjs status

# Install into global Antigravity hooks (~/.gemini/config/hooks.json)
node bin/agy-dlp.mjs install --global

# Install into project-level hooks (.agents/hooks.json)
node bin/agy-dlp.mjs install --project

# Enable or disable DLP protection live (no restart required)
node bin/agy-dlp.mjs toggle on
node bin/agy-dlp.mjs toggle off

# Scan a specific file or command for DLP violations
node bin/agy-dlp.mjs scan-file path/to/file
node bin/agy-dlp.mjs scan-cmd "cat .env"
```
