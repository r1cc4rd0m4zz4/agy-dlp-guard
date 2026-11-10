---
name: dlp-guard
description: Configure, inspect, test, and troubleshoot Antigravity DLP Guard (agy-dlp-guard) for zero-trust Data Loss Prevention, secret redaction, protected file access, and shell command hardening.
---

# Antigravity DLP Guard (`agy-dlp-guard`)

Use this skill when inspecting, testing, configuring, or troubleshooting Data Loss Prevention (DLP) hooks and rules in Antigravity (`agy`).

## Architecture Overview

`agy-dlp-guard` enforces deterministic, zero-trust security boundaries using Antigravity's native lifecycle hooks:

1. **`PreToolUse` (`hooks/dlp-guard.mjs`)**:
   - **Integrity & Anti-Tampering Guard**: Blocks write, edit, delete, chmod, or redirect attempts targeting `~/.gemini/config/hooks.json`, `.agents/hooks.json`, `dlp-guard.json`, `plugin.json`, or the `agy-dlp-guard` directory itself, as well as self-disabling CLI invocations (`agy plugin disable agy-dlp-guard`, `agy-dlp toggle off`, `agy-dlp uninstall`).
   - **Protected Path Guard (`lib/path-guard.mjs`)**: Blocks reading, writing, editing, or deleting sensitive files (`.env*` except safe templates, SSH/GPG/Age keys, AWS/GCP/Azure/K8s/Terraform/Vault/1Password credentials, `/etc/shadow*`, `/etc/sudoers*`, `.netrc`, `.npmrc`, `.pypirc`) with realpath symlink resolution, single & double URL decoding, tilde/`$HOME`/`$PWD` expansion, recursive brace expansion, and shell glob expansion.
   - **Pre-Execution Secret Prevention (`lib/secret-scanner.mjs`)**: Scans outbound `write_file`, `edit_file`, `multi_replace_file_content`, `send_message`, `search_web`, and `mcp:*` payloads to block accidental secret leaks or exfiltration before execution.
   - **Shell Obfuscation & Destructive Command Guard (`lib/bash-guard.mjs`)**: Inspects `run_command` commands across pipes, subshells, brace groups, process substitutions, ANSI-C strings, cross-segment variable assignments, command substitutions, parameter expansions, `xargs` pipelines, encoded payload execution (`base64 -d | sh`), and inline script invocations.

2. **`SessionStart` (`hooks/dlp-session-start.mjs`)**:
   - Injects a deterministic security status banner into conversation context at startup outlining active protections and Gitleaks engine status.

## Official Installation & Management

Install via Antigravity plugin manager:

```bash
# Official installation (mounts hooks, rules, and skill automatically)
agy plugin install https://github.com/r1cc4rd0m4zz4/agy-dlp-guard

# Check status
agy plugin list
node bin/agy-dlp.mjs status

# Enable / Disable
agy plugin enable agy-dlp-guard
agy plugin disable agy-dlp-guard
```

## Diagnostics CLI (`agy-dlp`)

Run `node bin/agy-dlp.mjs` to run live tests or diagnostic checks:

```bash
# Check status and loaded rules
node bin/agy-dlp.mjs status

# Run security test suite
node bin/agy-dlp.mjs test
```
