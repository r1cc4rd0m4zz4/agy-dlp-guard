# 🛡️ agy-dlp-guard

**Zero-Trust Data Loss Prevention (DLP), Secret Redaction & Shell Hardening Plugin/Hook for Google Antigravity (`agy`).**

Inspired by [`pi-dlp-guard`](https://github.com/r1cc4rd0m4zz4/pi-dlp-guard) and engineered specifically for the **Antigravity (`agy`)** lifecycle hook architecture (`PreToolUse`, `PostToolUse`, `UserPromptSubmit`, `SessionStart`) and `agy plugin` specification.

---

## ✨ Key Security Capabilities

### 1. 🔒 Protected Path & Symlink Traversal Guard (`PreToolUse`)
Blocks read, write, edit, copy, move, or delete operations targeting sensitive files across **all** Antigravity tools (`read_file`, `write_file`, `edit_file`, `multi_replace_file_content`, `grep_search`, `list_dir`, `find_by_name`, `run_command`, and `mcp:*`):
- **Environment Secrets**: `.env`, `.env.local`, `.env.production`, `.env.staging`, `.env.development.*`, `.envrc` *(while safely permitting genuine non-symlinked `.env.example`, `.env.sample`, `.env.template`, `.env.dist`, `.env.schema` outside integrity paths)*.
- **Cryptographic Keys & Certificates**: `~/.ssh/**`, `id_rsa`, `id_ed25519`, `id_ecdsa`, `id_dsa`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.jks`, `*.keystore`, `*.asc`, `*.gpg`, `*.age`, `~/.gnupg/**`.
- **Cloud, Infra & Package Credentials**: `~/.aws/**`, `~/.config/gcloud/**`, `~/.azure/**`, `~/.kube/**`, `~/.docker/config.json`, `~/.config/gh/**`, `~/.vault-token`, `~/.password-store/**`, `~/.config/op/**`, `*.tfstate*`, `*.tfvars`, `.npmrc`, `.pypirc`, `.netrc`, `.git-credentials`.
- **System Auth Files**: `/etc/shadow`, `/etc/shadow-`, `/etc/gshadow*`, `/etc/sudoers`, `/etc/sudoers.d/**`, `/etc/security/opasswd`.
- **Anti-Bypass Canonicalization**:
  - Single & double URL-decoding (`%2e%2e%2f`, `%252e%252e%252f`)
  - Null-byte stripping & path normalization
  - `$HOME`, `${HOME}`, `$PWD`, `${PWD}`, and `~` expansion
  - Recursive brace expansion (`{.env,.env.local}`, `.{env,bak}`)
  - Shell glob expansion against disk & canonical sensitive targets (`.en?`, `.e*`, `[.]env`, `.env*`)
  - Realpath symlink resolution (`ln -s .env innocent.txt` or `ln -s .env .env.example` → **BLOCKED**)

### 2. 🐚 Deep Shell & Obfuscation Guard (`PreToolUse` on `run_command`)
Parses and inspects complex shell commands before execution:
- **Subshell & Grouping Unwrapping**: Recursively unwraps `(rm .env)`, `{ rm .env; }`, `>(tee .env)`, `<(cat .env)`, and command substitutions `$(...)` / `` `...` ``.
- **Destructive Target Resolution**: Blocks `rm`, `unlink`, `shred`, `wipe`, `srm`, `mv`, `cp`, `ln`, `install`, `rsync`, `truncate`, `dd of=...`, `find ... -delete`, `chmod`, `chown`, `chattr`, `tee`, and shell redirects (`>`, `>>`, `>|`, `&>`, `>&`, `<>`) targeting protected or integrity paths.
- **Anti-Obfuscation Engine**:
  - ANSI-C quoting decoding (`$'\x2e\x65\x6e\x76'` → `.env`, octal `$'\056env'`)
  - Cross-segment variable assignment tracking (`A=.e; B=nv; cat $A$B` and `CMD=cat; F=.env; $CMD $F`)
  - Command substitution & parameter expansion normalization (`rm $(echo .env)`, `cat $(printf '%s' .env)`, `.${empty}env`, `${unset:-.env}`)
  - Pipe-to-`xargs` tracking (`echo .env | xargs cat`)
  - Encoded payload execution blocking (`base64 -d | sh`, `xxd -r | bash`, `eval $(...)`)
  - Inline script inspection (`python3 -c "open('.env')..."`, `node -e "fs.readFileSync('.env')"`, `ruby -e`, `perl -e`)
- **Tool-Aware Argument Inspection**:
  - Distinguishes search pattern from file path in `grep`, `rg`, `ag`, `ack` (`grep SECRET src/app.js` is allowed; `grep foo .env` is blocked).
  - Inspects `dd if=.env`, `source .env`, `. .env`, `sed`/`awk`/`jq`/`yq`, `git diff --no-index /dev/null .env`, `git show HEAD:.env`, `tar`/`zip`/`7z`, `openssl`, `scp`/`sftp`, `curl -d @.env -o .env`, `wget -O .env`.

### 3. 🛡️ Self-Protection & Integrity Guard (`PreToolUse`)
Prevents a compromised or jailbroken agent from disabling or tampering with DLP enforcement:
- Blocks writes, edits, deletions, symlinks, permissions changes, or redirects to `~/.gemini/config/hooks.json`, `.agents/hooks.json`, `dlp-guard.json`, `plugin.json`, and the `agy-dlp-guard` installation directory.
- Blocks self-disabling CLI execution (`agy-dlp toggle off`, `agy-dlp uninstall`) inside `run_command`.

### 4. 🕵️ Dual-Engine Secret Scanner & Redaction (`PreToolUse`, `PostToolUse`, `UserPromptSubmit`)
- **30+ High-Precision Built-in Regex Rules**:
  - AWS Access Keys (`AKIA...`, `ASIA...`) & AWS Secret Keys
  - GitHub Tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`)
  - GitLab PATs (`glpat-`), Slack Tokens (`xoxb-`, `xoxp-`, etc.) & Webhooks
  - Google API Keys (`AIza...`), OpenAI (`sk-proj-...`) & Anthropic (`sk-ant-...`) Keys
  - Stripe (`sk_live_`, `rk_live_`), Twilio (`SK...`), SendGrid (`SG...`), DigitalOcean (`dop_v1_`, `doo_v1_`), npm (`npm_...`), PyPI (`pypi-...`), Age secret keys (`AGE-SECRET-KEY-1...`), HashiCorp Vault (`hvs.`), Databricks (`dapi...`), Telegram Bot Tokens, JWTs, `Authorization: Bearer` tokens
  - PEM Private Keys (`RSA`, `OPENSSH`, `EC`, `DSA`, `PGP`, `ENCRYPTED`)
  - Database Connection URIs with embedded credentials (`postgres://`, `mysql://`, `mongodb+srv://`, `redis://`, `amqp://`)
  - Generic `API_KEY`, `SECRET_KEY`, `ACCESS_TOKEN`, `AUTH_TOKEN`, `PRIVATE_KEY`, `CLIENT_SECRET`, `PASSWORD`, `DB_PASS` assignments (with code-aware lookahead to avoid false positives on JS/TS expressions like `secretToToken.get(secret)`).
- **Optional Gitleaks Integration**: Automatically invokes `gitleaks detect --no-git` when installed on `PATH` for 150+ additional vendor rules.
- **Outbound Leak & Exfiltration Prevention (`PreToolUse`)**: Blocks `write_file`, `edit_file`, `multi_replace_file_content`, `send_message`, `search_web`, and `mcp:*` calls if they attempt to write or exfiltrate hardcoded secrets.
- **Inbound Output Redaction (`PostToolUse`)**: Intercepts `read_file`, `grep_search`, `view_file_outline`, `view_code_item`, `run_command`, and `mcp:*` outputs containing secrets, blocking raw credential exposure and providing a deterministic `[REDACTED:RULE_ID:xxxx...xxxx]` view.

---

## 🚀 Installation

### Option A: Install as a Standalone Antigravity Hook (Recommended)

```bash
git clone https://github.com/r1cc4rd0m4zz4/agy-dlp-guard.git
cd agy-dlp-guard

# Install globally into ~/.gemini/config/hooks.json
node bin/agy-dlp.mjs install --global

# Or install per-workspace into .agents/hooks.json
node bin/agy-dlp.mjs install --project
```

### Option B: Validate & Use as an Antigravity Plugin

`agy-dlp-guard` conforms strictly to the Antigravity Plugin specification (`plugin.json`, `hooks/hooks.json`, `rules/AGENTS.md`, `skills/dlp-guard/SKILL.md`):

```bash
agy plugin validate . --strict
```

---

## 🛠️ CLI Reference (`agy-dlp`)

```bash
# Display current installation, Gitleaks detection, and protected path rules
node bin/agy-dlp.mjs status

# Enable or disable DLP enforcement live (no restart needed)
node bin/agy-dlp.mjs toggle on
node bin/agy-dlp.mjs toggle off

# Test a file path + content against DLP rules
node bin/agy-dlp.mjs scan-file .env
node bin/agy-dlp.mjs scan-file src/config.js

# Test a shell command against the Bash Guard & Secret Scanner
node bin/agy-dlp.mjs scan-cmd "rm -rf .env"
node bin/agy-dlp.mjs scan-cmd "A=.e; B=nv; cat \$A\$B"

# Run the security regression suite
node bin/agy-dlp.mjs test
```

---

## ⚙️ Configuration (`dlp-guard.json`)

Create `.agents/dlp-guard.json` (project) or `~/.gemini/config/dlp-guard.json` (global) to customize behavior. See [`dlp-guard.json.example`](./dlp-guard.json.example):

```json
{
  "enabled": true,
  "mode": "enforce",
  "userPromptAction": "warn",
  "blockWriteSecrets": true,
  "redactToolOutput": true,
  "blockReadToolOutputOnSecret": true,
  "protectedPaths": [
    "**/.env",
    "**/.env.*",
    "**/*.pem",
    "**/*.key"
  ],
  "allowedPaths": [
    "**/.env.example",
    "**/.env.sample",
    "**/.env.template"
  ],
  "gitleaks": {
    "enabled": true,
    "binaryPath": "gitleaks",
    "timeoutMs": 5000
  }
}
```

---

## 🧪 Running Tests

`agy-dlp-guard` ships with a zero-dependency adversarial security regression suite covering 130+ test vectors across path traversal, symlink attacks, shell obfuscation, secret detection, false-positive immunity, and hook lifecycle protocols:

```bash
npm test
```

---

## 📄 License

MIT © [r1cc4rd0m4zz4](https://github.com/r1cc4rd0m4zz4)
