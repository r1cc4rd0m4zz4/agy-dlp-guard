# 🛡️ agy-dlp-guard

**Zero-Trust Data Loss Prevention (DLP), Secret Redaction & Shell Hardening Plugin/Hook for Google Antigravity (`agy`).**

Inspired by [`pi-dlp-guard`](https://github.com/r1cc4rd0m4zz4/pi-dlp-guard) and engineered specifically for the **Antigravity (`agy`)** lifecycle hook architecture (`PreToolUse`, `SessionStart`) and native `agy plugin` specification.

---

> [!IMPORTANT]
> **Skill vs Full Security Plugin (`skills.sh` vs `agy plugin install`)**:
> - Se installi questo repository tramite il gestore di prompt skills (`pnpx skills add https://github.com/r1cc4rd0m4zz4/agy-dlp-guard`), viene copiata **solamente la Skill prompt** (`skills/dlp-guard/SKILL.md`) che fornisce all'agente le nozioni di DLP. **Non vengono installati né attivati gli hook di ciclo di vita a basso livello**.
> - Per attivare l'**enforcement deterministico** (il blocco a basso livello dei comandi shell, la prevenzione dei leak nei tool e la protezione dei percorsi riservati), devi installare `agy-dlp-guard` tramite la procedura standard ufficiale: `agy plugin install`.

---

## ✨ Key Security Capabilities

### 1. 🔒 Protected Path & Symlink Traversal Guard (`PreToolUse`)
Blocks read, write, edit, copy, move, or delete operations targeting sensitive files across **all** Antigravity tools (`read_file`, `write_file`, `edit_file`, `multi_replace_file_content`, `run_command`, etc.):
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
- **Subshell & Grouping Unwrapping**: Recursively unwraps subshells, command substitutions, and grouped blocks.
- **Destructive Target Resolution**: Blocks destructive tools (`rm`, `unlink`, `shred`, `mv`, `cp`, `ln`, `truncate`, `dd`, `chmod`, `chown`, redirects) targeting protected or integrity paths.
- **Anti-Obfuscation Engine**:
  - ANSI-C quoting decoding (`$'\x2e...'`)
  - Cross-segment variable assignment tracking (`A=.e; B=nv; cat $A$B`)
  - Parameter expansion normalization
  - Pipe-to-`xargs` tracking
  - Encoded payload execution blocking (`base64 -d | sh`, `xxd -r | bash`, `eval`)
  - Inline script inspection (`python3 -c`, `node -e`, `ruby -e`, `perl -e`)
- **Tool-Aware Argument Inspection**:
  - Distinguishes search patterns from file paths (`grep`, `rg`, `ag`).
  - Inspects `dd`, `source`, `git`, `tar`, `zip`, `openssl`, `curl`, `wget`.

### 3. 🛡️ Self-Protection & Integrity Guard (`PreToolUse`)
Prevents a compromised or jailbroken agent from disabling or tampering with DLP enforcement:
- Blocks writes, edits, deletions, symlinks, permissions changes, or redirects to `~/.gemini/config/hooks.json`, `.agents/hooks.json`, `dlp-guard.json`, `plugin.json`, and the `agy-dlp-guard` installation directory.
- Blocks self-disabling CLI execution (`agy-dlp toggle off`, `agy-dlp uninstall`, `agy plugin disable agy-dlp-guard`) inside `run_command`.

### 4. 🕵️ Dual-Engine Secret Scanner & Redaction (`PreToolUse`)
- **30+ High-Precision Built-in Regex Rules**:
  - AWS Access Keys & Secret Keys
  - GitHub Tokens, GitLab PATs, Slack Tokens & Webhooks
  - Google API Keys, OpenAI & Anthropic Keys
  - Stripe, Twilio, SendGrid, DigitalOcean, npm, PyPI, Age keys, Vault, Databricks, Telegram, JWTs, Bearer tokens
  - PEM Private Keys
  - Database Connection URIs with embedded credentials
  - Sensitive credential variable patterns with code-aware lookahead and AST benign key immunity.
- **Optional Gitleaks Integration**: Automatically invokes `gitleaks` when installed on `PATH` for 150+ additional vendor rules.
- **Outbound Leak & Exfiltration Prevention (`PreToolUse`)**: Blocks `write_file`, `edit_file`, `multi_replace_file_content`, `send_message`, `search_web`, and `mcp:*` calls attempting to write or exfiltrate hardcoded secrets.

---

## 🚀 Installazione Ufficiale

Installazione diretta in Antigravity (`agy`) in un solo comando tramite il plugin manager ufficiale:

```bash
agy plugin install https://github.com/r1cc4rd0m4zz4/agy-dlp-guard
```

Antigravity clona automaticamente il repository in `~/.gemini/config/plugins/agy-dlp-guard`, registra il manifest (`plugin.json`), aggancia gli hook di ciclo di vita (`hooks.json`), e attiva la regola `rules/AGENTS.md` e la skill `dlp-guard`.

### Gestione del Plugin

```bash
# Verifica lo stato e i componenti attivi
agy plugin list

# Disabilita temporaneamente / Riabilita
agy plugin disable agy-dlp-guard
agy plugin enable agy-dlp-guard

# Disinstalla
agy plugin uninstall agy-dlp-guard
```

---

## 🛠️ CLI di Diagnostica e Test (`agy-dlp`)

All'interno dell'installazione è disponibile il comando di diagnostica:

```bash
# Mostra lo stato di DLP Guard, la configurazione attiva e il rilevamento del Plugin Engine
node bin/agy-dlp.mjs status

# Esegui un test diagnostico su percorso o comando per verificare se viene bloccato
node bin/agy-dlp.mjs scan path/to/target
node bin/agy-dlp.mjs scan "git status"

# Esegui la suite di test di sicurezza
node bin/agy-dlp.mjs test
```

---

## ⚙️ Configurazione Personalizzata (`dlp-guard.json`)

Per personalizzare le liste di percorsi o abilitare/disabilitare funzionalità specifiche, crea `.agents/dlp-guard.json` (nel progetto) o `~/.gemini/config/dlp-guard.json` (globale). Vedi [`dlp-guard.json.example`](./dlp-guard.json.example).

---

## 🧪 Esecuzione dei Test

`agy-dlp-guard` include una suite completa di test di sicurezza a zero dipendenze esterne:

```bash
npm test
```

---

## 📄 License

MIT © [r1cc4rd0m4zz4](https://github.com/r1cc4rd0m4zz4)
