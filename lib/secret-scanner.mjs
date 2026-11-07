import * as cp from "node:child_process";
import { DEFAULT_CONFIG } from "./config.mjs";

const secretMap = new Map();
const catCounters = new Map();

export function resetSessionState() {
  secretMap.clear();
  catCounters.clear();
}

export function getRedactedCount() {
  return secretMap.size;
}

export function tokenFor(rawVal, cat) {
  let tok = secretMap.get(rawVal);
  if (!tok) {
    const count = (catCounters.get(cat) ?? 0) + 1;
    catCounters.set(cat, count);
    tok = `[REDACTED_${cat}_#${count}]`;
    secretMap.set(rawVal, tok);
  }
  return tok;
}

export const RULES = [
  {
    category: "PRIVATE_KEY",
    rx: /(-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----)/g,
  },
  {
    category: "AGE_SECRET_KEY",
    rx: /\b(AGE-SECRET-KEY-1[A-Z0-9]{58})\b/g,
  },
  {
    category: "AWS_KEY",
    rx: /\b((?:AKIA|ASIA)[0-9A-Z]{16})\b/g,
  },
  {
    category: "GITHUB_TOKEN",
    rx: /\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})(?![\w])/g,
  },
  {
    category: "GITLAB_TOKEN",
    rx: /\b(glpat-[0-9a-zA-Z_\-]{20,})\b/g,
  },
  {
    category: "SLACK_TOKEN",
    rx: /\b(xox[baprs]-[0-9a-zA-Z-]{10,48})\b/g,
  },
  {
    category: "NPM_TOKEN",
    rx: /\b(npm_[A-Za-z0-9]{36})(?![\w])/g,
  },
  {
    category: "PYPI_TOKEN",
    rx: /\b(pypi-[A-Za-z0-9_-]{50,})(?![\w-])/g,
  },
  {
    category: "API_KEY",
    rx: /\b(sk-(?:ant|proj|svcacct|admin)-[\w-]{20,}|sk-[A-Za-z0-9]{32,}|AIza[0-9A-Za-z-_]{35}|[rs]k_live_[0-9A-Za-z]{24,}|hf_[a-zA-Z0-9]{34}|SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}|do[po]_v1_[a-f0-9]{64})(?![\w-])/g,
  },
  {
    category: "JWT_TOKEN",
    rx: /\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g,
  },
  {
    category: "BEARER_TOKEN",
    rx: /Authorization["']?\s*:\s*["']?Bearer\s+([A-Za-z0-9_\-.~+/]{16,}=*)/gi,
  },
  {
    category: "URL_CREDENTIAL",
    rx: /[a-zA-Z][a-zA-Z0-9+.-]*:\/\/(?:[^\s:/@]*:)?([^\s@/]{3,})@/g,
  },
  {
    category: "SECRET",
    rx: new RegExp(
      `(?:^|[\\s;,{("'])(?:export\\s+)?([A-Za-z0-9_-]+)["']?\\s*[=:]\\s*(?:"([^"\\r\\n]{8,})"|'([^'\\r\\n]{8,})'|([A-Za-z0-9_~%+=-]{8,})(?![A-Za-z0-9_~%+=-]|[.(]))`,
      "gi"
    ),
  },
];

const BENIGN_SET = new Set([
  "true",
  "false",
  "null",
  "undefined",
  "none",
  "unknown",
  "example",
  "changeme",
  "dummy",
  "placeholder",
  "password",
  "secret",
  "token",
  "choice",
  "score",
  "noun",
  "string",
  "number",
  "boolean",
  "integer",
  "array",
  "object",
]);

const NON_SECRET_KEY_SUFFIXES = new Set([
  "type",
  "types",
  "method",
  "methods",
  "mode",
  "modes",
  "provider",
  "providers",
  "status",
  "flow",
  "required",
  "check",
  "scope",
  "scheme",
  "name",
  "names",
  "id",
  "ids",
  "path",
  "paths",
  "url",
  "urls",
  "uri",
  "uris",
  "file",
  "files",
  "dir",
  "dirs",
  "count",
  "counts",
  "total",
  "totals",
  "length",
  "size",
  "limit",
  "rate",
  "score",
  "scores",
  "choice",
  "choices",
  "category",
  "categories",
  "label",
  "labels",
  "result",
  "results",
  "index",
  "indices",
  "list",
  "field",
  "fields",
  "schema",
  "prompt",
  "instruction",
  "instructions",
  "criteria",
]);

const NON_SECRET_EXACT_KEYS = new Set([
  "key",
  "keys",
  "pass",
  "auth",
  "private",
  "public",
  "primary_key",
  "foreign_key",
  "sort_key",
  "routing_key",
  "cache_key",
  "partition_key",
  "composite_key",
  "event_key",
  "search_key",
  "object_key",
  "decision_key",
  "type_key",
  "translation_key",
  "item_key",
  "element_key",
  "map_key",
  "cluster_key",
  "typed_key",
  "tokenizer_token",
  "nlp_token",
  "ast_token",
  "lexical_token",
  "cancellation_token",
  "test_pass",
  "compiler_pass",
  "render_pass",
  "multi_pass",
  "private_method",
  "private_field",
  "private_property",
  "private_repo",
  "private_route",
]);

const SENSITIVE_KEY_PATTERNS = [
  /(?:^|[_-])pw(?:[_-]|$)|password|passwd|passphrase|passcode/i,
  /secret/i,
  /credential/i,
  /(?:api|secret|private|priv|access|signing|encryption|enc|master|ssh|auth|license|app|client|deploy)[_-]key/i,
  /(?:auth|access|refresh|bearer|session|api|id|secret)[_-]token/i,
  /\b(?:db|database|admin|root|user|redis|postgres|mysql|ftp|smtp)[_-]pass\b/i,
];

function isNaturalLanguageIdentifier(val) {
  return /^[a-z]+(?:[_-][a-z]+)*$/.test(val);
}

function isSafeOrPlaceholder(secret, quoteType) {
  if (!secret || typeof secret !== "string") return true;
  const trimmed = secret.trim();
  if (BENIGN_SET.has(trimmed.toLowerCase())) return true;
  if (/^\[REDACTED_[A-Z_]+_#\d+\]$/.test(trimmed)) return true;
  if (/^(?:<[A-Za-z0-9_ -]+>|\([A-Za-z0-9_ -]+\)|\[[A-Za-z0-9_ -]+\]|\*+|\.+)$/.test(trimmed)) return true;
  // Single-quoted strings in shell/JSON are literal values, not variable expansions
  if (quoteType === "single") return false;
  if (/^\$\{?[A-Z_][A-Z0-9_]*\}?$/.test(trimmed)) return true;
  return false;
}

function isSensitiveSecretAssignment(varName, secret, quoteType) {
  if (!varName || isSafeOrPlaceholder(secret, quoteType)) return false;
  // Text with whitespace (sentences, descriptions) in assignments are natural language, not secrets
  if (/\s/.test(secret.trim())) return false;

  const name = varName.trim().toLowerCase();
  const rawName = varName.trim();

  // 1. Non-secret exact keys (object properties, dictionary keys, test passes, AST tokens)
  if (NON_SECRET_EXACT_KEYS.has(name)) {
    // If it is bare 'token' or 'tokens', only treat as secret if value has digits/entropy (not natural language)
    if ((name === "token" || name === "tokens") && !isNaturalLanguageIdentifier(secret)) {
      return true;
    }
    return false;
  }

  // 2. Non-secret suffixes (metadata, types, counters, status, metrics, schema)
  const lastUnderscore = name.lastIndexOf("_");
  const lastHyphen = name.lastIndexOf("-");
  const sepIndex = Math.max(lastUnderscore, lastHyphen);
  if (sepIndex > 0) {
    const suffix = name.slice(sepIndex + 1);
    if (NON_SECRET_KEY_SUFFIXES.has(suffix)) return false;
  }

  // 3. Natural language identifiers (snake_case/kebab-case words without digits or symbols)
  // are never secrets unless the variable explicitly designates a password/passphrase
  const isExplicitPassword = /(?:^|[_-])pw(?:[_-]|$)|password|passwd|passphrase|passcode/i.test(name);
  if (!isExplicitPassword && isNaturalLanguageIdentifier(secret)) {
    return false;
  }

  // 4. Must match a known sensitive credential variable pattern or uppercase TOKEN/SECRET
  if (SENSITIVE_KEY_PATTERNS.some((rx) => rx.test(rawName))) {
    return true;
  }

  if (/^(?:TOKEN|SECRET|CREDENTIAL|API_KEY)$/.test(rawName)) {
    return true;
  }

  return false;
}

function isBenign(val) {
  return isSafeOrPlaceholder(val);
}

let gitleaksMode = null;

export function parseGitleaksMode(versionOutput) {
  if (!versionOutput || typeof versionOutput !== "string") return false;
  const m = versionOutput.trim().match(/v?(\d+)\.(\d+)\.(\d+)/);
  if (!m) return false;
  const major = Number(m[1]);
  const minor = Number(m[2]);
  if (major > 8 || (major === 8 && minor >= 19)) return "stdin";
  if (major === 8) return "detect-pipe";
  return false;
}

export function hasGitleaks() {
  if (gitleaksMode === null) {
    try {
      const res = cp.spawnSync("gitleaks", ["version"], { timeout: 2000, encoding: "utf-8" });
      gitleaksMode = res.status === 0 ? parseGitleaksMode(`${res.stdout ?? ""}\n${res.stderr ?? ""}`) : false;
    } catch {
      gitleaksMode = false;
    }
  }
  return gitleaksMode !== false;
}

export function scanWithGitleaks(text, timeoutMs = 2000, modeOverride) {
  if (!modeOverride && !hasGitleaks()) return [];
  const mode = modeOverride ?? (gitleaksMode || "stdin");
  const args =
    mode === "detect-pipe"
      ? ["detect", "--pipe", "--no-banner", "--log-level", "error", "--report-format", "json", "--report-path", "-"]
      : ["stdin", "--no-banner", "--log-level", "error", "--report-format", "json", "--report-path", "-"];
  try {
    const res = cp.spawnSync("gitleaks", args, {
      input: text,
      timeout: timeoutMs,
      encoding: "utf-8",
      maxBuffer: 10 * 1024 * 1024,
    });
    const parsed = JSON.parse(res.stdout || "[]");
    if (!Array.isArray(parsed)) return [];
    return parsed
      .map((item) => (item && typeof item === "object" ? item.Secret : ""))
      .filter((s) => typeof s === "string" && s.length >= 8 && !isSafeOrPlaceholder(s));
  } catch {
    return [];
  }
}

export function detectSecrets(text, config = DEFAULT_CONFIG, useGitleaks = true) {
  if (typeof text !== "string" || !text) return null;

  for (const { category, rx } of RULES) {
    rx.lastIndex = 0;
    let match;
    while ((match = rx.exec(text)) !== null) {
      let captured;
      let quoteType;
      if (category === "SECRET") {
        const varName = match[1];
        if (match[2]) {
          captured = match[2];
          quoteType = "double";
        } else if (match[3]) {
          captured = match[3];
          quoteType = "single";
        } else if (match[4]) {
          captured = match[4];
          quoteType = "none";
        }
        if (!captured || !isSensitiveSecretAssignment(varName, captured, quoteType)) continue;
      } else {
        captured = match.slice(1, 4).find((g) => typeof g === "string" && g.length > 0);
        if (!captured || isSafeOrPlaceholder(captured, quoteType)) continue;
      }

      return {
        category,
        detected: captured,
        sample: captured.length > 8 ? `${captured.slice(0, 4)}...${captured.slice(-4)}` : "[SECRET]",
      };
    }
  }

  if (useGitleaks && config.enableGitleaks && text.length >= config.gitleaksMinBytes) {
    const leaks = scanWithGitleaks(text, config.gitleaksTimeoutMs);
    if (leaks.length > 0) {
      const first = leaks[0];
      return {
        category: "GITLEAKS_DETECTED",
        detected: first,
        sample: first.length > 8 ? `${first.slice(0, 4)}...${first.slice(-4)}` : "[SECRET]",
        count: leaks.length,
      };
    }
  }

  return null;
}

function replaceKnown(text) {
  if (!secretMap.size) return text;
  let out = text;
  for (const sec of [...secretMap.keys()].sort((a, b) => b.length - a.length)) {
    if (out.includes(sec)) out = out.split(sec).join(secretMap.get(sec));
  }
  return out;
}

export function redactSecrets(text, config = DEFAULT_CONFIG, useGitleaks = false) {
  if (typeof text !== "string" || !text) return text;
  let out = replaceKnown(text);

  for (const { category, rx } of RULES) {
    rx.lastIndex = 0;
    out = out.replace(rx, (fullMatch, ...args) => {
      const offsetIndex = args.findIndex((a) => typeof a === "number");
      const groups = offsetIndex >= 0 ? args.slice(0, offsetIndex) : args.slice(0, -2);
      let secret;
      let quoteType;

      if (category === "SECRET") {
        const varName = groups[0];
        if (groups[1]) {
          secret = groups[1];
          quoteType = "double";
        } else if (groups[2]) {
          secret = groups[2];
          quoteType = "single";
        } else if (groups[3]) {
          secret = groups[3];
          quoteType = "none";
        }
        if (!secret || !isSensitiveSecretAssignment(varName, secret, quoteType)) return fullMatch;
      } else {
        secret = groups.find((group) => typeof group === "string" && group.length > 0);
        if (!secret || isSafeOrPlaceholder(secret, quoteType)) return fullMatch;
      }

      const idx = fullMatch.lastIndexOf(secret);
      if (idx === -1) return fullMatch;
      return (
        fullMatch.slice(0, idx) +
        tokenFor(secret, category) +
        fullMatch.slice(idx + secret.length)
      );
    });
  }

  out = replaceKnown(out);

  if (useGitleaks && config.enableGitleaks && out.length >= config.gitleaksMinBytes) {
    const leaks = scanWithGitleaks(out, config.gitleaksTimeoutMs);
    for (const leak of leaks) {
      if (!isSafeOrPlaceholder(leak)) {
        out = out.split(leak).join(tokenFor(leak, "SECRET"));
      }
    }
  }

  return out;
}
