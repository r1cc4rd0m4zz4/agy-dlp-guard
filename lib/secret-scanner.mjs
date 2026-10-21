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

const SEC_WORDS = [
  "SECRET",
  "KEY",
  "TOKEN",
  "PASSWORD",
  "PASSWD",
  "PASS",
  "PW",
  "AUTH",
  "PRIVATE",
  "CREDENTIAL",
].join("|");

export const RULES = [
  {
    category: "PRIVATE_KEY",
    rx: /(-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----)/g,
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
    rx: /\b(sk-ant-[\w-]{20,}|sk-proj-[\w-]{20,}|sk-[A-Za-z0-9]{32,}|AIza[0-9A-Za-z-_]{35}|[rs]k_live_[0-9A-Za-z]{24,}|hf_[a-zA-Z0-9]{34}|SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}|do[po]_v1_[a-f0-9]{64})(?![\w-])/g,
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
    rx: /[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^\s:/@]+:([^\s@/]{3,})@/g,
  },
  {
    category: "SECRET",
    rx: new RegExp(
      "(?:^|[\\s;,{(\"'])(?:export\\s+)?(?:[A-Za-z0-9]+[_-])*(?:" +
        SEC_WORDS +
        ")(?:[_-][A-Za-z0-9]+)*[\"']?\\s*[=:]\\s*(?:\"([^\"\\r\\n]{8,})\"|'([^'\\r\\n]{8,})'|([A-Za-z0-9_~%+=-]{8,})(?![A-Za-z0-9_~%+=-]|[.(]))",
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
]);

function isBenign(val) {
  if (!val || typeof val !== "string") return true;
  const s = val.trim().toLowerCase();
  if (BENIGN_SET.has(s)) return true;
  if (/^(?:\$\{[^}]+\}|\$[A-Za-z_]\w*|<[^>]+>|\[REDACTED_.*\]|\*+|\.+)$/.test(val)) return true;
  return false;
}

let gitleaksAvailable = null;
export function hasGitleaks() {
  if (gitleaksAvailable === null) {
    try {
      const res = cp.spawnSync("gitleaks", ["version"], { timeout: 1000, stdio: "ignore" });
      gitleaksAvailable = res.status === 0;
    } catch {
      gitleaksAvailable = false;
    }
  }
  return gitleaksAvailable;
}

export function scanWithGitleaks(text, timeoutMs = 500) {
  if (!hasGitleaks()) return [];
  try {
    const res = cp.spawnSync(
      "gitleaks",
      ["stdin", "--no-banner", "--log-level", "error", "--report-format", "json", "--report-path", "-"],
      {
        input: text,
        timeout: timeoutMs,
        encoding: "utf-8",
        maxBuffer: 10 * 1024 * 1024,
      }
    );
    const parsed = JSON.parse(res.stdout || "[]");
    return Array.isArray(parsed)
      ? parsed.map((item) => item.Secret || "").filter((s) => s.length >= 8 && !isBenign(s))
      : [];
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
      const captured = match.slice(1, 4).find((g) => typeof g === "string" && g);
      if (captured && !isBenign(captured)) {
        return {
          category,
          detected: captured,
          sample: captured.length > 8 ? `${captured.slice(0, 4)}...${captured.slice(-4)}` : "[SECRET]",
        };
      }
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

export function redactSecrets(text, config = DEFAULT_CONFIG, useGitleaks = false) {
  if (typeof text !== "string" || !text) return text;
  let out = text;

  for (const { category, rx } of RULES) {
    rx.lastIndex = 0;
    out = out.replace(rx, (fullMatch, ...groups) => {
      const captured = groups.slice(0, 3).find((g) => typeof g === "string" && g);
      if (!captured || isBenign(captured)) return fullMatch;

      const idx = fullMatch.lastIndexOf(captured);
      if (idx === -1) return fullMatch;
      return (
        fullMatch.slice(0, idx) +
        tokenFor(captured, category) +
        fullMatch.slice(idx + captured.length)
      );
    });
  }

  if (useGitleaks && config.enableGitleaks && out.length >= config.gitleaksMinBytes) {
    const leaks = scanWithGitleaks(out, config.gitleaksTimeoutMs);
    for (const leak of leaks) {
      if (!isBenign(leak)) {
        out = out.split(leak).join(tokenFor(leak, "SECRET"));
      }
    }
  }

  return out;
}
