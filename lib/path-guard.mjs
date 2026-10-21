import * as fs from "node:fs";
import * as path from "node:path";
import { getHome, DEFAULT_CONFIG } from "./config.mjs";

export const TEMPLATE_ENV = /^\.env\.(?:example|sample|template|dist|default|schema)$/i;

const SAMPLE_SENSITIVE_BASENAMES = [
  ".env",
  ".env.local",
  ".env.production",
  ".envrc",
  "id_rsa",
  "id_ed25519",
  "id_ecdsa",
  "id_dsa",
  "private.key",
  "server.pem",
  "cert.p12",
  "cert.pfx",
  ".netrc",
  ".git-credentials",
  ".bashrc",
  ".zshrc",
  "auth.json",
];

export function expandHome(p, cwd = process.cwd()) {
  if (typeof p !== "string") return "";
  const home = getHome();
  return p
    .replace(/^(?:~|\$HOME|\$\{HOME\})(?=\/|$)/, home)
    .replace(/\$\{HOME\}|\$HOME\b/g, home)
    .replace(/^(?:~\+|\$PWD|\$\{PWD\})(?=\/|$)/, cwd)
    .replace(/\$\{PWD\}|\$PWD\b/g, cwd);
}

export function expandBraces(input, depth = 0) {
  if (typeof input !== "string" || depth > 4) return [input];
  const m = input.match(/^(.*?)\{([^{}]+)\}(.*)$/);
  if (!m) return [input];
  const [, prefix, body, suffix] = m;
  if (!body.includes(",")) return [input];
  return body
    .split(",")
    .slice(0, 16)
    .flatMap((part) => expandBraces(prefix + part + suffix, depth + 1));
}

export function globToRegExp(glob) {
  let s = "";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === "*" && glob[i + 1] === "*") {
      if (glob[i + 2] === "/") {
        s += "(?:.*/)?";
        i += 2;
      } else {
        s += ".*";
        i += 1;
      }
    } else if (c === "*") {
      s += "[^/]*";
    } else {
      s += c.replace(/[.+^${}()|[\]\\?]/g, "\\$&");
    }
  }
  return new RegExp(`^${s}$`, "i");
}

export function shellWildcardToRegExp(pat) {
  let s = "";
  for (let i = 0; i < pat.length; i++) {
    const c = pat[i];
    if (c === "*") {
      s += "[^/]*";
    } else if (c === "?") {
      s += "[^/]";
    } else if (c === "[") {
      const close = pat.indexOf("]", i + 1);
      if (close !== -1) {
        const inner = pat.slice(i + 1, close).replace(/\\/g, "\\\\");
        s += `[${inner}]`;
        i = close;
      } else {
        s += "\\[";
      }
    } else {
      s += c.replace(/[.+^${}()|\\]/g, "\\$&");
    }
  }
  return new RegExp(`^${s}$`, "i");
}

export function canonical(p, depth = 0) {
  try {
    return fs.realpathSync(p);
  } catch {
    // Path does not exist as-is
  }

  try {
    if (depth < 8 && fs.lstatSync(p).isSymbolicLink()) {
      const linkTarget = fs.readlinkSync(p);
      const resolvedTarget = path.isAbsolute(linkTarget)
        ? linkTarget
        : path.resolve(path.dirname(p), linkTarget);
      return canonical(resolvedTarget, depth + 1);
    }
  } catch {
    // lstat failed
  }

  const parent = path.dirname(p);
  return parent === p ? p : path.join(canonical(parent, depth), path.basename(p));
}

export function matchesPattern(pattern, absPath, cwd) {
  let g = expandHome(pattern.replace(/\\/g, "/"), cwd);
  const normalizedAbs = absPath.replace(/\\/g, "/");

  // A pattern without slash matches only the basename (e.g. ".env" or "*.pem")
  if (!g.includes("/")) {
    return globToRegExp(g).test(path.basename(normalizedAbs));
  }

  // Relative pattern: qualify against cwd
  if (!g.startsWith("/") && !g.startsWith("**")) {
    g = `${cwd.replace(/\\/g, "/")}/${g}`;
  }

  if (globToRegExp(g).test(normalizedAbs)) return true;
  if (g.endsWith("/**") && globToRegExp(g.slice(0, -3)).test(normalizedAbs)) return true;

  // Handle canonical symlink prefixes (e.g. /var -> /private/var on macOS)
  const prefix = g.replace(/\/\*\*?.*$/, "");
  const canonPrefix = canonical(prefix).replace(/\\/g, "/");
  if (canonPrefix !== prefix) {
    const gCanon = canonPrefix + g.slice(prefix.length);
    if (globToRegExp(gCanon).test(normalizedAbs)) return true;
    if (gCanon.endsWith("/**") && globToRegExp(gCanon.slice(0, -3)).test(normalizedAbs)) return true;
  }

  return false;
}

function checkSinglePath(cleaned, config, cwd, op, allowWildcardExpand = true) {
  const expanded = expandHome(cleaned, cwd);
  const lexical = path.resolve(cwd, expanded);
  const canon = canonical(lexical);

  const isEnvTemplate =
    TEMPLATE_ENV.test(path.basename(lexical)) &&
    TEMPLATE_ENV.test(path.basename(canon));

  const protectedList = isEnvTemplate ? [] : config.protectedPaths || [];
  const integrityList = op === "write" ? config.integrityPaths || [] : [];

  for (const abs of new Set([lexical, canon])) {
    const norm = abs.replace(/\\/g, "/");

    const hitProtected = protectedList.find((p) => matchesPattern(p, norm, cwd));
    if (hitProtected) {
      return {
        protected: true,
        reason: `percorso sensibile protetto "${hitProtected}"`,
      };
    }

    const hitIntegrity = integrityList.find((p) => matchesPattern(p, norm, cwd));
    if (hitIntegrity) {
      return {
        protected: true,
        reason: `integrità del sistema: scrittura/modifica vietata su "${hitIntegrity}"`,
      };
    }
  }

  // Shell wildcard / glob defense (e.g., .en?, .e*, [.]env, id_*)
  const base = path.basename(lexical);
  if (allowWildcardExpand && /[*?[\]]/.test(base)) {
    const wildRx = shellWildcardToRegExp(base);
    const parentDir = path.dirname(lexical);

    // 1. Check actual files on disk in parentDir that match the wildcard
    try {
      if (fs.existsSync(parentDir) && fs.statSync(parentDir).isDirectory()) {
        for (const entry of fs.readdirSync(parentDir)) {
          if (wildRx.test(entry)) {
            const candidate = path.join(parentDir, entry);
            const sub = checkSinglePath(candidate, config, cwd, op, false);
            if (sub.protected) return sub;
          }
        }
      }
    } catch {
      // Ignore directory read errors
    }

    // 2. Check non-trivial wildcards against canonical sensitive basenames
    const nonWildChars = base.replace(/[*?[\]]/g, "");
    if (nonWildChars.length >= 2 || base.startsWith(".")) {
      for (const sample of SAMPLE_SENSITIVE_BASENAMES) {
        if (wildRx.test(sample)) {
          const candidate = path.join(parentDir, sample);
          const sub = checkSinglePath(candidate, config, cwd, op, false);
          if (sub.protected) return sub;
        }
      }
    }
  }

  return { protected: false };
}

export function isPathProtected(
  targetPath,
  config = DEFAULT_CONFIG,
  cwd = process.cwd(),
  op = "read"
) {
  if (typeof targetPath !== "string" || !targetPath.trim()) {
    return { protected: false };
  }

  // Defend against null byte injection
  if (targetPath.includes("\0")) {
    return {
      protected: true,
      reason: "rilevato carattere nullo (null-byte injection attempt)",
    };
  }

  let cleaned = targetPath.trim();

  // Defend against single and double URL-encoded path traversal attacks
  for (let pass = 0; pass < 2; pass++) {
    try {
      if (/%[0-9a-fA-F]{2}/.test(cleaned)) {
        const decoded = decodeURIComponent(cleaned);
        if (decoded === cleaned) break;
        cleaned = decoded;
      } else {
        break;
      }
    } catch {
      break;
    }
  }

  if (cleaned.includes("\0")) {
    return {
      protected: true,
      reason: "rilevato carattere nullo (null-byte injection attempt)",
    };
  }

  // Expand shell brace expressions like .{env,env.local}
  for (const variant of expandBraces(cleaned)) {
    const res = checkSinglePath(variant, config, cwd, op, true);
    if (res.protected) return res;
  }

  return { protected: false };
}
