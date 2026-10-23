import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { fileURLToPath } from "node:url";

export const BASE_HOME = (() => {
  try {
    return fs.realpathSync(os.homedir());
  } catch {
    return os.homedir();
  }
})();

export function getHome() {
  return process.env.HOME || BASE_HOME;
}

export const HOME = BASE_HOME;

let packageDir = "";
try {
  packageDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
} catch {
  // Fallback if import.meta.url is not resolvable
}

export const PACKAGE_DIR = packageDir;

export const DEFAULT_CONFIG = {
  enabled: true,
  protectedPaths: [
    ".env",
    ".env.*",
    "*.env",
    ".envrc",
    "**/.git/**",
    "~/.ssh/**",
    "/etc/ssh/**",
    "/etc/shadow*",
    "/etc/gshadow*",
    "/etc/sudoers*",
    "~/.aws/**",
    "~/.config/gcloud/**",
    "~/.gcp/**",
    "~/.azure/**",
    "~/.oci/**",
    "~/.gnupg/**",
    "~/.password-store/**",
    "~/.local/share/keyrings/**",
    "~/Library/Keychains/**",
    "~/.config/gh/**",
    "~/.config/glab-cli/**",
    "~/.config/op/**",
    "~/.op/**",
    "~/.config/sops/**",
    "~/.config/age/**",
    "~/.kube/**",
    "~/.docker/config.json",
    "~/.terraform.d/**",
    "**/*.tfstate",
    "**/*.tfstate.*",
    "**/*.tfvars",
    "~/.vault-token",
    "~/.netrc",
    "~/.git-credentials",
    "~/.npmrc",
    "~/.pypirc",
    "~/.gem/credentials",
    "~/.cargo/credentials*",
    "~/.composer/auth.json",
    "~/.zshrc*",
    "~/.zprofile",
    "~/.zshenv",
    "~/.zsh_history",
    "~/.bashrc*",
    "~/.bash_profile",
    "~/.bash_history",
    "~/.profile",
    "**/*rc.local",
    "**/*.pem",
    "**/*.key",
    "**/*.pkcs12",
    "**/*.pfx",
    "**/*.p12",
    "**/*.jks",
    "**/*.keystore",
    "**/*.age",
    "**/id_rsa*",
    "**/id_ed25519*",
    "**/id_ecdsa*",
    "**/id_dsa*",
    "~/.pi/agent/auth.json",
    "~/.claude/.credentials.json",
  ],
  integrityPaths: [
    "~/.pi/agent/**",
    "**/.pi/agent/**",
    "~/.gemini/config/**",
    "**/.gemini/config/**",
    "~/.gemini/antigravity-cli/**",
    "~/.gemini/antigravity/**",
    "~/.gemini/antigravity-ide/**",
    ".agents/**",
    ".agent/**",
    "_agents/**",
    "_agent/**",
    "**/dlp-guard.json",
    ...(packageDir ? [`${packageDir}/**`] : []),
  ],
  enableGitleaks: true,
  gitleaksMinBytes: 4096,
  gitleaksTimeoutMs: 500,
  blockInlineSecretsInCommands: true,
  blockReaderCommandsOnProtected: true,
};

export function getConfigCandidates(cwd = process.cwd()) {
  const home = getHome();
  return [
    { file: path.join(cwd, ".agents", "dlp-guard.json"), trusted: false },
    { file: path.join(cwd, ".agent", "dlp-guard.json"), trusted: false },
    { file: path.join(cwd, ".pi", "dlp-guard.json"), trusted: false },
    { file: path.join(home, ".gemini", "config", "dlp-guard.json"), trusted: true },
    { file: path.join(home, ".pi", "agent", "dlp-guard.json"), trusted: true },
  ];
}

export function getConfigPaths(cwd = process.cwd()) {
  return getConfigCandidates(cwd).map((c) => c.file);
}

export function loadConfig(cwd = process.cwd()) {
  for (const { file: cfgPath, trusted } of getConfigCandidates(cwd)) {
    try {
      if (fs.existsSync(cfgPath)) {
        const raw = fs.readFileSync(cfgPath, "utf-8");
        const parsed = JSON.parse(raw);
        const list = (v, d) => (Array.isArray(v) && v.every((s) => typeof s === "string") ? v : d);
        const num = (v, d) => (typeof v === "number" && v >= 0 ? v : d);
        const bool = (v, d) => (typeof v === "boolean" ? v : d);
        const userProtected = list(parsed.protectedPaths, DEFAULT_CONFIG.protectedPaths);
        const userIntegrity = list(parsed.integrityPaths, DEFAULT_CONFIG.integrityPaths);

        return {
          // Untrusted workspace configs cannot disable the guard or weaken built-in protections
          enabled: trusted ? bool(parsed.enabled, DEFAULT_CONFIG.enabled) : true,
          protectedPaths: trusted
            ? userProtected
            : Array.from(new Set([...DEFAULT_CONFIG.protectedPaths, ...userProtected])),
          integrityPaths: Array.from(
            new Set([
              ...(trusted ? userIntegrity : [...DEFAULT_CONFIG.integrityPaths, ...userIntegrity]),
              "**/dlp-guard.json",
              ...(packageDir ? [`${packageDir}/**`] : []),
            ])
          ),
          enableGitleaks: trusted ? bool(parsed.enableGitleaks, DEFAULT_CONFIG.enableGitleaks) : true,
          gitleaksMinBytes: num(parsed.gitleaksMinBytes, DEFAULT_CONFIG.gitleaksMinBytes),
          gitleaksTimeoutMs: num(parsed.gitleaksTimeoutMs, DEFAULT_CONFIG.gitleaksTimeoutMs),
          blockInlineSecretsInCommands: trusted
            ? bool(parsed.blockInlineSecretsInCommands, DEFAULT_CONFIG.blockInlineSecretsInCommands)
            : true,
          blockReaderCommandsOnProtected: trusted
            ? bool(parsed.blockReaderCommandsOnProtected, DEFAULT_CONFIG.blockReaderCommandsOnProtected)
            : true,
          loadedFrom: cfgPath,
        };
      }
    } catch {
      // Continue to next candidate
    }
  }

  return {
    ...DEFAULT_CONFIG,
    integrityPaths: Array.from(
      new Set([
        ...DEFAULT_CONFIG.integrityPaths,
        ...(packageDir ? [`${packageDir}/**`] : []),
      ])
    ),
    loadedFrom: null,
  };
}
