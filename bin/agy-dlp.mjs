#!/usr/bin/env node

/**
 * agy-dlp: Command Line Interface for Antigravity DLP Guard
 *
 * Commands:
 *   status                 Display current configuration and hook registration status
 *   install [--global|--workspace]
 *                          Install and register hooks in Antigravity configuration
 *   uninstall [--global|--workspace]
 *                          Remove hooks registration from Antigravity configuration
 *   toggle <on|off>        Enable or disable DLP guard controls (live + hooks.json)
 *   scan <file|cmd|string> Test DLP rules against a file path, command, or string
 *   test                   Execute the regression test suite
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as cp from "node:child_process";
import { fileURLToPath } from "node:url";
import { loadConfig, getHome, DEFAULT_CONFIG } from "../lib/config.mjs";
import { isPathProtected } from "../lib/path-guard.mjs";
import { checkBashCommand } from "../lib/bash-guard.mjs";
import { detectSecrets, hasGitleaks } from "../lib/secret-scanner.mjs";

const packageDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function getHooksJsonPath(isWorkspace) {
  if (isWorkspace) {
    return path.join(process.cwd(), ".agents", "hooks.json");
  }
  return path.join(getHome(), ".gemini", "config", "hooks.json");
}

function getDlpConfigPath(isWorkspace) {
  if (isWorkspace) {
    return path.join(process.cwd(), ".agents", "dlp-guard.json");
  }
  return path.join(getHome(), ".gemini", "config", "dlp-guard.json");
}

function showHelp() {
  console.log(`
agy-dlp-guard 🛡️  Antigravity DLP Guard Management CLI

Usage:
  agy-dlp <command> [options]

Commands:
  status                     Show DLP status, loaded config, and hook registration
  install [--global|--workspace]
                             Install and register DLP hooks in Antigravity
  uninstall [--global|--workspace]
                             Remove DLP hooks from Antigravity hooks.json
  toggle <on|off>            Enable or disable DLP guard (takes effect live)
  scan <path|command|text>   Test whether a path, command, or content is blocked
  test                       Run test suite

Options:
  --global     Operate on global ~/.gemini/config/ (default)
  --workspace  Operate on current workspace .agents/
`);
}

function cmdStatus(isWorkspace) {
  const hooksFile = getHooksJsonPath(isWorkspace);
  const cfg = loadConfig(process.cwd());

  let registered = false;
  let hookEnabled = false;

  if (fs.existsSync(hooksFile)) {
    try {
      const hooksData = JSON.parse(fs.readFileSync(hooksFile, "utf-8"));
      if (hooksData["dlp-guard"]) {
        registered = true;
        hookEnabled = hooksData["dlp-guard"].enabled !== false;
      }
    } catch {}
  }

  const effectivelyActive = cfg.enabled && (!registered || hookEnabled);

  console.log("==================================================");
  console.log("🛡️  Antigravity DLP Guard (agy-dlp-guard) Status");
  console.log("==================================================");
  console.log(`Guard State:         ${effectivelyActive ? "ACTIVE (Attivo)" : "DISABLED (Disattivato)"}`);
  console.log(`Config Source:       ${cfg.loadedFrom || "Default built-in values"}`);
  console.log(`Hooks Target:        ${hooksFile}`);
  console.log(`Registered in hooks: ${registered ? (hookEnabled ? "YES (Attivo)" : "YES (Disabilitato)") : "NO"}`);
  console.log(`Protected Paths:     ${cfg.protectedPaths.length} patterns`);
  console.log(`Integrity Paths:     ${cfg.integrityPaths.length} patterns`);
  console.log(
    `Gitleaks Engine:     ${
      cfg.enableGitleaks
        ? hasGitleaks()
          ? "AVAILABLE (nel PATH)"
          : "NOT FOUND (solo regex native)"
        : "DISABLED"
    }`
  );
  console.log(`Inline Cmd Secrets:  ${cfg.blockInlineSecretsInCommands ? "BLOCKED" : "ALLOWED"}`);
  console.log(`Protected Readers:   ${cfg.blockReaderCommandsOnProtected ? "BLOCKED" : "ALLOWED"}`);
  console.log("==================================================");
}

function cmdInstall(isWorkspace) {
  const hooksFile = getHooksJsonPath(isWorkspace);
  const targetDir = path.dirname(hooksFile);

  if (!fs.existsSync(targetDir)) {
    fs.mkdirSync(targetDir, { recursive: true });
  }

  let hooksData = {};
  if (fs.existsSync(hooksFile)) {
    try {
      hooksData = JSON.parse(fs.readFileSync(hooksFile, "utf-8"));
      fs.copyFileSync(hooksFile, `${hooksFile}.bak`);
    } catch {
      hooksData = {};
    }
  }

  const guardScript = path.join(packageDir, "hooks", "dlp-guard.mjs");
  const sessionScript = path.join(packageDir, "hooks", "dlp-session-start.mjs");

  hooksData["dlp-guard"] = {
    enabled: true,
    SessionStart: [
      {
        type: "command",
        command: `node "${sessionScript}"`,
      },
    ],
    PreToolUse: [
      {
        matcher: "*",
        hooks: [
          {
            type: "command",
            command: `node "${guardScript}"`,
            timeout: 5,
          },
        ],
      },
    ],
  };

  fs.writeFileSync(hooksFile, JSON.stringify(hooksData, null, 2) + "\n", "utf-8");
  console.log(`✅ Hook di agy-dlp-guard registrato con successo in:`);
  console.log(`   ${hooksFile}`);
  if (fs.existsSync(`${hooksFile}.bak`)) {
    console.log(`   (Backup creato in ${hooksFile}.bak)`);
  }
}

function cmdUninstall(isWorkspace) {
  const hooksFile = getHooksJsonPath(isWorkspace);
  if (!fs.existsSync(hooksFile)) {
    console.log(`Nessun file hooks trovato in: ${hooksFile}`);
    return;
  }

  try {
    const hooksData = JSON.parse(fs.readFileSync(hooksFile, "utf-8"));
    if (hooksData["dlp-guard"]) {
      delete hooksData["dlp-guard"];
      fs.writeFileSync(hooksFile, JSON.stringify(hooksData, null, 2) + "\n", "utf-8");
      console.log(`✅ Hook rimosso con successo da: ${hooksFile}`);
    } else {
      console.log(`L'hook dlp-guard non era presente in: ${hooksFile}`);
    }
  } catch (err) {
    console.error(`Errore durante la disinstallazione: ${err.message}`);
  }
}

function cmdToggle(state, isWorkspace) {
  const normalized = (state || "").trim().toLowerCase();
  if (normalized !== "on" && normalized !== "off") {
    console.error("Specificare 'on' oppure 'off' (es. agy-dlp toggle off).");
    process.exit(1);
  }
  const enabled = normalized === "on";

  // 1. Update hooks.json if present
  const hooksFile = getHooksJsonPath(isWorkspace);
  if (fs.existsSync(hooksFile)) {
    try {
      const hooksData = JSON.parse(fs.readFileSync(hooksFile, "utf-8"));
      if (hooksData["dlp-guard"]) {
        hooksData["dlp-guard"].enabled = enabled;
        fs.writeFileSync(hooksFile, JSON.stringify(hooksData, null, 2) + "\n", "utf-8");
      }
    } catch {}
  }

  // 2. Update dlp-guard.json so the change takes effect immediately on the next tool call
  const cfgFile = getDlpConfigPath(isWorkspace);
  const cfgDir = path.dirname(cfgFile);
  if (!fs.existsSync(cfgDir)) {
    fs.mkdirSync(cfgDir, { recursive: true });
  }
  let cfgData = {};
  if (fs.existsSync(cfgFile)) {
    try {
      cfgData = JSON.parse(fs.readFileSync(cfgFile, "utf-8"));
    } catch {
      cfgData = {};
    }
  }
  cfgData.enabled = enabled;
  fs.writeFileSync(cfgFile, JSON.stringify(cfgData, null, 2) + "\n", "utf-8");

  console.log(`✅ [DLP Guard] Impostato su: ${enabled ? "ATTIVO" : "DISATTIVATO"} (live in ${cfgFile})`);
}

function cmdScan(input) {
  if (!input) {
    console.log("Specificare una stringa, comando o percorso da testare.");
    return;
  }

  const cfg = loadConfig(process.cwd());
  console.log(`🔍 Analisi di: "${input}"`);

  // Check 1: Path test
  const pathRead = isPathProtected(input, cfg, process.cwd(), "read");
  const pathWrite = isPathProtected(input, cfg, process.cwd(), "write");

  if (pathRead.protected) {
    console.log(`🛑 [Path Guard - READ]: BLOCCATO (${pathRead.reason})`);
  } else {
    console.log(`✅ [Path Guard - READ]: CONSENTITO`);
  }

  if (pathWrite.protected) {
    console.log(`🛑 [Path Guard - WRITE]: BLOCCATO (${pathWrite.reason})`);
  } else {
    console.log(`✅ [Path Guard - WRITE]: CONSENTITO`);
  }

  // Check 2: Bash test
  const bashRes = checkBashCommand(input, cfg, process.cwd());
  if (bashRes.block) {
    console.log(`🛑 [Bash Guard]: BLOCCATO (${bashRes.reason})`);
  } else {
    console.log(`✅ [Bash Guard]: CONSENTITO`);
  }

  // Check 3: Secret test
  const secretHit = detectSecrets(input, cfg, true);
  if (secretHit) {
    console.log(`🛑 [Secret Scanner]: SEGRETO RILEVATO (${secretHit.category})`);
  } else {
    console.log(`✅ [Secret Scanner]: NESSUN SEGRETO RILEVATO`);
  }
}

function cmdTest() {
  const runner = path.join(packageDir, "tests", "run_all.mjs");
  const res = cp.spawnSync("node", [runner], { stdio: "inherit" });
  process.exit(res.status ?? 0);
}

function main() {
  const args = process.argv.slice(2);
  const cmd = args[0] || "status";
  const isWorkspace = args.includes("--workspace");

  switch (cmd) {
    case "status":
      cmdStatus(isWorkspace);
      break;
    case "install":
      cmdInstall(isWorkspace);
      break;
    case "uninstall":
      cmdUninstall(isWorkspace);
      break;
    case "toggle":
      cmdToggle(args[1], isWorkspace);
      break;
    case "scan":
      cmdScan(
        args
          .slice(1)
          .filter((a) => !a.startsWith("--"))
          .join(" ")
      );
      break;
    case "test":
      cmdTest();
      break;
    case "--help":
    case "-h":
    case "help":
      showHelp();
      break;
    default:
      console.error(`Comando sconosciuto: ${cmd}`);
      showHelp();
      process.exit(1);
  }
}

main();
