#!/usr/bin/env node

/**
 * agy-dlp-guard: SessionStart Lifecycle Hook for Google Antigravity (AGY).
 *
 * Injects session security posture notice at conversation start.
 */

import * as fs from "node:fs";
import { loadConfig } from "../lib/config.mjs";
import { hasGitleaks } from "../lib/secret-scanner.mjs";

function main() {
  let stdinData = "";
  try {
    stdinData = fs.readFileSync(0, "utf-8");
  } catch {}

  let cwd = process.cwd();
  if (stdinData.trim()) {
    try {
      const payload = JSON.parse(stdinData);
      if (Array.isArray(payload.workspacePaths) && payload.workspacePaths[0]) {
        cwd = payload.workspacePaths[0];
      } else if (payload.cwd) {
        cwd = payload.cwd;
      }
    } catch {}
  }

  const config = loadConfig(cwd);
  if (!config.enabled) {
    process.stdout.write(JSON.stringify({ injectSteps: [] }));
    process.exit(0);
  }

  const gitleaksStatus = config.enableGitleaks
    ? (hasGitleaks() ? "Gitleaks attivo + Regex native" : "Regex native (Gitleaks non nel PATH)")
    : "Solo regex native (Gitleaks disabilitato)";

  const msg = [
    "🛡️ [DLP Guard] Antigravity Hook attivo (v2 Hardened).",
    "• Protezione percorsi sensibili (.env*, chiavi SSH/GPG/Age, credenziali cloud/K8s/Terraform, rc files) abilitata.",
    "• Difesa anti-manomissione (integrità configurazioni, hook di sicurezza e CLI) abilitata.",
    "• Ispezione profonda comandi shell (catene &&, subshell, gruppi, redirezioni, variabili, wildcard, interpreti) attiva.",
    `• Motore di rilevamento segreti: ${gitleaksStatus}.`,
  ].join("\n");

  process.stdout.write(
    JSON.stringify({
      injectSteps: [
        {
          systemMessage: {
            systemMessage: msg,
          },
        },
      ],
    })
  );
  process.exit(0);
}

main();
