#!/usr/bin/env node
/**
 * Test runner for agy-dlp-guard
 */

import { runPathGuardTests } from "./test_path_guard.mjs";
import { runBashGuardTests } from "./test_bash_guard.mjs";
import { runSecretScannerTests } from "./test_secret_scanner.mjs";
import { runHookProtocolTests } from "./test_hooks.mjs";

const SUITES = [
  { name: "Path & Traversal Guard", fn: runPathGuardTests },
  { name: "Bash Command & Obfuscation Guard", fn: runBashGuardTests },
  { name: "Secret Scanner & Redaction Engine", fn: runSecretScannerTests },
  { name: "Antigravity Hook Lifecycle & Protocol", fn: runHookProtocolTests },
];

let failed = 0;

console.log("==================================================");
console.log("🛡️  agy-dlp-guard — Full Security Regression Suite");
console.log("==================================================\n");

for (const suite of SUITES) {
  console.log(`▶ Running ${suite.name}...`);
  try {
    await suite.fn();
  } catch (err) {
    failed++;
    console.error(`  FAIL ${suite.name}:`, err?.stack || err);
  }
}

console.log("");
if (failed > 0) {
  console.error(`❌ ${failed} test suite(s) failed.`);
  process.exit(1);
} else {
  console.log("✅ All 4 security test suites passed with 0 errors!");
  process.exit(0);
}
