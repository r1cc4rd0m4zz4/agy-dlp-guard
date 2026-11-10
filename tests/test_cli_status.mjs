import assert from "node:assert/strict";
import cp from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const testDir = path.dirname(fileURLToPath(import.meta.url));
const packageDir = path.resolve(testDir, "..");
const cliScript = path.join(packageDir, "bin", "agy-dlp.mjs");

export async function runCliStatusTests() {
  const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), "dlp-cli-home-"));
  const tmpProj = fs.mkdtempSync(path.join(os.tmpdir(), "dlp-cli-proj-"));

  try {
    // Scenario 1: Neither monolithic hooks.json nor plugin enabled -> Registered: NO
    const res1 = cp.spawnSync("node", [cliScript, "status"], {
      cwd: tmpProj,
      env: { ...process.env, HOME: tmpHome },
      encoding: "utf-8",
    });
    assert.equal(res1.status, 0, `CLI status exited with non-zero: ${res1.stderr}`);
    assert.match(res1.stdout, /Registered in hooks:\s+NO/);

    // Scenario 2: Active via Antigravity Plugin Engine (config.json has plugins.agy-dlp-guard.enabled = true)
    const geminiCfgDir = path.join(tmpHome, ".gemini", "config");
    fs.mkdirSync(geminiCfgDir, { recursive: true });
    fs.writeFileSync(
      path.join(geminiCfgDir, "config.json"),
      JSON.stringify({ plugins: { "agy-dlp-guard": { enabled: true } } }, null, 2)
    );

    const res2 = cp.spawnSync("node", [cliScript, "status"], {
      cwd: tmpProj,
      env: { ...process.env, HOME: tmpHome },
      encoding: "utf-8",
    });
    assert.equal(res2.status, 0);
    assert.match(
      res2.stdout,
      /Registered in hooks:\s+YES \(via Antigravity Plugin Engine\)/,
      "CLI status must report active when enabled in Antigravity plugin config"
    );

    // Scenario 3: Explicitly disabled in plugin engine
    fs.writeFileSync(
      path.join(geminiCfgDir, "config.json"),
      JSON.stringify({ plugins: { "agy-dlp-guard": { enabled: false } } }, null, 2)
    );
    const res3 = cp.spawnSync("node", [cliScript, "status"], {
      cwd: tmpProj,
      env: { ...process.env, HOME: tmpHome },
      encoding: "utf-8",
    });
    assert.equal(res3.status, 0);
    assert.match(
      res3.stdout,
      /Registered in hooks:\s+DISABLED \(via Antigravity Plugin Engine\)/,
      "CLI status must report disabled when turned off in plugin config"
    );

    // Scenario 4: Registered via monolithic hooks.json fallback
    fs.unlinkSync(path.join(geminiCfgDir, "config.json"));
    fs.writeFileSync(
      path.join(geminiCfgDir, "hooks.json"),
      JSON.stringify({ "dlp-guard": { enabled: true } }, null, 2)
    );
    const res4 = cp.spawnSync("node", [cliScript, "status"], {
      cwd: tmpProj,
      env: { ...process.env, HOME: tmpHome },
      encoding: "utf-8",
    });
    assert.equal(res4.status, 0);
    assert.match(
      res4.stdout,
      /Registered in hooks:\s+YES \(via hooks\.json\)/,
      "CLI status must report active via hooks.json fallback"
    );

    console.log("  ok   cli status detection (all 4 assertion groups passed)");
    return true;
  } finally {
    fs.rmSync(tmpHome, { recursive: true, force: true });
    fs.rmSync(tmpProj, { recursive: true, force: true });
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  runCliStatusTests().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
