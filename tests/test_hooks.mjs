import assert from "node:assert/strict";
import cp from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const testDir = path.dirname(fileURLToPath(import.meta.url));
const packageDir = path.resolve(testDir, "..");
const guardScript = path.join(packageDir, "hooks", "dlp-guard.mjs");
const sessionScript = path.join(packageDir, "hooks", "dlp-session-start.mjs");

function runHook(scriptPath, inputObj, customHome) {
  const res = cp.spawnSync("node", [scriptPath], {
    input: JSON.stringify(inputObj),
    encoding: "utf-8",
    timeout: 3000,
    env: customHome ? { ...process.env, HOME: customHome } : process.env,
  });
  assert.equal(res.status, 0, `Hook failed with error: ${res.stderr}`);
  return JSON.parse(res.stdout || "{}");
}

export async function runHookProtocolTests() {
  const cleanProjectDir = fs.mkdtempSync(path.join(os.tmpdir(), "clean-proj-"));
  const cleanHomeDir = fs.mkdtempSync(path.join(os.tmpdir(), "clean-home-"));
  const invoke = (script, payload) => runHook(script, payload, cleanHomeDir);

  try {
    // 1. SessionStart protocol
    const sessionOut = invoke(sessionScript, {
      conversationId: "test-conv-001",
      workspacePaths: [cleanProjectDir],
      modelName: "test-model",
    });
    assert.ok(Array.isArray(sessionOut.injectSteps), "SessionStart must return injectSteps array");
    assert.ok(sessionOut.injectSteps.length > 0, "injectSteps must not be empty");
    assert.match(
      sessionOut.injectSteps[0]?.systemMessage?.systemMessage || "",
      /DLP Guard/,
      "Session message must contain DLP Guard notice"
    );

    // 2. PreToolUse: run_command blocking malicious command
    const cmdDeny = invoke(guardScript, {
      toolCall: {
        name: "run_command",
        args: { CommandLine: "echo test > .env" },
      },
      workspacePaths: [cleanProjectDir],
    });
    assert.equal(cmdDeny.decision, "deny", "run_command targeting .env must be denied");
    assert.match(cmdDeny.reason || "", /DLP Guard/);

    // 3. PreToolUse: run_command allowing benign command
    const cmdAllow = invoke(guardScript, {
      toolCall: {
        name: "run_command",
        args: { CommandLine: "git status" },
      },
      workspacePaths: [cleanProjectDir],
    });
    assert.equal(cmdAllow.decision, "allow", "git status must be allowed");

    // 4. PreToolUse: read_file blocking protected path
    const readDeny = invoke(guardScript, {
      toolCall: {
        name: "read_file",
        args: { Path: ".env" },
      },
      workspacePaths: [cleanProjectDir],
    });
    assert.equal(readDeny.decision, "deny", "read_file on .env must be denied");

    // 5. PreToolUse: read_file allowing benign path
    const readAllow = invoke(guardScript, {
      toolCall: {
        name: "read_file",
        args: { Path: "package.json" },
      },
      workspacePaths: [cleanProjectDir],
    });
    assert.equal(readAllow.decision, "allow", "read_file on package.json must be allowed");

    // 6. PreToolUse: write_file blocking integrity path (guard's own package)
    const writeIntegrityDeny = invoke(guardScript, {
      toolCall: {
        name: "write_file",
        args: {
          Path: path.join(packageDir, "malicious.js"),
          Content: "console.log('tampered');",
        },
      },
      workspacePaths: [cleanProjectDir],
    });
    assert.equal(writeIntegrityDeny.decision, "deny", "write_file on integrity path must be denied");

    // 7. PreToolUse: write_file blocking plaintext secret
    const sampleToken = ["gh" + "p_", "1234567890".repeat(3), "123456"].join("");
    const writeSecretDeny = invoke(guardScript, {
      toolCall: {
        name: "write_file",
        args: {
          Path: "src/config.js",
          Content: 'const tok = "' + sampleToken + '";',
        },
      },
      workspacePaths: [cleanProjectDir],
    });
    assert.equal(writeSecretDeny.decision, "deny", "write_file containing secret must be denied");

    // 8. PreToolUse: edit_file blocking secret replacement
    const editSecretDeny = invoke(guardScript, {
      toolCall: {
        name: "edit_file",
        args: {
          Path: "src/config.js",
          Target: "const x = 1;",
          Replacement: 'const tok = "' + sampleToken + '";',
        },
      },
      workspacePaths: [cleanProjectDir],
    });
    assert.equal(editSecretDeny.decision, "deny", "edit_file with secret replacement must be denied");

    // 9. Regression test: edit_file where Target (old text snippet) is literally ".env" on a benign file (README.md) must be ALLOWED
    const editTargetSnippetAllow = invoke(guardScript, {
      toolCall: {
        name: "edit_file",
        args: {
          Path: "README.md",
          Target: ".env",
          Replacement: ".env.example",
        },
      },
      workspacePaths: [cleanProjectDir],
    });
    assert.equal(
      editTargetSnippetAllow.decision,
      "allow",
      "edit_file replacing text snippet '.env' inside README.md must be allowed"
    );

    // 10. PreToolUse: multi_replace_file_content blocking secret in ReplacementChunks
    const multiReplaceDeny = invoke(guardScript, {
      toolCall: {
        name: "multi_replace_file_content",
        args: {
          TargetFile: "src/config.js",
          ReplacementChunks: [
            { TargetContent: "const a = 1;", ReplacementContent: 'const k = "' + sampleToken + '";' },
          ],
        },
      },
      workspacePaths: [cleanProjectDir],
    });
    assert.equal(
      multiReplaceDeny.decision,
      "deny",
      "multi_replace_file_content with secret in ReplacementChunks must be denied"
    );

    // 11. PreToolUse: search_web exfiltration guard blocking secret in query
    const searchWebExfilDeny = invoke(guardScript, {
      toolCall: {
        name: "search_web",
        args: {
          query: "leak " + sampleToken,
        },
      },
      workspacePaths: [cleanProjectDir],
    });
    assert.equal(
      searchWebExfilDeny.decision,
      "deny",
      "search_web containing secret in query must be denied"
    );

    // 12. PreToolUse: clean write allowed in an ordinary project directory
    const cleanWrite = invoke(guardScript, {
      toolCall: {
        name: "write_file",
        args: { Path: "src/utils.js", Content: "export function add(a, b) { return a + b; }" },
      },
      workspacePaths: [cleanProjectDir],
    });
    assert.equal(cleanWrite.decision, "allow", "Clean write in project directory must be allowed");

    console.log("  ok   hooks protocol (all 12 assertion groups passed)");
    return true;
  } finally {
    fs.rmSync(cleanProjectDir, { recursive: true, force: true });
    fs.rmSync(cleanHomeDir, { recursive: true, force: true });
  }
}
