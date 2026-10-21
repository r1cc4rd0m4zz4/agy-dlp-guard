#!/usr/bin/env node

/**
 * agy-dlp-guard: PreToolUse Lifecycle Hook for Google Antigravity (AGY).
 *
 * Intercepts tool calls before execution to:
 * 1. Block access to sensitive paths (.env, SSH keys, cloud credentials, tokens).
 * 2. Prevent tampering with system configuration and hook files (integrity).
 * 3. Detect and block plaintext secret leakage in write_file, edit_file, bash commands, and outbound queries.
 * 4. Analyze bash command chains, tracking directories, variables, subshells, and unwrapping wrappers.
 *
 * Zero external dependencies.
 */

import * as fs from "node:fs";
import { loadConfig } from "../lib/config.mjs";
import { isPathProtected } from "../lib/path-guard.mjs";
import { checkBashCommand } from "../lib/bash-guard.mjs";
import { detectSecrets } from "../lib/secret-scanner.mjs";

function respond(decision, reason) {
  const payload = { decision };
  if (reason) payload.reason = reason;
  process.stdout.write(JSON.stringify(payload));
  process.exit(0);
}

function getCwd(payload) {
  if (Array.isArray(payload.workspacePaths) && payload.workspacePaths[0]) {
    return payload.workspacePaths[0];
  }
  return process.cwd();
}

export function findPaths(args) {
  const PATH_KEYS = [
    "Path",
    "path",
    "FilePath",
    "filePath",
    "file_path",
    "TargetFile",
    "targetFile",
    "target_file",
    "TargetPath",
    "targetPath",
    "target_path",
    "File",
    "file",
    "NotebookPath",
    "notebook_path",
    "Source",
    "source",
    "Destination",
    "destination",
    "Directory",
    "directory",
    "DirPath",
    "dirPath",
    "dir_path",
    "SearchPath",
    "searchPath",
    "search_path",
    "Paths",
    "paths",
    "Files",
    "files",
  ];

  const found = [];
  for (const k of PATH_KEYS) {
    if (args[k] !== undefined && args[k] !== null) {
      if (Array.isArray(args[k])) {
        for (const item of args[k]) {
          if (typeof item === "string" && item.trim()) found.push(item.trim());
        }
      } else if (typeof args[k] === "string" && args[k].trim()) {
        found.push(args[k].trim());
      }
    }
  }
  return found;
}

function extractReplacementTexts(args) {
  const chunks = [];
  for (const k of ["Replacement", "replacement", "ReplacementContent", "replacementContent", "Content", "content"]) {
    if (typeof args[k] === "string" && args[k]) {
      chunks.push(args[k]);
    }
  }
  const chunkList = args.ReplacementChunks || args.replacementChunks || args.edits || args.Edits;
  if (Array.isArray(chunkList)) {
    for (const c of chunkList) {
      if (c && typeof c === "object") {
        const text =
          c.ReplacementContent || c.replacementContent || c.Replacement || c.replacement || c.newText || "";
        if (typeof text === "string" && text) chunks.push(text);
      }
    }
  }
  return chunks.join("\n");
}

function main() {
  let stdinData = "";
  try {
    stdinData = fs.readFileSync(0, "utf-8");
  } catch {
    respond("allow");
    return;
  }

  if (!stdinData.trim()) {
    respond("allow");
    return;
  }

  let payload;
  try {
    payload = JSON.parse(stdinData);
  } catch {
    respond("allow");
    return;
  }

  const toolCall = payload.toolCall || {};
  const toolName = (toolCall.name || "").toLowerCase();
  const args = toolCall.args || {};
  const cwd = getCwd(payload);
  const config = loadConfig(cwd);

  if (!config.enabled) {
    respond("allow");
    return;
  }

  // 1. run_command (or bash)
  if (toolName === "run_command" || toolName === "bash") {
    const cmd = args.CommandLine || args.command || args.cmd || "";
    const res = checkBashCommand(cmd, config, cwd);
    if (res.block) {
      respond("deny", `🛑 [DLP Guard] ${res.reason}`);
      return;
    }
  }

  // 2. read_file / view_file / view_file_outline / view_code_item
  if (
    toolName === "read_file" ||
    toolName === "view_file" ||
    toolName === "view_file_outline" ||
    toolName === "view_code_item" ||
    toolName.startsWith("read")
  ) {
    const targetPaths = findPaths(args);
    for (const p of targetPaths) {
      const check = isPathProtected(p, config, cwd, "read");
      if (check.protected) {
        respond(
          "deny",
          `🛑 [DLP Guard] Lettura bloccata su ${p} (${check.reason})`
        );
        return;
      }
    }
  }

  // 3. write_file / create_file
  if (toolName === "write_file" || toolName === "create_file") {
    const targetPaths = findPaths(args);
    for (const p of targetPaths) {
      const check = isPathProtected(p, config, cwd, "write");
      if (check.protected) {
        respond(
          "deny",
          `🛑 [DLP Guard] Scrittura bloccata su ${p} (${check.reason})`
        );
        return;
      }
    }

    const content = args.Content || args.content || "";
    const secretHit = detectSecrets(content, config, true);
    if (secretHit) {
      const targetName = targetPaths[0] || "file";
      respond(
        "deny",
        `🛑 [DLP Guard] Scrittura bloccata su ${targetName}: rilevata credenziale o segreto in chiaro (${secretHit.category}).`
      );
      return;
    }
  }

  // 4. edit_file / replace_file_content / multi_replace_file_content / patch
  if (
    toolName === "edit_file" ||
    toolName === "replace" ||
    toolName === "replace_file_content" ||
    toolName === "multi_replace_file_content" ||
    toolName.includes("patch")
  ) {
    const targetPaths = findPaths(args);
    for (const p of targetPaths) {
      const check = isPathProtected(p, config, cwd, "write");
      if (check.protected) {
        respond(
          "deny",
          `🛑 [DLP Guard] Modifica bloccata su ${p} (${check.reason})`
        );
        return;
      }
    }

    const replacementText = extractReplacementTexts(args);
    const secretHit = detectSecrets(replacementText, config, true);
    if (secretHit) {
      const targetName = targetPaths[0] || "file";
      respond(
        "deny",
        `🛑 [DLP Guard] Modifica bloccata su ${targetName}: rilevata credenziale o segreto in chiaro nel blocco sostituito (${secretHit.category}).`
      );
      return;
    }
  }

  // 5. Outbound exfiltration guard on web search / URL fetch tools
  if (
    toolName === "search_web" ||
    toolName === "read_url_content" ||
    toolName.includes("fetch") ||
    toolName.includes("http")
  ) {
    const outboundText = [args.query, args.Query, args.url, args.Url, args.URL]
      .filter((v) => typeof v === "string" && v)
      .join(" ");
    if (outboundText) {
      const secretHit = detectSecrets(outboundText, config, false);
      if (secretHit) {
        respond(
          "deny",
          `🛑 [DLP Guard] Esfiltrazione bloccata in ${toolName}: rilevata credenziale o segreto nella richiesta esterna (${secretHit.category}).`
        );
        return;
      }
    }
  }

  // 6. Generic structured tools with file paths (MCP tools, grep_search, list_dir, etc.)
  const allPaths = findPaths(args);
  if (allPaths.length > 0) {
    const isWrite = /write|edit|replace|patch|create|delete|remove|move|rename|update/i.test(
      toolName
    );
    const op = isWrite ? "write" : "read";
    for (const p of allPaths) {
      const check = isPathProtected(p, config, cwd, op);
      if (check.protected) {
        respond(
          "deny",
          `🛑 [DLP Guard] Operazione bloccata su ${p} (${check.reason})`
        );
        return;
      }
    }
  }

  respond("allow");
}

main();
