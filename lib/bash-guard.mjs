import * as path from "node:path";
import { isPathProtected, expandHome } from "./path-guard.mjs";
import { detectSecrets } from "./secret-scanner.mjs";
import { DEFAULT_CONFIG } from "./config.mjs";

export function decodeAnsiC(str) {
  return str
    .replace(/\\x([0-9a-fA-F]{1,2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/\\u([0-9a-fA-F]{1,4})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/\\0?([0-7]{1,3})/g, (_, o) => String.fromCharCode(parseInt(o, 8)))
    .replace(/\\n/g, "\n")
    .replace(/\\r/g, "\r")
    .replace(/\\t/g, "\t")
    .replace(/\\(['"\\])/g, "$1");
}

export function parseSegments(cmd) {
  const segments = [];
  let currentSeg = { words: [], redirects: [], inputRedirects: [], pipedToNext: false };
  let curWord = "";
  let hasWord = false;
  let quoteChar = "";
  let ansiC = false;
  let ansiBuf = "";
  let redirMode = null; // "write" | "read" | null

  const pushWord = () => {
    if (hasWord) {
      if (redirMode === "write") currentSeg.redirects.push(curWord);
      else if (redirMode === "read") currentSeg.inputRedirects.push(curWord);
      else currentSeg.words.push(curWord);
      redirMode = null;
      curWord = "";
      hasWord = false;
    }
  };

  const pushSegment = (isPipe = false) => {
    pushWord();
    redirMode = null;
    while (currentSeg.words[0] === "{") currentSeg.words.shift();
    while (currentSeg.words[currentSeg.words.length - 1] === "}") currentSeg.words.pop();
    if (
      currentSeg.words.length > 0 ||
      currentSeg.redirects.length > 0 ||
      currentSeg.inputRedirects.length > 0
    ) {
      currentSeg.pipedToNext = isPipe;
      segments.push(currentSeg);
    }
    currentSeg = { words: [], redirects: [], inputRedirects: [], pipedToNext: false };
  };

  for (let i = 0; i < cmd.length; i++) {
    const ch = cmd[i];
    if (!quoteChar && (cmd.startsWith("$IFS", i) || cmd.startsWith("${IFS}", i))) {
      pushWord();
      i += cmd[i + 1] === "{" ? 5 : 3;
      continue;
    }
    if (quoteChar) {
      if (ch === quoteChar) {
        if (ansiC) {
          curWord += decodeAnsiC(ansiBuf);
          ansiBuf = "";
          ansiC = false;
        }
        quoteChar = "";
      } else if (ansiC) {
        if (ch === "\\" && i + 1 < cmd.length) {
          ansiBuf += ch + cmd[++i];
        } else {
          ansiBuf += ch;
        }
      } else if (ch === "\\" && quoteChar === '"' && i + 1 < cmd.length) {
        curWord += cmd[++i];
      } else {
        curWord += ch;
      }
    } else if (ch === "$" && (cmd[i + 1] === "'" || cmd[i + 1] === '"')) {
      quoteChar = cmd[++i];
      ansiC = quoteChar === "'";
      ansiBuf = "";
      hasWord = true;
    } else if (ch === "$" && cmd[i + 1] === "(") {
      let depth = 1;
      curWord += "$(";
      hasWord = true;
      i += 2;
      while (i < cmd.length && depth > 0) {
        if (cmd[i] === "(") depth++;
        else if (cmd[i] === ")") depth--;
        curWord += cmd[i++];
      }
      i--;
    } else if (ch === "'" || ch === '"') {
      quoteChar = ch;
      hasWord = true;
    } else if (ch === "\\" && i + 1 < cmd.length) {
      curWord += cmd[++i];
      hasWord = true;
    } else if (ch === "(" || ch === ")") {
      pushSegment(false);
    } else if (ch === "|" && cmd[i + 1] !== "|") {
      pushSegment(true);
    } else if (ch === "|" && cmd[i + 1] === "|") {
      i++;
      pushSegment(false);
    } else if (ch === ";" || ch === "\n") {
      pushSegment(false);
    } else if (ch === "&") {
      const prev = cmd[i - 1];
      const next = cmd[i + 1];
      if (next === "&") {
        i++;
        pushSegment(false);
      } else if (next === ">") {
        pushWord();
        i++;
        if (cmd[i + 1] === ">") i++;
        redirMode = "write";
      } else if (prev === ">" || prev === "<") {
        if (/[0-9-]/.test(next || "")) {
          curWord += ch;
          hasWord = true;
        } else {
          redirMode = "write";
        }
      } else {
        pushSegment(false);
      }
    } else if (ch === ">") {
      if (hasWord && /^[0-9]+$/.test(curWord)) {
        curWord = "";
        hasWord = false;
      } else {
        pushWord();
      }
      if (cmd[i + 1] === ">" || cmd[i + 1] === "|") i++;
      if (cmd[i + 1] === "(") {
        pushSegment(false);
      } else {
        redirMode = "write";
      }
    } else if (ch === "<") {
      if (hasWord && /^[0-9]+$/.test(curWord)) {
        curWord = "";
        hasWord = false;
      } else {
        pushWord();
      }
      if (cmd[i + 1] === "<") {
        i++;
        if (cmd[i + 1] === "<") i++;
        redirMode = null;
      } else if (cmd[i + 1] === ">") {
        i++;
        redirMode = "write";
      } else if (cmd[i + 1] === "(") {
        pushSegment(false);
      } else {
        redirMode = "read";
      }
    } else if (/\s/.test(ch)) {
      pushWord();
    } else {
      curWord += ch;
      hasWord = true;
    }
  }

  pushSegment(false);
  return segments;
}

export function extractSubshells(cmd) {
  const subshells = [];

  // Extract $(...) with balanced parentheses
  let i = 0;
  while (i < cmd.length) {
    if (cmd[i] === "$" && cmd[i + 1] === "(") {
      let depth = 1;
      let start = i + 2;
      i += 2;
      while (i < cmd.length && depth > 0) {
        if (cmd[i] === "(") depth++;
        else if (cmd[i] === ")") depth--;
        i++;
      }
      subshells.push(cmd.slice(start, depth === 0 ? i - 1 : i));
    } else {
      i++;
    }
  }

  // Extract `...` backticks
  const backtickMatches = [...cmd.matchAll(/`([^`]+)`/g)];
  for (const m of backtickMatches) {
    if (m[1]) subshells.push(m[1]);
  }

  return subshells;
}

const WRAPPERS = new Set([
  "sudo",
  "env",
  "command",
  "nohup",
  "time",
  "exec",
  "nice",
  "builtin",
  "xargs",
  "doas",
  "su",
  "timeout",
  "strace",
  "ltrace",
]);

const OPTS_WITH_ARG = new Set([
  "-u",
  "-g",
  "-C",
  "-U",
  "-r",
  "-t",
  "-D",
  "-n",
  "-d",
  "-I",
  "--user",
  "--group",
]);

const MUTATORS = new Set([
  "rm",
  "rmdir",
  "mv",
  "cp",
  "ln",
  "install",
  "rsync",
  "touch",
  "truncate",
  "chmod",
  "chown",
  "chgrp",
  "tee",
  "shred",
  "unlink",
  "mkdir",
  "patch",
]);

const READERS = new Set([
  "cat",
  "head",
  "tail",
  "more",
  "less",
  "base64",
  "xxd",
  "hexdump",
  "strings",
  "bat",
  "view",
  "nl",
  "tac",
  "od",
  "rev",
  "shuf",
  "sort",
  "uniq",
  "cut",
  "paste",
  "column",
  "fmt",
  "pr",
  "fold",
  "expand",
  "unexpand",
  "wc",
  "diff",
  "cmp",
  "comm",
  "zcat",
  "bzcat",
  "xzcat",
  "source",
  ".",
]);

const ARCHIVERS = new Set(["tar", "zip", "7z", "gzip", "bzip2", "xz", "zstd", "cpio"]);
const GREP_CMDS = new Set(["grep", "egrep", "fgrep", "rg", "ag", "ack"]);
const AWK_CMDS = new Set(["awk", "gawk", "mawk", "nawk"]);
const JQ_CMDS = new Set(["jq", "yq"]);
const INTERPRETERS = new Set([
  "python",
  "python3",
  "python2",
  "node",
  "bun",
  "deno",
  "ruby",
  "perl",
  "php",
  "lua",
]);
const IN_PLACE_EDITORS = new Set(["sed", "perl", "ruby"]);
const SHELLS = new Set(["sh", "bash", "zsh", "dash", "ksh"]);
const VAR_DECL_CMDS = new Set(["export", "local", "declare", "typeset", "readonly"]);

const isFdOrSafe = (target) =>
  /^&?[0-9-]+$/.test(target) ||
  target === "-" ||
  target === "/dev/null" ||
  target === "/dev/zero" ||
  target === "/dev/urandom" ||
  target === "/dev/random" ||
  target === "/dev/stdout" ||
  target === "/dev/stderr" ||
  target === "/dev/stdin";

function applyVars(str, vars) {
  if (!vars || !vars.size || typeof str !== "string") return str;
  return str.replace(/\$\{([A-Za-z_]\w*)\}|\$([A-Za-z_]\w*)/g, (m, g1, g2) => {
    const k = g1 || g2;
    return vars.has(k) ? vars.get(k) : m;
  });
}

function resolveTargetCandidates(rawTarget, vars) {
  if (typeof rawTarget !== "string" || !rawTarget) return [];
  const withVars = applyVars(rawTarget, vars);
  const out = new Set([rawTarget, withVars]);

  for (const base of [rawTarget, withVars]) {
    const subResolved = base
      .replace(/\$\(\s*echo\s+(?:-[neE]+\s+)?(["']?)([^()"']*)\1\s*\)/g, "$2")
      .replace(/`\s*echo\s+(?:-[neE]+\s+)?(["']?)([^`"']*)\1\s*`/g, "$2")
      .replace(/\$\(\s*printf\s+(?:["']%s["']\s+)?(["']?)([^()"']*)\1\s*\)/g, "$2")
      .replace(/\$\{[A-Za-z_]\w*:[=-]([^}]*)\}/g, "$1");
    out.add(subResolved);

    const stripped = subResolved.replace(
      /\$\{(?!HOME\b|PWD\b)[A-Za-z_]\w*\}|\$(?!HOME\b|PWD\b)[A-Za-z_]\w*/g,
      ""
    );
    if (stripped && stripped !== "/") out.add(stripped);
  }

  return [...out];
}

export function unwrapWords(words) {
  let i = 0;
  let usedXargs = false;
  while (i < words.length) {
    const w = words[i];
    if (/^[A-Za-z_]\w*=/.test(w)) {
      i++;
      continue;
    }
    const base = w.replace(/^.*\//, "");
    if (WRAPPERS.has(base)) {
      if (base === "xargs") usedXargs = true;
      i++;
      if (base === "timeout" && i < words.length && /^[0-9]/.test(words[i])) {
        i++;
      }
      while (i < words.length && words[i].startsWith("-")) {
        const next = words[i + 1];
        if (
          OPTS_WITH_ARG.has(words[i]) &&
          next &&
          !next.startsWith("-") &&
          !MUTATORS.has(next) &&
          !READERS.has(next) &&
          !WRAPPERS.has(next)
        ) {
          i += 2;
        } else {
          i++;
        }
      }
      continue;
    }
    break;
  }

  return {
    cmdName: words[i] ? words[i].replace(/^.*\//, "") : "",
    args: words.slice(i + 1),
    usedXargs,
  };
}

function extractStringLiterals(code) {
  let folded = code;
  for (let pass = 0; pass < 4; pass++) {
    const next = folded
      .replace(/"([^"\\]*)"\s*\+\s*"([^"\\]*)"/g, '"$1$2"')
      .replace(/'([^'\\]*)'\s*\+\s*'([^'\\]*)'/g, "'$1$2'");
    if (next === folded) break;
    folded = next;
  }
  const literals = [];
  const rx = /"([^"\\]*(?:\\.[^"\\]*)*)"|'([^'\\]*(?:\\.[^'\\]*)*)'|`([^`\\]*(?:\\.[^`\\]*)*)`/g;
  for (const src of new Set([code, folded])) {
    let m;
    while ((m = rx.exec(src)) !== null) {
      const lit = m[1] ?? m[2] ?? m[3] ?? "";
      if (lit.trim()) literals.push(lit.trim());
    }
  }
  return literals;
}

export function checkBashCommand(
  cmd,
  config = DEFAULT_CONFIG,
  cwd = process.cwd(),
  depth = 0
) {
  if (typeof cmd !== "string" || !cmd.trim() || depth > 5) {
    return { block: false };
  }

  // 1. Check for inline plaintext secrets in the command string itself
  if (config.blockInlineSecretsInCommands) {
    const secretHit = detectSecrets(cmd, config);
    if (secretHit) {
      return {
        block: true,
        reason: `rilevata credenziale/segreto in chiaro nella riga di comando (${secretHit.category})`,
      };
    }
  }

  let here = cwd;
  const vars = new Map();
  const deny = (target, reason) => ({
    block: true,
    reason: `operazione shell vietata su "${target}" (${reason})`,
  });

  const checkTarget = (rawTarget, op, customPrefix = "") => {
    for (const candidate of resolveTargetCandidates(rawTarget, vars)) {
      if (!candidate || isFdOrSafe(candidate)) continue;
      const check = isPathProtected(candidate, config, here, op);
      if (check.protected) {
        return deny(rawTarget, customPrefix ? `${customPrefix}: ${check.reason}` : check.reason);
      }
    }
    return null;
  };

  const nestedCommands = extractSubshells(cmd);
  const segments = parseSegments(cmd);

  let pipedArgs = [];
  let pipedFromDecoder = false;

  for (const { words, redirects, inputRedirects, pipedToNext } of segments) {
    if (words.length === 0 && redirects.length === 0 && inputRedirects.length === 0) {
      pipedArgs = [];
      pipedFromDecoder = false;
      continue;
    }

    // Record leading variable assignments (e.g. A=.e; B=nv; or export FOO=.env)
    for (let wIdx = 0; wIdx < words.length; wIdx++) {
      const tok = words[wIdx];
      if (VAR_DECL_CMDS.has(tok) || tok.startsWith("-")) continue;
      const eqMatch = tok.match(/^([A-Za-z_]\w*)=(.*)$/);
      if (eqMatch) {
        vars.set(eqMatch[1], applyVars(eqMatch[2], vars));
      } else {
        break;
      }
    }

    const expandedWords = words.map((w) => applyVars(w, vars));
    const { cmdName, args: rawArgs, usedXargs } = unwrapWords(expandedWords);
    const args = usedXargs && pipedArgs.length > 0 ? [...rawArgs, ...pipedArgs] : rawArgs;

    // Anti-tampering: prevent the agent from disabling or uninstalling DLP Guard via CLI
    if (cmdName === "agy-dlp" || cmdName === "agy-dlp-guard" || words.some((w) => /agy-dlp(?:-guard)?(?:\.mjs)?$/.test(w))) {
      const hasUninstallOrDisable = args.some((a) => /^(?:uninstall|off|disable)$/i.test(a));
      const tIdx = args.findIndex((a) => /^toggle$/i.test(a));
      const isToggleOff = tIdx !== -1 && /^(?:off|false|0|disable)$/i.test(args[tIdx + 1] || "");
      if (hasUninstallOrDisable || isToggleOff) {
        return deny(cmdName || "agy-dlp", "integrità del sistema: disattivazione o modifica di DLP Guard non consentita dall'agente");
      }
    }
    if ((cmdName === "agy" || cmdName === "pi" || cmdName === "opencode") && args.some((a) => /^(?:uninstall|remove|disable)$/i.test(a)) && args.some((a) => /dlp-guard/i.test(a))) {
      return deny(cmdName, "integrità del sistema: disattivazione o rimozione di DLP Guard non consentita dall'agente");
    }

    // Block piping base64 -d / xxd -r directly into a shell interpreter
    if (pipedFromDecoder && (SHELLS.has(cmdName) || cmdName === "eval" || cmdName === "source" || cmdName === ".")) {
      return deny(cmdName, "esecuzione di payload offuscato/decodificato in pipe verso shell vietata");
    }

    // Track directory changes across command chains
    if (cmdName === "cd" || cmdName === "pushd") {
      if (args[0]) {
        const resolvedDir = resolveTargetCandidates(args[0], vars).pop() || args[0];
        here = path.resolve(here, expandHome(resolvedDir, here));
      }
      pipedArgs = [];
      pipedFromDecoder = false;
      continue;
    }

    // Inspect subshells in shell -c or eval
    if (SHELLS.has(cmdName)) {
      const cIdx = args.indexOf("-c");
      if (cIdx !== -1 && args[cIdx + 1]) {
        nestedCommands.push(args[cIdx + 1]);
      } else if (config.blockReaderCommandsOnProtected) {
        for (const scriptArg of args.filter((a) => !a.startsWith("-"))) {
          const hit = checkTarget(scriptArg, "read", `esecuzione/lettura non autorizzata tramite ${cmdName}`);
          if (hit) return hit;
        }
      }
    }
    if (cmdName === "eval") {
      nestedCommands.push(args.join(" "));
    }

    // 1. Check all write redirects (>, >>, >|, &>, <>)
    for (const target of redirects) {
      const hit = checkTarget(target, "write");
      if (hit) return hit;
    }

    // 2. Check all input redirects (< file)
    if (config.blockReaderCommandsOnProtected) {
      for (const target of inputRedirects) {
        const hit = checkTarget(target, "read", "redirezione di lettura non autorizzata");
        if (hit) return hit;
      }
    }

    // 3. Special handling for dd (if=read, of=write)
    if (cmdName === "dd") {
      for (const a of args) {
        if (a.startsWith("if=") && config.blockReaderCommandsOnProtected) {
          const hit = checkTarget(a.slice(3), "read", "lettura non autorizzata tramite dd");
          if (hit) return hit;
        } else if (a.startsWith("of=")) {
          const hit = checkTarget(a.slice(3), "write");
          if (hit) return hit;
        }
      }
    }

    // 4. Check mutating commands and in-place editors
    const isInPlace =
      IN_PLACE_EDITORS.has(cmdName) &&
      args.some((a) => /^-[A-Za-z]*i|^--in-place/.test(a));

    if (MUTATORS.has(cmdName) || isInPlace) {
      const mutTargets =
        cmdName === "sed"
          ? args.filter((a, idx) => !a.startsWith("-") && idx > 0)
          : args.filter((a) => !a.startsWith("-"));
      for (const target of mutTargets) {
        const hit = checkTarget(target, "write");
        if (hit) return hit;
      }
    }

    // 5. Check direct reading commands
    if (config.blockReaderCommandsOnProtected && READERS.has(cmdName)) {
      const readTargets = args.filter((a) => !a.startsWith("-"));
      for (const target of readTargets) {
        const hit = checkTarget(target, "read", `lettura non autorizzata tramite ${cmdName}`);
        if (hit) return hit;
      }
    }

    // 6. Check grep / rg / ag / ack (distinguishing pattern from file arguments)
    if (config.blockReaderCommandsOnProtected && GREP_CMDS.has(cmdName)) {
      let hasExplicitPattern = false;
      const posArgs = [];
      const optsTakingArg = new Set([
        "-m", "-A", "-B", "-C", "-g", "-t", "--max-count", "--after-context",
        "--before-context", "--context", "--glob", "--type", "--include",
        "--exclude", "--exclude-dir", "--color",
      ]);
      for (let j = 0; j < args.length; j++) {
        const a = args[j];
        if (a === "-e" || a === "--regexp") {
          hasExplicitPattern = true;
          j++;
        } else if (a.startsWith("--regexp=")) {
          hasExplicitPattern = true;
        } else if (a === "-f" || a === "--file") {
          hasExplicitPattern = true;
          if (args[j + 1]) {
            const hit = checkTarget(args[++j], "read", `lettura file pattern tramite ${cmdName}`);
            if (hit) return hit;
          }
        } else if (a.startsWith("--file=")) {
          hasExplicitPattern = true;
          const hit = checkTarget(a.slice(7), "read", `lettura file pattern tramite ${cmdName}`);
          if (hit) return hit;
        } else if (optsTakingArg.has(a)) {
          j++;
        } else if (!a.startsWith("-")) {
          posArgs.push(a);
        }
      }
      const fileTargets = hasExplicitPattern ? posArgs : posArgs.slice(1);
      for (const target of fileTargets) {
        const hit = checkTarget(target, "read", `ricerca/lettura non autorizzata tramite ${cmdName}`);
        if (hit) return hit;
      }
    }

    // 7. Check sed (without -i), awk, jq, yq
    if (config.blockReaderCommandsOnProtected && (cmdName === "sed" || AWK_CMDS.has(cmdName) || JQ_CMDS.has(cmdName))) {
      let hasScriptFileOrExpr = false;
      const posArgs = [];
      for (let j = 0; j < args.length; j++) {
        const a = args[j];
        if (a === "-f" || a === "--file" || a === "--from-file") {
          hasScriptFileOrExpr = true;
          if (args[j + 1]) {
            const hit = checkTarget(args[++j], "read", `lettura tramite ${cmdName}`);
            if (hit) return hit;
          }
        } else if (a.startsWith("--file=")) {
          hasScriptFileOrExpr = true;
          const hit = checkTarget(a.slice(7), "read", `lettura tramite ${cmdName}`);
          if (hit) return hit;
        } else if (a === "-e" || a === "--expression") {
          hasScriptFileOrExpr = true;
          j++;
        } else if (a === "-F" || a === "-v") {
          j++;
        } else if ((a === "--slurpfile" || a === "--rawfile") && j + 2 < args.length) {
          const hit = checkTarget(args[j + 2], "read", `lettura tramite ${cmdName}`);
          if (hit) return hit;
          j += 2;
        } else if ((a === "--arg" || a === "--argjson") && j + 2 < args.length) {
          j += 2;
        } else if (!a.startsWith("-")) {
          posArgs.push(a);
        }
      }
      const fileTargets = hasScriptFileOrExpr ? posArgs : posArgs.slice(1);
      for (const target of fileTargets) {
        const hit = checkTarget(target, "read", `lettura non autorizzata tramite ${cmdName}`);
        if (hit) return hit;
      }
    }

    // 8. Check archivers (tar, zip, 7z, gzip, etc.)
    if (ARCHIVERS.has(cmdName)) {
      for (let j = 0; j < args.length; j++) {
        const a = args[j];
        if ((a === "-C" || a === "--directory") && args[j + 1]) {
          const hit = checkTarget(args[++j], "write");
          if (hit) return hit;
        } else if ((a === "-f" || a === "--file") && args[j + 1]) {
          const hit = checkTarget(args[++j], "write");
          if (hit) return hit;
        } else if (!a.startsWith("-")) {
          if (config.blockReaderCommandsOnProtected) {
            const hitR = checkTarget(a, "read", `archiviazione non autorizzata tramite ${cmdName}`);
            if (hitR) return hitR;
          }
          const hitW = checkTarget(a, "write");
          if (hitW) return hitW;
        }
      }
    }

    // 9. Check find (-delete, -exec, and protected search roots)
    if (cmdName === "find") {
      const hasDelete = args.includes("-delete");
      const execIdx = args.findIndex((a) => a === "-exec" || a === "-execdir" || a === "-ok");
      const targetsToCheck = [];
      for (let j = 0; j < args.length; j++) {
        const a = args[j];
        if (a === "-exec" || a === "-execdir" || a === "-ok") break;
        if ((a === "-name" || a === "-iname" || a === "-path" || a === "-wholename") && args[j + 1]) {
          targetsToCheck.push(args[++j]);
        } else if (!a.startsWith("-") && a !== "!" && a !== ";") {
          targetsToCheck.push(a);
        }
      }
      for (const t of targetsToCheck) {
        if (hasDelete) {
          const hit = checkTarget(t, "write");
          if (hit) return hit;
        }
        if (config.blockReaderCommandsOnProtected && (execIdx !== -1 || t !== ".")) {
          const hit = checkTarget(t, "read", "ricerca find su percorso protetto");
          if (hit) return hit;
        }
      }
      if (execIdx !== -1) {
        const execTokens = args
          .slice(execIdx + 1)
          .filter((a) => a !== ";" && a !== "\\;" && a !== "+")
          .map((a) => (a === "{}" && targetsToCheck[0] ? targetsToCheck[0] : a));
        if (execTokens.length > 0) {
          nestedCommands.push(execTokens.join(" "));
        }
      }
    }

    // 10. Check git commands referencing protected files (e.g. git diff --no-index /dev/null .env, git show HEAD:.env, git checkout -- .env)
    if (cmdName === "git") {
      const sub = args[0];
      const isGitMutator = sub === "checkout" || sub === "restore" || sub === "clean";
      for (let j = 0; j < args.length; j++) {
        const a = args[j];
        let candidate = null;
        if (a.startsWith("--file=")) {
          candidate = a.slice(7);
        } else if ((a === "-f" || a === "--file") && sub === "config" && args[j + 1]) {
          candidate = args[++j];
        } else if (!a.startsWith("-") && a !== "--" && j > 0) {
          candidate = a.includes(":") && !a.includes("://") ? a.split(":").pop() : a;
        }
        if (candidate) {
          if (isGitMutator) {
            const hitW = checkTarget(candidate, "write", "modifica git non autorizzata su percorso protetto");
            if (hitW) return hitW;
          }
          if (config.blockReaderCommandsOnProtected) {
            const hitR = checkTarget(candidate, "read", "accesso git non autorizzato a percorso protetto");
            if (hitR) return hitR;
          }
        }
      }
    }

    // 11. Check openssl, scp, sftp
    if (cmdName === "openssl") {
      for (let j = 0; j < args.length; j++) {
        const a = args[j];
        if ((a === "-in" || a === "-inkey" || a === "-certin") && args[j + 1] && config.blockReaderCommandsOnProtected) {
          const hit = checkTarget(args[++j], "read", "lettura tramite openssl");
          if (hit) return hit;
        } else if (a.startsWith("file:") && config.blockReaderCommandsOnProtected) {
          const hit = checkTarget(a.slice(5), "read", "lettura tramite openssl");
          if (hit) return hit;
        } else if ((a === "-out" || a === "-keyout") && args[j + 1]) {
          const hit = checkTarget(args[++j], "write");
          if (hit) return hit;
        }
      }
    }
    if (cmdName === "scp" || cmdName === "sftp") {
      for (const a of args.filter((x) => !x.startsWith("-"))) {
        const localPart = a.includes(":") && !a.includes("://") ? a.split(":").pop() : a;
        if (config.blockReaderCommandsOnProtected) {
          const hitR = checkTarget(localPart, "read", `trasferimento non autorizzato tramite ${cmdName}`);
          if (hitR) return hitR;
        }
        const hitW = checkTarget(localPart, "write");
        if (hitW) return hitW;
      }
    }

    // 12. Check interpreters (python, python3, node, bun, deno, ruby, perl, php, lua)
    if (INTERPRETERS.has(cmdName)) {
      const codeFlags = new Set(["-c", "-e", "-p", "-r", "--eval", "--print", "eval"]);
      for (let j = 0; j < args.length; j++) {
        const a = args[j];
        if (codeFlags.has(a) && args[j + 1]) {
          const inlineCode = args[++j];
          const hasMutationCall = /\b(?:write|writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream|unlink|unlinkSync|rm|rmSync|rmdir|remove|removedirs|rmtree|rename|replace|chmod|chown|truncate|copyFile|cpSync|shutil)\b/i.test(
            inlineCode
          );
          for (const lit of extractStringLiterals(inlineCode)) {
            if (config.blockReaderCommandsOnProtected) {
              const hitR = checkTarget(lit, "read", `accesso tramite script inline ${cmdName}`);
              if (hitR) return hitR;
            }
            if (hasMutationCall) {
              const hitW = checkTarget(lit, "write", `modifica tramite script inline ${cmdName}`);
              if (hitW) return hitW;
            }
          }
        } else if (!a.startsWith("-")) {
          if (config.blockReaderCommandsOnProtected) {
            const hit = checkTarget(a, "read", `esecuzione/lettura tramite ${cmdName}`);
            if (hit) return hit;
          }
        }
      }
    }

    // 13. Check cURL & Wget exfiltration and output write vectors
    if (cmdName === "curl") {
      for (let j = 0; j < args.length; j++) {
        const arg = args[j];
        let readTarget = null;
        let writeTarget = null;
        if (arg.startsWith("@")) {
          readTarget = arg.slice(1);
        } else if (arg.includes("=@")) {
          readTarget = arg.split("=@")[1];
        } else if ((arg === "-T" || arg === "--upload-file") && j + 1 < args.length) {
          readTarget = args[++j];
        } else if ((arg === "-o" || arg === "--output") && j + 1 < args.length) {
          writeTarget = args[++j];
        } else if (arg.startsWith("--output=")) {
          writeTarget = arg.slice(9);
        }

        if (readTarget) {
          const hit = checkTarget(
            readTarget,
            "read",
            "tentativo di esfiltrazione/lettura di percorso sensibile tramite curl"
          );
          if (hit) return hit;
        }
        if (writeTarget) {
          const hit = checkTarget(writeTarget, "write");
          if (hit) return hit;
        }
      }
    }

    if (cmdName === "wget") {
      for (let j = 0; j < args.length; j++) {
        const arg = args[j];
        let readTarget = null;
        let writeTarget = null;
        if (arg.startsWith("--post-file=")) {
          readTarget = arg.slice("--post-file=".length);
        } else if (arg === "--post-file" && j + 1 < args.length) {
          readTarget = args[++j];
        } else if ((arg === "-O" || arg === "--output-document" || arg === "-P" || arg === "--directory-prefix") && j + 1 < args.length) {
          writeTarget = args[++j];
        } else if (arg.startsWith("--output-document=")) {
          writeTarget = arg.slice("--output-document=".length);
        } else if (arg.startsWith("--directory-prefix=")) {
          writeTarget = arg.slice("--directory-prefix=".length);
        }

        if (readTarget) {
          const hit = checkTarget(
            readTarget,
            "read",
            "tentativo di esfiltrazione/lettura di percorso sensibile tramite wget"
          );
          if (hit) return hit;
        }
        if (writeTarget) {
          const hit = checkTarget(writeTarget, "write");
          if (hit) return hit;
        }
      }
    }

    // Track piped data for xargs and base64-decode detection
    if (pipedToNext) {
      if (cmdName === "echo" || cmdName === "printf") {
        pipedArgs = args.filter((a) => !a.startsWith("-"));
        pipedFromDecoder = false;
      } else if (
        (cmdName === "base64" && args.some((a) => a === "-d" || a === "-D" || a === "--decode")) ||
        (cmdName === "xxd" && args.includes("-r"))
      ) {
        pipedFromDecoder = true;
        for (const b64Candidate of pipedArgs) {
          try {
            const decoded = Buffer.from(b64Candidate, "base64").toString("utf-8");
            if (decoded && /^[\x20-\x7e\s]+$/.test(decoded)) {
              nestedCommands.push(decoded);
            }
          } catch {}
        }
      } else {
        pipedArgs = [];
        pipedFromDecoder = false;
      }
    } else {
      pipedArgs = [];
      pipedFromDecoder = false;
    }
  }

  // 14. Recursively inspect nested subshells
  for (const inner of nestedCommands) {
    const res = checkBashCommand(inner, config, here, depth + 1);
    if (res.block) return res;
  }

  return { block: false };
}
