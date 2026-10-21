import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { isPathProtected } from "../lib/path-guard.mjs";
import { DEFAULT_CONFIG } from "../lib/config.mjs";

export async function runPathGuardTests() {
  const tmpHome = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "dlp-test-home-")));
  const tmpCwd = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "dlp-test-cwd-")));

  const prevHome = process.env.HOME;
  process.env.HOME = tmpHome;

  const prot = (p, op = "read", cfg = DEFAULT_CONFIG) =>
    isPathProtected(p, cfg, tmpCwd, op).protected;

  try {
    // 1. .env variants and templates
    for (const p of [".env", ".env.local", "./.env", "../../.env", "subdir/../../.env", "production.env", ".envrc"]) {
      assert.ok(prot(p), `Expected ${p} to be protected`);
    }
    for (const p of [".env.example", ".env.sample", ".env.template", ".env.dist"]) {
      assert.ok(!prot(p), `Expected template ${p} to be allowed`);
    }

    // 2. Template symlinked to real .env MUST be blocked, and template inside integrityPath MUST be write-blocked
    const realSecret = path.join(tmpCwd, ".env");
    fs.writeFileSync(realSecret, "SECRET=1\n");
    const fakeTemplate = path.join(tmpCwd, ".env.example");
    fs.symlinkSync(realSecret, fakeTemplate);
    assert.ok(prot(".env.example"), "Symlink named .env.example pointing to .env must be blocked");
    fs.unlinkSync(fakeTemplate);
    assert.ok(prot("~/.gemini/config/.env.example", "write"), "Writing .env.example inside integrityPath must be blocked");

    // 3. Credentials, keys, cloud/infra state, and shell rc files
    for (const p of [
      "~/.ssh/id_rsa",
      "$HOME/.aws/credentials",
      ".git/config",
      "certs/server.pem",
      "keys/private.key",
      "infra/terraform.tfstate",
      "infra/prod.tfvars",
      "~/.kube/config",
      "~/.config/gh/hosts.yml",
      "~/.password-store/work/db.gpg",
      "~/.vault-token",
      "~/.zshrc.local",
      "~/.bash_profile",
      "~/.netrc",
      "~/.git-credentials",
      "~/.pi/agent/auth.json",
    ]) {
      assert.ok(prot(p), `Expected sensitive path ${p} to be protected`);
    }

    // 4. Benign files
    for (const p of ["src/index.js", "package.json", "README.md", "environment.ts", "notes.txt"]) {
      assert.ok(!prot(p), `Expected benign file ${p} to NOT be protected`);
    }

    // 5. CWD-relative patterns
    const customCfg = { ...DEFAULT_CONFIG, protectedPaths: ["vault/**"] };
    assert.ok(prot("vault/secret.txt", "read", customCfg));
    assert.ok(!prot("other/vault/secret.txt", "read", customCfg));

    // 6. Symlink to a protected file
    const linkToSecret = path.join(tmpCwd, "innocent.txt");
    fs.symlinkSync(realSecret, linkToSecret);
    assert.ok(prot("innocent.txt"), "Symlink pointing to .env must be protected");

    // 7. Dangling symlink to an integrity path
    const danglingLink = path.join(tmpCwd, "dangling_link");
    fs.symlinkSync(path.join(tmpHome, ".gemini", "config", "evil.mjs"), danglingLink);
    assert.ok(prot("dangling_link", "write"), "Dangling link into integrity path must be write-blocked");
    assert.ok(!prot("dangling_link", "read"), "Dangling link read is not blocked under integrity rules");

    // 8. Integrity paths: read allowed, write blocked
    const integrityFile = "~/.gemini/config/settings.json";
    assert.ok(!prot(integrityFile, "read"), "Integrity path should allow read");
    assert.ok(prot(integrityFile, "write"), "Integrity path must block write");

    // 9. Null-byte injection protection (raw and URL-encoded)
    assert.ok(prot("safe.txt\0.env"), "Raw null-byte injection must be blocked");
    assert.ok(prot("safe.txt%00.env"), "URL-encoded null-byte injection must be blocked");

    // 10. Single and double URL-encoded traversal protection
    assert.ok(prot("%2e%2e%2f%2e%2e%2f.env"), "Single URL-encoded traversal must be blocked");
    assert.ok(prot("%252e%252e%252f.env"), "Double URL-encoded traversal must be blocked");

    // 11. Shell brace expansion & wildcards (.en?, .e*, [.]env, .{env,bak})
    for (const p of [".en?", ".e*", "[.]env", ".{env,bak}", "~/{.ssh,.aws}/id_rsa", "$PWD/.env", "${PWD}/.env"]) {
      assert.ok(prot(p), `Expected wildcard/brace/PWD path ${p} to be blocked`);
    }
    for (const p of ["*.js", "*.md", "src/*.ts"]) {
      assert.ok(!prot(p), `Expected benign wildcard ${p} to be allowed`);
    }

    console.log("  ok   path guard (all 11 assertion groups passed)");
    return true;
  } finally {
    process.env.HOME = prevHome;
    fs.rmSync(tmpHome, { recursive: true, force: true });
    fs.rmSync(tmpCwd, { recursive: true, force: true });
  }
}
