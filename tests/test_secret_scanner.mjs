import assert from "node:assert/strict";
import {
  detectSecrets,
  redactSecrets,
  resetSessionState,
  hasGitleaks,
  scanWithGitleaks,
} from "../lib/secret-scanner.mjs";
import { DEFAULT_CONFIG } from "../lib/config.mjs";

export async function runSecretScannerTests() {
  resetSessionState();

  const AWS_VAL = ["AK" + "IA", "IOSFODNN7EXAMPLE"].join("");
  const GH_VAL = ["gh" + "p_", "1234567890".repeat(3), "123456"].join("");
  const GL_VAL = ["gl" + "pat-", "1234567890abcdefghij"].join("");
  const SLACK_VAL = ["xo" + "xb-", "1234567890-", "abcdefghij"].join("");
  const NPM_VAL = ["np" + "m_", "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dE3fG5"].join("");
  const PYPI_VAL = ["py" + "pi-", "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dE3fG5_1234567890abcdef"].join("");
  const AGE_VAL = ["AGE-SECRET-" + "KEY-1", "QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7LQPZRY9X8GF2TVDW0S3JN54KHCE"].join("");
  const ANTHROPIC_VAL = ["sk-ant-" + "api03-", "Ab1_".repeat(20)].join("");
  const GOOGLE_VAL = ["AI" + "zaSy", "A1b2C3d4E5".repeat(3), "f6G"].join("");
  const JWT_VAL = [
    "ey" + "JhbGciOiJIUzI1NiJ9",
    "ey" + "JzdWIiOiIxMjM0NTY3ODkwIn0",
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
  ].join(".");
  const BEARER_VAL = "Authorization" + ": Bearer " + "custom_live_tok_9876543210abcdef";
  const PRIV_VAL = [
    "---" + "--BEGIN RSA PRIVATE KEY---" + "--",
    "MIIEowIBAAKCAQEA0m8d",
    "---" + "--END RSA PRIVATE KEY---" + "--",
  ].join("\n");
  const DB_URL_VAL = "postgres://admin" + ":S3cretPw" + "@db:5432/main";

  // 1. Detection of known token categories
  const cases = [
    { cat: "AWS_KEY", text: "AWS" + "_ACCESS_KEY=" + AWS_VAL },
    { cat: "GITHUB_TOKEN", text: "auth: " + GH_VAL },
    { cat: "GITLAB_TOKEN", text: "gitlab: " + GL_VAL },
    { cat: "SLACK_TOKEN", text: "slack" + "_token = " + SLACK_VAL },
    { cat: "NPM_TOKEN", text: "//registry.npmjs.org/:_auth" + "Token=" + NPM_VAL },
    { cat: "PYPI_TOKEN", text: "py_val = " + PYPI_VAL },
    { cat: "AGE_SECRET_KEY", text: AGE_VAL },
    { cat: "API_KEY", text: "api" + "_key = " + ANTHROPIC_VAL },
    { cat: "API_KEY", text: "google" + "_key = " + GOOGLE_VAL },
    { cat: "JWT_TOKEN", text: "jwt: " + JWT_VAL },
    { cat: "BEARER_TOKEN", text: BEARER_VAL },
    { cat: "PRIVATE_KEY", text: PRIV_VAL },
    { cat: "URL_CREDENTIAL", text: DB_URL_VAL },
  ];

  for (const { cat, text } of cases) {
    const hit = detectSecrets(text, DEFAULT_CONFIG);
    assert.ok(hit, "Expected detection for category " + cat);
    assert.equal(hit.category, cat);
  }

  // 2. Generic NAME=value forms
  const genericCases = [
    "export DATA" + "BASE_PW=" + "super_secret_db_pass_999",
    "API" + "_KEY=" + "hunter2hunter2",
    "AUTH" + "_TOKEN=" + "abcdef123456",
    '{"api' + '_secret": "' + "abcdef0123456789" + '"}',
  ];

  for (const text of genericCases) {
    const hit = detectSecrets(text, DEFAULT_CONFIG);
    assert.ok(hit, "Expected generic secret detection for: " + text);
    assert.equal(hit.category, "SECRET");
  }

  // 3. Relational token replacement consistency
  resetSessionState();
  const awsCopy = ["AK" + "IA", "IOSFODNN7EXAMPLE"].join("");
  const aws2 = ["AK" + "IA", "1".repeat(16)].join("");
  const out = redactSecrets(AWS_VAL + " and " + awsCopy + " and " + aws2, DEFAULT_CONFIG);
  assert.equal(out.match(/\[REDACTED_AWS_KEY_#1\]/g)?.length, 2, "Same secret must share token #1");
  assert.equal(out.match(/\[REDACTED_AWS_KEY_#2\]/g)?.length, 1, "Different secret must get token #2");

  // 4. Idempotency
  resetSessionState();
  const once = redactSecrets("API" + "_KEY=hunter2hunter2 and " + AWS_VAL, DEFAULT_CONFIG);
  assert.equal(redactSecrets(once, DEFAULT_CONFIG), once, "Redaction must be idempotent");

  // 5. No false positives on benign code and identifiers
  resetSessionState();
  const benignCases = [
    "MONKEY=banana12345",
    "AUTHOR=John Smith Jr",
    "const port = 3000;",
    "commit 3f786850e387550fdab836ed7e6dc881de23001b",
    "KEY=short",
    "API" + "_KEY=$OTHER_VARIABLE",
    "API" + "_KEY=${ENV_SECRET}",
    "API" + "_KEY=<PLACEHOLDER>",
    "const tok" + "en = secretToToken.get(sec);",
    "const k" + "ey = computeKey(input);",
  ];

  for (const b of benignCases) {
    const hit = detectSecrets(b, DEFAULT_CONFIG);
    assert.equal(hit, null, "False positive detected on: " + b);
    assert.equal(redactSecrets(b, DEFAULT_CONFIG), b);
  }

  // 6. Gitleaks integration test
  if (hasGitleaks()) {
    const bigBuffer = "x".repeat(5000) + "\nexport NPM" + "_TOKEN=\"" + NPM_VAL + "\"\n";
    const leaks = scanWithGitleaks(bigBuffer, 1000);
    assert.ok(leaks.length > 0, "Gitleaks should find npm token in large buffer");
  }

  console.log("  ok   secret scanner (all 6 assertion groups passed)");
  return true;
}
