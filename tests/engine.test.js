/**
 * Minimal, dependency-free test runner for engine.js.
 * Run with: node tests/engine.test.js
 */
const assert = require("assert");
const { analyzeUrl, analyzeEmail, levenshtein } = require("../engine.js");

let passed = 0, failed = 0;

function test(name, fn) {
  try {
    fn();
    passed++;
    console.log("  ok  -", name);
  } catch (e) {
    failed++;
    console.log("  FAIL -", name);
    console.log("       ", e.message);
  }
}

console.log("Legit URLs should score low / clean:");
test("google.com is clean", () => {
  const r = analyzeUrl("https://www.google.com/search?q=test");
  assert.strictEqual(r.level, "clean");
});
test("paypal.com is clean", () => {
  const r = analyzeUrl("https://www.paypal.com/signin");
  assert.strictEqual(r.level, "clean");
});
test("a plain unrelated https domain is clean-ish", () => {
  const r = analyzeUrl("https://example.com/about");
  assert.ok(r.level === "clean" || r.level === "low");
});

console.log("\nPhishing-style URLs should be flagged:");
test("typosquat of paypal is flagged high", () => {
  const r = analyzeUrl("http://paypa1.com/login");
  assert.ok(r.flags.some((f) => f.id === "typosquat"));
});
test("brand name stuffed into unrelated domain", () => {
  const r = analyzeUrl("http://secure-paypal-login-verify.xyz/account");
  assert.ok(r.flags.some((f) => f.id === "typosquat" || f.id === "brand-mention"));
  assert.ok(r.flags.some((f) => f.id === "suspicious-tld"));
  assert.ok(r.flags.some((f) => f.id === "no-https"));
});
test("raw IP host is flagged", () => {
  const r = analyzeUrl("http://192.168.1.50/paypal/login.php");
  assert.ok(r.flags.some((f) => f.id === "ip-host"));
});
test("@ trick is flagged", () => {
  const r = analyzeUrl("http://google.com@evil-site.ru/reset");
  assert.ok(r.flags.some((f) => f.id === "at-symbol"));
});
test("URL shortener is flagged", () => {
  const r = analyzeUrl("https://bit.ly/3xample");
  assert.ok(r.flags.some((f) => f.id === "shortener"));
});
test("punycode domain is flagged", () => {
  const r = analyzeUrl("https://xn--pypal-4ve.com/login");
  assert.ok(r.flags.some((f) => f.id === "punycode"));
});
test("obvious phishing URL is high risk", () => {
  const r = analyzeUrl("http://account-verify-paypal-secure.tk/login.php?id=1");
  assert.strictEqual(r.level, "high");
});

console.log("\nEmail text analysis:");
test("benign email has no flags", () => {
  const r = analyzeEmail("Hi Jordan, attaching the notes from today's standup. Talk soon, Sam.");
  assert.strictEqual(r.level, "clean");
});
test("classic phishing email is flagged high", () => {
  const text = `From: "PayPal Support" <support@paypal-alert-secure.tk>
Dear Customer,

We detected unusual activity on your account. Your account will be suspended within 24 hours
unless you verify your account immediately. Click here now: http://paypal-alert-secure.tk/verify

Please confirm your password and card number to restore access.`;
  const r = analyzeEmail(text);
  assert.strictEqual(r.level, "high");
  assert.ok(r.flags.some((f) => f.id === "urgency"));
  assert.ok(r.flags.some((f) => f.id === "sensitive-request"));
  assert.ok(r.flags.some((f) => f.id === "generic-greeting"));
  assert.ok(r.flags.some((f) => f.id === "sender-mismatch"));
  assert.ok(r.flags.some((f) => f.id.startsWith("typosquat:") || f.id.startsWith("brand-mention:") || f.id.startsWith("suspicious-tld:")));
});

console.log("\nUtility checks:");
test("levenshtein distance basics", () => {
  assert.strictEqual(levenshtein("paypal.com", "paypal.com"), 0);
  assert.strictEqual(levenshtein("paypa1.com", "paypal.com"), 1);
  assert.strictEqual(levenshtein("kitten", "sitting"), 3);
});

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);

