import { chromium } from "playwright";
import { fileURLToPath } from "url";
import path from "path";
import { createServer } from "http";
import { readFile } from "fs/promises";

const dir = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

const server = createServer(async (req, res) => {
  if (req.url === "/favicon.ico") { res.writeHead(204); res.end(); return; }
  let filePath = path.join(dir, req.url === "/" ? "/index.html" : req.url);
  try {
    const data = await readFile(filePath);
    const ext = path.extname(filePath);
    const type = ext === ".html" ? "text/html" : ext === ".js" ? "application/javascript" : "text/plain";
    res.writeHead(200, { "Content-Type": type });
    res.end(data);
  } catch {
    res.writeHead(404);
    res.end("not found");
  }
});

await new Promise((resolve) => server.listen(0, resolve));
const port = server.address().port;

const browser = await chromium.launch({ executablePath: "/opt/pw-browsers/chromium" });
const page = await browser.newPage();
// Only real script exceptions fail the run — network noise (e.g. a stray
// favicon 404, or requests blocked by this sandbox's proxy) is not an app bug.
const consoleErrors = [];
page.on("pageerror", (e) => consoleErrors.push(String(e)));

await page.goto(`http://localhost:${port}/index.html`);

// 1. URL tab: load bad sample, scan, expect high risk banner
await page.click('[data-sample="url-bad"]');
await page.click("#scan-url-btn");
const urlRiskText = await page.textContent(".risk-banner .risk-label");
console.log("URL scan result:", urlRiskText.trim());
if (!/high risk/i.test(urlRiskText)) throw new Error("Expected high risk for bad sample URL, got: " + urlRiskText);

// 2. Good URL should be clean
await page.click('[data-sample="url-good"]');
await page.click("#scan-url-btn");
const goodUrlText = await page.textContent(".risk-banner .risk-label");
console.log("Good URL scan result:", goodUrlText.trim());
if (!/no red flags/i.test(goodUrlText)) throw new Error("Expected clean for paypal.com, got: " + goodUrlText);

// 3. Email tab
await page.click('[data-tab="email"]');
await page.click('[data-sample="email-bad"]');
await page.click("#scan-email-btn");
const emailRiskText = await page.textContent(".risk-banner .risk-label");
console.log("Email scan result:", emailRiskText.trim());
if (!/high risk/i.test(emailRiskText)) throw new Error("Expected high risk for phishing email sample, got: " + emailRiskText);

const flagCount = await page.locator(".flags-list .flag").count();
console.log("Flags rendered:", flagCount);
if (flagCount < 3) throw new Error("Expected several flags rendered for phishing email");

const linksFound = await page.locator(".link-list li").count();
console.log("Links found in email:", linksFound);
if (linksFound < 1) throw new Error("Expected at least one extracted link in email sample");

if (consoleErrors.length) {
  throw new Error("Console/page errors detected: " + consoleErrors.join(" | "));
}

console.log("\nAll smoke checks passed.");
await browser.close();
server.close();

