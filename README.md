# Phish Check

A lightweight, client-side phishing detector: paste a suspicious URL or the
full text of an email, and get back an instant risk score with a plain-English
explanation of every red flag found. No backend, no accounts, no data leaves
the browser — the whole thing is static HTML/CSS/JS.

**Live demo →** `https://rufaidaafrin.github.io/phishing-detector/` (enable GitHub Pages — see below)

## Why

Phishing is still the #1 initial access vector in most breach reports, and
recognizing it is a core blue-team / SOC-analyst skill. This project is both:

- a small, genuinely useful tool — paste a link before you click it, or an
  email before you act on it, and get a second opinion in under a second;
- a demonstration of applied detection engineering — the same
  "known-pattern → weighted signal → risk score" approach used in real
  phishing/URL-reputation and SIEM detection rules, just built small enough
  to read end to end.

## What it checks

**URLs**

| Check | Why it matters |
|---|---|
| Raw IP address instead of a domain | Legitimate sites almost never link this way |
| Typosquatting | Levenshtein distance against a list of commonly-impersonated brand domains (`paypa1.com` vs `paypal.com`) |
| Brand name in an unrelated domain | e.g. `secure-paypal-login.xyz` |
| Punycode / `xn--` domains | Common homograph-attack vector |
| `@` in the URL | Everything before `@` is ignored by the browser — used to disguise the real host |
| Suspicious/low-cost TLDs | `.tk`, `.xyz`, `.top`, etc. are disproportionately used in phishing |
| URL shorteners | Hides the real destination |
| Excessive subdomains | e.g. `paypal.com.verify-login.xyz` |
| Missing HTTPS | No encryption for anything submitted |
| Non-standard ports, unusually long domains, many hyphens | Secondary signals |

**Email / message text** — all of the above, run against every link found in
the message, plus:

| Check | Why it matters |
|---|---|
| Urgency / pressure language | "act now", "account suspended", "24 hours" — designed to short-circuit careful reading |
| Requests for sensitive data | passwords, card numbers, SSNs, OTP codes |
| Generic greeting | "Dear Customer" instead of a real name — typical of mass sends |
| Sender name/domain mismatch | `From: "PayPal Support" <support@paypal-alert.tk>` |

Each finding is weighted (`low` / `medium` / `high`) and summed into an
overall **Clean / Low / Medium / High** risk rating.

## Honest limitations

This is a **heuristic, rule-based** tool, not a machine-learning classifier
and not a threat-intel feed. It will:

- miss well-crafted phishing that avoids every listed pattern (false negative)
- occasionally flag an unusual-but-legitimate domain (false positive)
- only recognize the ~25 brands currently in `engine.js`'s `BRANDS` list

Treat its output as a fast first-pass triage aid, not a verdict — and never
enter credentials into a site you reached by clicking a link, regardless of
what any tool says.

## Running it locally

No build step, no dependencies:

```bash
git clone https://github.com/rufaidaafrin/phishing-detector.git
cd phishing-detector
python3 -m http.server 8000   # or: npx serve
# open http://localhost:8000
```

You can also just double-click `index.html` — everything is inline/relative,
no server required for basic use (some browsers restrict local `file://`
script loading, so a static server is more reliable).

## Deployment

This repo is a static site, so it deploys for free on GitHub Pages:

1. Go to **Settings → Pages** in this repository.
2. Under **Build and deployment**, set **Source** to `Deploy from a branch`,
   branch `main`, folder `/ (root)`.
3. Save — GitHub will publish it at
   `https://rufaidaafrin.github.io/phishing-detector/` within a minute or two.

## Tests

The detection logic (`engine.js`) is DOM-free and unit tested with plain
Node — no test framework dependency:

```bash
node tests/engine.test.js
```

A browser-level smoke test (Playwright) exercises the actual UI:

```bash
npm install playwright
node tests/smoke.mjs
```

## Project structure

```
index.html          the app (structure + styles)
engine.js            pure heuristic detection logic (no DOM) — the interesting part
app.js               UI wiring: reads input, calls engine.js, renders results
tests/engine.test.js  unit tests for the detection logic
tests/smoke.mjs       headless-browser smoke test for the full UI
```

## Roadmap

- [ ] Lightweight ML classifier (logistic regression / small gradient-boosted
      model trained on a public phishing-URL dataset) as a second opinion
      alongside the rule-based score
- [ ] Expand the brand list and load it from a JSON file instead of inline
- [ ] Browser extension wrapper (right-click a link → "Check with Phish
      Check") using the same `engine.js`
- [ ] Bulk/CSV scanning mode for a list of URLs

## License

MIT — see [LICENSE](LICENSE).

