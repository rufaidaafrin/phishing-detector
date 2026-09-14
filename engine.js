/**
 * Phishing Heuristics Engine
 * ---------------------------------------------------------------------------
 * Pure, DOM-free rule-based analysis for URLs and email/message text.
 * No network calls, no external services, no data leaves the browser.
 *
 * This is intentionally a *heuristic* engine: it looks for known phishing
 * patterns (typosquatting, urgency language, credential harvesting cues,
 * etc.) and produces a weighted risk score. It is NOT a guarantee of safety
 * or maliciousness — treat it as a first-pass triage aid, not a verdict.
 *
 * Works identically in the browser (loaded via <script>) and in Node
 * (via module.exports), so the same logic that ships in the app can be
 * unit tested directly. See tests/engine.test.js.
 */
(function (root) {
  "use strict";

  // ---------------------------------------------------------------------
  // Reference data
  // ---------------------------------------------------------------------

  // A small set of frequently-impersonated brands and their official
  // registrable domains. Not exhaustive — meant to demonstrate the
  // technique, easy to extend.
  const BRANDS = [
    { name: "PayPal", domains: ["paypal.com"] },
    { name: "Google", domains: ["google.com"] },
    { name: "Microsoft", domains: ["microsoft.com", "live.com", "office.com", "outlook.com"] },
    { name: "Apple", domains: ["apple.com", "icloud.com"] },
    { name: "Amazon", domains: ["amazon.com"] },
    { name: "Facebook", domains: ["facebook.com", "fb.com"] },
    { name: "Instagram", domains: ["instagram.com"] },
    { name: "Netflix", domains: ["netflix.com"] },
    { name: "Bank of America", domains: ["bankofamerica.com"] },
    { name: "Chase", domains: ["chase.com"] },
    { name: "Wells Fargo", domains: ["wellsfargo.com"] },
    { name: "American Express", domains: ["americanexpress.com", "amex.com"] },
    { name: "eBay", domains: ["ebay.com"] },
    { name: "LinkedIn", domains: ["linkedin.com"] },
    { name: "Dropbox", domains: ["dropbox.com"] },
    { name: "Adobe", domains: ["adobe.com"] },
    { name: "IRS", domains: ["irs.gov"] },
    { name: "USPS", domains: ["usps.com"] },
    { name: "FedEx", domains: ["fedex.com"] },
    { name: "DHL", domains: ["dhl.com"] },
    { name: "Coinbase", domains: ["coinbase.com"] },
    { name: "Binance", domains: ["binance.com"] },
    { name: "Venmo", domains: ["venmo.com"] },
    { name: "Steam", domains: ["steampowered.com", "steamcommunity.com"] },
    { name: "Discord", domains: ["discord.com"] },
    { name: "Spotify", domains: ["spotify.com"] },
  ];

  const SUSPICIOUS_TLDS = [
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click", "link",
    "loan", "win", "review", "zip", "country", "kim", "men", "date",
    "faith", "accountant", "party", "bid", "stream", "download",
  ];

  const URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc",
  ];

  const URGENCY_PHRASES = [
    "act now", "urgent action", "immediately", "verify your account",
    "account suspended", "account will be suspended", "24 hours",
    "limited time", "act fast", "final notice", "failure to respond",
    "your account will be closed", "unauthorized access detected",
    "confirm your identity", "unusual activity", "click here now",
    "will expire", "account locked", "restore access", "avoid suspension",
  ];

  const SENSITIVE_REQUEST_PHRASES = [
    "social security number", "ssn", "credit card number", "card number",
    "cvv", "your password", "pin number", "bank account number",
    "routing number", "confirm your password", "enter your password",
    "verify your card", "one-time passcode", "one time passcode", "otp code",
  ];

  const GENERIC_GREETING_RE = /\b(dear\s+(customer|user|member|valued\s+customer|sir\s*\/\s*madam|account\s+holder))\b/i;

  const FROM_HEADER_RE = /from:\s*"?([^"<\n]+?)"?\s*<([^>]+)>/i;

  // ---------------------------------------------------------------------
  // Small utilities
  // ---------------------------------------------------------------------

  function levenshtein(a, b) {
    const m = a.length, n = b.length;
    if (m === 0) return n;
    if (n === 0) return m;
    const dp = new Array(m + 1);
    for (let i = 0; i <= m; i++) dp[i] = new Array(n + 1).fill(0);
    for (let i = 0; i <= m; i++) dp[i][0] = i;
    for (let j = 0; j <= n; j++) dp[0][j] = j;
    for (let i = 1; i <= m; i++) {
      for (let j = 1; j <= n; j++) {
        dp[i][j] = Math.min(
          dp[i - 1][j] + 1,
          dp[i][j - 1] + 1,
          dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)
        );
      }
    }
    return dp[m][n];
  }

  function isIpHost(host) {
    const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipv4.test(host)) {
      return host.split(".").every((part) => Number(part) <= 255);
    }
    // crude IPv6 literal check (brackets are stripped by URL parser already)
    return /^[0-9a-f:]+$/i.test(host) && host.includes(":");
  }

  function isOfficialOrSubdomain(host, officialDomain) {
    return host === officialDomain || host.endsWith("." + officialDomain);
  }

  function makeFlag(id, severity, title, detail) {
    return { id, severity, title, detail };
  }

  const SEVERITY_WEIGHT = { low: 1, medium: 2, high: 3 };

  function computeRisk(flags) {
    const score = flags.reduce((sum, f) => sum + (SEVERITY_WEIGHT[f.severity] || 0), 0);
    let level;
    if (score === 0) level = "clean";
    else if (score <= 2) level = "low";
    else if (score <= 5) level = "medium";
    else level = "high";
    return { score, level, flags };
  }

  // ---------------------------------------------------------------------
  // URL analysis
  // ---------------------------------------------------------------------

  function normalizeForParsing(raw) {
    let s = raw.trim();
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) {
      s = "http://" + s;
    }
    return s;
  }

  function analyzeUrl(rawUrl) {
    const flags = [];
    const input = (rawUrl || "").trim();
    if (!input) return computeRisk(flags);

    let parsed;
    try {
      parsed = new URL(normalizeForParsing(input));
    } catch (e) {
      flags.push(makeFlag("unparseable", "medium", "Could not parse as a URL",
        "The input doesn't look like a well-formed URL or domain."));
      return computeRisk(flags);
    }

    const host = parsed.hostname.toLowerCase();

    if (input.includes("@") && parsed.username) {
      flags.push(makeFlag("at-symbol", "high", "Contains an '@' in the URL",
        "Everything before the '@' is ignored by the browser — this is a classic trick to disguise the real destination host (" + host + ")."));
    }

    if (isIpHost(host)) {
      flags.push(makeFlag("ip-host", "high", "Uses a raw IP address",
        "The link points directly to an IP address (" + host + ") instead of a domain name. Legitimate sites almost never do this."));
    }

    if (host.includes("xn--")) {
      flags.push(makeFlag("punycode", "high", "Punycode / internationalized domain",
        "The domain uses Punycode encoding, which is sometimes used to display lookalike characters from other alphabets (a homograph attack)."));
    }

    const tld = host.split(".").pop();
    if (SUSPICIOUS_TLDS.includes(tld)) {
      flags.push(makeFlag("suspicious-tld", "medium", "Uncommon, low-cost top-level domain",
        "The ." + tld + " TLD is disproportionately popular with phishing and spam campaigns because it's cheap or free to register."));
    }

    if (URL_SHORTENERS.includes(host)) {
      flags.push(makeFlag("shortener", "medium", "URL shortening service",
        "This link hides its real destination behind a shortener (" + host + "). Expand it before trusting it."));
    }

    const labels = host.split(".");
    if (labels.length > 4) {
      flags.push(makeFlag("many-subdomains", "medium", "Unusually many subdomains",
        "The domain has " + labels.length + " parts. A common trick is burying a fake brand name in a subdomain, e.g. paypal.com.verify-login.xyz."));
    }

    if (host.length > 40) {
      flags.push(makeFlag("long-domain", "low", "Unusually long domain name",
        "The domain name is " + host.length + " characters long."));
    }

    const hyphenCount = (host.match(/-/g) || []).length;
    if (hyphenCount >= 2) {
      flags.push(makeFlag("many-hyphens", "low", "Multiple hyphens in the domain",
        "Domains combining a brand name with words like 'secure' or 'verify' via hyphens are a common phishing pattern."));
    }

    if (parsed.protocol === "http:") {
      flags.push(makeFlag("no-https", "medium", "Not using HTTPS",
        "Any data submitted on this page would travel unencrypted. Legitimate login or payment pages use HTTPS."));
    }

    if (parsed.port && !["80", "443", ""].includes(parsed.port)) {
      flags.push(makeFlag("nonstandard-port", "low", "Non-standard port",
        "The link specifies port " + parsed.port + ", which is unusual for a normal website."));
    }

    // Brand impersonation / typosquatting
    let isOfficial = false;
    for (const brand of BRANDS) {
      for (const d of brand.domains) {
        if (isOfficialOrSubdomain(host, d)) { isOfficial = true; break; }
      }
      if (isOfficial) break;
    }

    if (!isOfficial) {
      let matched = false;
      for (const brand of BRANDS) {
        for (const d of brand.domains) {
          const dist = levenshtein(host, d);
          if (dist > 0 && dist <= 2 && Math.abs(host.length - d.length) <= 3) {
            flags.push(makeFlag("typosquat", "high", "Looks like a typosquat of " + brand.name,
              "\"" + host + "\" is very close to " + brand.name + "'s official domain (" + d + ") but isn't an exact match — a classic typosquatting pattern."));
            matched = true;
            break;
          }
        }
        if (matched) break;
      }
      if (!matched) {
        for (const brand of BRANDS) {
          const kw = brand.name.toLowerCase().replace(/[^a-z0-9]/g, "");
          const hostAlnum = host.replace(/[^a-z0-9]/g, "");
          if (kw.length >= 4 && hostAlnum.includes(kw)) {
            flags.push(makeFlag("brand-mention", "high", "Mentions \"" + brand.name + "\" but isn't their domain",
              "The domain references " + brand.name + " but does not belong to any of " + brand.name + "'s official domains — a likely impersonation attempt."));
            matched = true;
            break;
          }
        }
      }
    }

    return computeRisk(flags);
  }

  // ---------------------------------------------------------------------
  // Email / message text analysis
  // ---------------------------------------------------------------------

  const URL_IN_TEXT_RE = /\b((?:https?:\/\/|www\.)[^\s<>"')\]]+)/gi;

  function extractUrls(text) {
    const matches = text.match(URL_IN_TEXT_RE) || [];
    // de-duplicate while preserving order
    return [...new Set(matches.map((m) => m.replace(/[.,;:!?]+$/, "")))];
  }

  function analyzeEmail(rawText) {
    const text = rawText || "";
    const lower = text.toLowerCase();
    const flags = [];

    const foundUrgency = URGENCY_PHRASES.filter((p) => lower.includes(p));
    if (foundUrgency.length) {
      flags.push(makeFlag("urgency", "medium", "Urgency / pressure language",
        "Phrases designed to rush you into acting without thinking: \"" + foundUrgency.slice(0, 3).join("\", \"") + "\"" + (foundUrgency.length > 3 ? ", and more." : ".")));
    }

    const foundSensitive = SENSITIVE_REQUEST_PHRASES.filter((p) => lower.includes(p));
    if (foundSensitive.length) {
      flags.push(makeFlag("sensitive-request", "high", "Requests sensitive information",
        "Legitimate organizations don't ask for this over email: \"" + foundSensitive.slice(0, 3).join("\", \"") + "\"" + (foundSensitive.length > 3 ? ", and more." : ".")));
    }

    if (GENERIC_GREETING_RE.test(text)) {
      flags.push(makeFlag("generic-greeting", "low", "Generic greeting",
        "Addresses you as \"Customer\", \"User\", or similar instead of your name — typical of mass phishing sends."));
    }

    const fromMatch = text.match(FROM_HEADER_RE);
    if (fromMatch) {
      const displayName = fromMatch[1].toLowerCase();
      const fromEmail = fromMatch[2].toLowerCase();
      const emailDomain = (fromEmail.split("@")[1] || "").trim();
      for (const brand of BRANDS) {
        const kw = brand.name.toLowerCase().replace(/[^a-z0-9]/g, "");
        if (kw.length >= 4 && displayName.replace(/[^a-z0-9]/g, "").includes(kw)) {
          const matchesOfficial = brand.domains.some((d) => isOfficialOrSubdomain(emailDomain, d));
          if (!matchesOfficial) {
            flags.push(makeFlag("sender-mismatch", "high", "Sender name doesn't match sender domain",
              "The \"From\" name claims to be " + brand.name + ", but the email address (" + fromEmail + ") isn't on any of " + brand.name + "'s official domains."));
          }
          break;
        }
      }
    }

    const urls = extractUrls(text);
    const urlResults = urls.map((u) => ({ url: u, result: analyzeUrl(u) }));
    for (const { url, result } of urlResults) {
      for (const f of result.flags) {
        flags.push(makeFlag(f.id + ":" + url, f.severity, f.title + " (in link: " + url + ")", f.detail));
      }
    }

    const risk = computeRisk(flags);
    risk.urls = urlResults;
    return risk;
  }

  // ---------------------------------------------------------------------
  // Exports
  // ---------------------------------------------------------------------

  const api = { analyzeUrl, analyzeEmail, computeRisk, levenshtein, extractUrls, BRANDS };

  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  } else {
    root.PhishingHeuristics = api;
  }
})(typeof window !== "undefined" ? window : globalThis);

