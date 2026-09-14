(function () {
  "use strict";
  const { analyzeUrl, analyzeEmail } = window.PhishingHeuristics;

  const tabs = document.querySelectorAll(".tab");
  const panels = { url: document.getElementById("panel-url"), email: document.getElementById("panel-email") };
  tabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      tabs.forEach((t) => { t.classList.remove("active"); t.setAttribute("aria-selected", "false"); });
      tab.classList.add("active");
      tab.setAttribute("aria-selected", "true");
      Object.entries(panels).forEach(([key, panel]) => { panel.hidden = key !== tab.dataset.tab; });
    });
  });

  const urlInput = document.getElementById("url-input");
  const emailInput = document.getElementById("email-input");
  const resultsEl = document.getElementById("results");
  const emptyStateEl = document.getElementById("empty-state");

  document.getElementById("scan-url-btn").addEventListener("click", () => {
    const val = urlInput.value.trim();
    if (!val) return;
    render(analyzeUrl(val), "url", false);
  });

  document.getElementById("scan-email-btn").addEventListener("click", () => {
    const val = emailInput.value.trim();
    if (!val) return;
    render(analyzeEmail(val), "email", false);
  });

  document.getElementById("clear-btn-url").addEventListener("click", () => {
    urlInput.value = "";
    clearResults();
    urlInput.focus();
  });
  document.getElementById("clear-btn-email").addEventListener("click", () => {
    emailInput.value = "";
    clearResults();
    emailInput.focus();
  });

  const SAMPLES = {
    "url-bad": "http://secure-paypal-login-verify-account.tk/signin",
    "url-good": "https://www.paypal.com/signin",
    "email-bad":
      'From: "PayPal Support" <support@paypal-alert-secure.tk>\n' +
      "Dear Customer,\n\n" +
      "We detected unusual activity on your account. Your account will be suspended within 24 hours " +
      "unless you verify your account immediately.\n\n" +
      "Click here now: http://paypal-alert-secure.tk/verify\n\n" +
      "Please confirm your password and card number to restore access.",
  };

  document.querySelectorAll("[data-sample]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const kind = btn.dataset.sample;
      if (kind === "url-bad" || kind === "url-good") {
        urlInput.value = SAMPLES[kind];
        render(analyzeUrl(urlInput.value), "url", false);
      } else if (kind === "email-bad") {
        emailInput.value = SAMPLES[kind];
        render(analyzeEmail(emailInput.value), "email", false);
      }
    });
  });

  function clearResults() {
    resultsEl.innerHTML = "";
    emptyStateEl.hidden = false;
  }

  const LEVEL_META = {
    clean: { label: "No red flags found", cls: "level-clean", color: "var(--clean)", bg: "var(--clean-bg)" },
    low: { label: "Low risk", cls: "level-low", color: "var(--low)", bg: "var(--low-bg)" },
    medium: { label: "Medium risk", cls: "level-medium", color: "var(--medium)", bg: "var(--medium-bg)" },
    high: { label: "High risk", cls: "level-high", color: "var(--high)", bg: "var(--high-bg)" },
  };

  function render(risk, kind, isExample) {
    emptyStateEl.hidden = true;
    const meta = LEVEL_META[risk.level];
    const meterPct = Math.min(100, (risk.score / 10) * 100);

    const flagsHtml = risk.flags.length
      ? risk.flags
          .map(
            (f) => `
        <li class="flag flag-${f.severity}">
          <span class="flag-sev">${f.severity}</span>
          <div>
            <div class="flag-title">${escapeHtml(f.title)}</div>
            <div class="flag-detail">${escapeHtml(f.detail)}</div>
          </div>
        </li>`
          )
          .join("")
      : `<li class="flag flag-clean"><div><div class="flag-title">No heuristic red flags matched.</div>
          <div class="flag-detail">That's a good sign, but it isn't a guarantee — sophisticated phishing can still slip past pattern-based checks. Always verify through an official, independently-typed URL.</div></div></li>`;

    let linksSection = "";
    if (kind === "email" && risk.urls && risk.urls.length) {
      linksSection = `
        <div class="links-found">
          <div class="section-label">Links found in message (${risk.urls.length})</div>
          <ul class="link-list">
            ${risk.urls
              .map(
                (u) =>
                  `<li><code>${escapeHtml(u.url)}</code> — <span class="pill pill-${u.result.level}">${LEVEL_META[u.result.level].label}</span></li>`
              )
              .join("")}
          </ul>
        </div>`;
    }

    resultsEl.innerHTML = `
      ${isExample ? '<span class="example-tag">Example scan — try your own above</span>' : ""}
      <div class="risk-banner" style="background:${meta.bg};color:${meta.color}">
        <div class="risk-label">${meta.label}</div>
        <div class="risk-score-block">
          <div class="risk-score">${risk.score}</div>
          <div class="risk-score-caption">heuristic score</div>
        </div>
      </div>
      <div class="meter">
        <div class="meter-track"><div class="meter-fill" style="width:${meterPct}%;background:${meta.color}"></div></div>
        <div class="meter-labels"><span>0 clean</span><span>3 medium</span><span>6+ high</span></div>
      </div>
      ${linksSection}
      <ul class="flags-list">${flagsHtml}</ul>
      <p class="disclaimer">This is an educational, rule-based heuristic tool — not a verdict. Never enter
      credentials or payment details into a site you reached by clicking a link; navigate there yourself instead.</p>
    `;
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  // Show the tool already working on first load, clearly marked as an example.
  urlInput.value = SAMPLES["url-bad"];
  render(analyzeUrl(urlInput.value), "url", true);
})();

