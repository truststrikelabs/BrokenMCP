(function () {
  const CANONICAL_ORIGIN = "http://127.0.0.1:8410";

  const completedLabChallenges = new Set();

  let CONFIG = null;
  let CHALLENGES = [];
  let CHALLENGE_ORDER = [];
  let API_BASE = "";
  let labRunId = "";

  let loadToken = 0;
  let pendingLabId = "";

  class OfflineError extends Error {}

  const STATUS_INTERVAL = 5000;
  let REGISTRY = [];
  let labStatuses = {};
  const busyLabs = new Set();
  let pendingCommands = "";
  let lastKnownRunning = null;
  let connecting = false;

  const elements = {
    labNav: document.querySelector("#labNav"),
    challengeList: document.querySelector("#challengeList"),
    toast: document.querySelector("#toast"),
    sidebar: document.querySelector("#sidebar"),
    sidebarScrim: document.querySelector("#sidebarScrim"),
    topbarChallengeProgress: document.querySelector("#topbarChallengeProgress"),
    incidentReport: document.querySelector("#incidentReport"),
    labStatus: document.querySelector("#labStatus"),
    statusText: document.querySelector("#statusText"),
    statusServer: document.querySelector("#statusServer"),
    statusEndpoint: document.querySelector("#statusEndpoint"),
    statusFlags: document.querySelector("#statusFlags"),
    statusToggle: document.querySelector("#statusToggle"),
    statusPrimary: document.querySelector("#statusPrimary"),
    statusDetail: document.querySelector("#statusDetail"),
    statusDetailText: document.querySelector("#statusDetailText"),
    statusCommands: document.querySelector("#statusCommands"),
    statusCommandsCode: document.querySelector("#statusCommandsCode"),
    onlineDot: document.querySelector("#onlineDot"),
  };

  function startCommands() {
    return [
      "pip3 install -r requirements.txt --break-system-packages",
      "cd " + CONFIG.folder,
      "python3 run.py --reset",
    ].join("\n");
  }

  function originProblem() {
    if (window.location.protocol === "file:") return "file";
    if (window.location.origin !== CANONICAL_ORIGIN) return "origin";
    return null;
  }

  function firstBuiltLabId() {
    const built = REGISTRY.find((lab) => lab.built);
    return built ? built.id : "";
  }

  function requestedLabId() {
    const raw = new URLSearchParams(window.location.search).get("lab") || "";
    const cleaned = raw.trim().toLowerCase();
    if (!/^mcp\d{2}$/.test(cleaned)) return firstBuiltLabId();
    const entry = labEntry(cleaned);
    return entry && entry.built ? cleaned : firstBuiltLabId();
  }

  function renderSidebar(activeId) {
    elements.labNav.innerHTML = "";
    REGISTRY.forEach((lab) => {
      const item = document.createElement("button");
      item.type = "button";
      item.className = "nav-item" + (lab.built ? "" : " planned");
      item.disabled = !lab.built;
      if (lab.id === activeId) item.classList.add("active");
      item.dataset.labId = lab.id;
      item.title = lab.built
        ? lab.title
        : lab.title + " (planned, port " + lab.port + " reserved)";

      const icon = document.createElement("span");
      icon.className = "nav-icon";
      icon.setAttribute("aria-hidden", "true");
      icon.textContent = String(lab.n).padStart(2, "0");

      const name = document.createElement("span");
      name.textContent = labCode(lab.n);

      const meta = document.createElement("span");
      meta.className = "nav-meta";
      if (lab.built) {
        const dot = document.createElement("span");
        dot.className = "nav-dot";
        dot.dataset.labDot = lab.id;
        dot.title = "Checking";
        const count = document.createElement("span");
        count.className = "nav-count";
        count.dataset.labCount = lab.id;
        const total = lab.challenges || 0;
        count.textContent = total ? `0/${total}` : "";
        meta.append(dot, count);
      } else {
        const soon = document.createElement("span");
        soon.className = "nav-soon";
        soon.textContent = "Soon";
        meta.append(soon);
      }

      item.append(icon, name, meta);
      elements.labNav.append(item);
    });
    renderSidebarCounts();
  }

  function renderControls() {
    if (!CONFIG) return;
    const row = labStatuses[CONFIG.id];
    const running = Boolean(row && row.running);
    const managed = Boolean(row && row.managed);
    const button = elements.statusToggle;

    if (busyLabs.has(CONFIG.id)) {
      button.textContent = "Working...";
      button.disabled = true;
      button.title = "";
      return;
    }

    button.disabled = false;
    if (!running) {
      button.textContent = "Start lab";
      button.title = "Run this lab from the GUI";
    } else if (managed) {
      button.textContent = "Stop lab";
      button.title = "Stop the lab this GUI started";
    } else {
      button.textContent = "Stop lab";
      button.disabled = true;
      button.title = "This lab was started outside the GUI, so stop it where you started it";
    }
  }

  async function control(labId, action) {
    busyLabs.add(labId);
    renderControls();
    try {
      const response = await fetch(`api/labs/${labId}/${action}`, { method: "POST" });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(body.error || "That did not work");

      const settled = await waitForState(labId, action === "start");
      showToast(
        settled
          ? action === "start" ? "Lab started" : "Lab stopped"
          : action === "start" ? "The lab is taking longer than expected" : "The lab did not stop",
      );
    } catch (error) {
      showToast(error.message);
    } finally {
      busyLabs.delete(labId);
      const rows = await refreshLabStatuses();
      const up = Boolean(rows[labId] && rows[labId].running);
      if (up && CONFIG && CONFIG.id === labId) await connect();
      renderControls();
    }
  }

  function wait(ms) {
    return new Promise((resolve) => window.setTimeout(resolve, ms));
  }

  async function waitForState(labId, wantRunning) {
    for (let attempt = 0; attempt < 60; attempt += 1) {
      await wait(500);
      const rows = await refreshLabStatuses();
      const row = rows[labId];
      if (Boolean(row && row.running) === wantRunning) return true;
    }
    return false;
  }

  function labCode(n) {
    return "MCP" + String(n).padStart(2, "0") + ":2025";
  }

  function labEntry(id) {
    return REGISTRY.find((lab) => lab.id === id) || null;
  }

  function completedCount(lab) {
    const row = labStatuses[lab.id];
    const runId = row && row.run_id;
    if (!lab.storageKey || !runId) return 0;
    try {
      const saved = JSON.parse(localStorage.getItem(`${lab.storageKey}-${runId}`) || "{}");
      return Array.isArray(saved.completed) ? saved.completed.length : 0;
    } catch {
      return 0;
    }
  }

  function renderSidebarCounts() {
    REGISTRY.filter((lab) => lab.built).forEach((lab) => {
      const node = document.querySelector(`[data-lab-count="${lab.id}"]`);
      if (!node) return;
      const total = lab.challenges || 0;
      const done = lab.id === CONFIG?.id ? completedLabChallenges.size : completedCount(lab);
      node.textContent = total ? `${done}/${total}` : "";
    });
  }

  async function refreshLabStatuses() {
    let rows = [];
    try {
      const response = await fetch("api/labs", { cache: "no-store" });
      if (response.ok) rows = await response.json();
    } catch {
      rows = [];
    }
    labStatuses = {};
    rows.forEach((row) => {
      labStatuses[row.id] = row;
    });

    REGISTRY.filter((lab) => lab.built).forEach((lab) => {
      const dot = document.querySelector(`[data-lab-dot="${lab.id}"]`);
      if (!dot) return;
      const row = labStatuses[lab.id];
      const up = Boolean(row && row.running);
      dot.classList.toggle("up", up);
      dot.title = up ? "Running on " + lab.port : "Not running";
    });
    renderSidebarCounts();

    if (CONFIG) {
      const row = labStatuses[CONFIG.id];
      const running = Boolean(row && row.running);
      if (running !== lastKnownRunning) {
        if (running) {
          if (!connecting && !originProblem()) {
            connecting = true;
            const token = loadToken;
            connect().finally(() => {
              connecting = false;
              if (token !== loadToken) {
                labRunId = "";
              }
            });
          }
        } else {
          labRunId = "";
          setOffline(true);
        }
      }
      renderControls();
    }
    return labStatuses;
  }

  function loadScript(src) {
    return new Promise((resolve, reject) => {
      const script = document.createElement("script");
      script.src = src;
      const cleanup = () => script.remove();
      script.onload = () => {
        cleanup();
        resolve();
      };
      script.onerror = () => {
        cleanup();
        reject(new Error("Could not load " + src));
      };
      document.head.append(script);
    });
  }

  async function api(path, options = {}) {
    let response;
    try {
      response = await fetch(API_BASE + path, {
        headers: { "Content-Type": "application/json", ...(options.headers || {}) },
        ...options,
      });
    } catch {
      setOffline(true);
      throw new OfflineError("unreachable");
    }
    let body = {};
    try {
      body = await response.json();
    } catch {
      body = {};
    }
    if (!response.ok) {
      setOffline(false);
      throw new Error(body.error || `The lab refused that request (${response.status})`);
    }
    setOffline(false);
    return body;
  }

  function escapeHtml(value = "") {
    return String(value)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  function showToast(message) {
    elements.toast.textContent = message;
    elements.toast.classList.add("show");
    window.clearTimeout(showToast.timer);
    showToast.timer = window.setTimeout(() => elements.toast.classList.remove("show"), 2200);
  }

  function setText(id, value) {
    const node = document.querySelector("#" + id);
    if (node) node.textContent = value;
  }

  function fillList(id, items, tag) {
    const host = document.querySelector("#" + id);
    if (!host) return;
    host.innerHTML = "";
    items.forEach((item) => {
      const node = document.createElement(tag);
      node.textContent = item;
      host.append(node);
    });
  }

  function applyConfig() {
    const total = CHALLENGE_ORDER.length;
    document.title = "BrokenMCP Corp - " + CONFIG.org;
    setText("brandOrg", CONFIG.org);
    setText("avatar", CONFIG.avatar);
    setText("serverName", CONFIG.server);
    setText("serverEndpoint", "127.0.0.1:" + CONFIG.port + "/mcp");
    setText("statusServer", CONFIG.server);
    setText("statusEndpoint", "http://127.0.0.1:" + CONFIG.port + "/mcp");
    setText("topbarCode", CONFIG.code);
    setText("topbarTitle", CONFIG.title);
    setText("incidentReportTitle", CONFIG.reportTitle);
    setText("reportLabel", CONFIG.reportLabel);
    setText("reportSeverity", CONFIG.severity);
    setText("reportFlags", total + "/" + total);
    setText("topbarChallengeProgress", "0/" + total);
    fillList("reportEvidence", CONFIG.evidence, "li");
    fillList("reportFixes", CONFIG.fixes, "li");
    const brief = CONFIG.brief;
    const briefHost = document.querySelector("#labBrief");
    if (briefHost && brief) {
      fillParagraphs("briefBackground", brief.background);
      fillParagraphs("briefRole", brief.role);
      setCodeBlock("briefCommandBlock", "briefCommand", brief.command);
      setCodeBlock("briefOutputBlock", "briefOutput", brief.output);
      briefHost.classList.remove("hidden");
      initOutputScrollbar();
    }
  }

  function initOutputScrollbar() {
    const pre = document.querySelector("#briefOutputBlock");
    const rail = document.querySelector("#briefOutputRail");
    const thumb = document.querySelector("#briefOutputThumb");
    if (!pre || !rail || !thumb) return;

    function sync() {
      const overflow = pre.scrollWidth - pre.clientWidth;
      if (overflow <= 1 || pre.classList.contains("hidden")) {
        rail.classList.remove("is-active");
        return;
      }
      rail.classList.add("is-active");
      const railWidth = rail.clientWidth;
      const thumbWidth = Math.max(32, railWidth * (pre.clientWidth / pre.scrollWidth));
      const maxLeft = railWidth - thumbWidth;
      thumb.style.width = thumbWidth + "px";
      thumb.style.left = (maxLeft > 0 ? (pre.scrollLeft / overflow) * maxLeft : 0) + "px";
    }

    if (!initOutputScrollbar.bound) {
      let startX = 0;
      let startLeft = 0;
      let dragging = false;

      pre.addEventListener("scroll", sync);
      window.addEventListener("resize", sync);

      thumb.addEventListener("pointerdown", (event) => {
        dragging = true;
        startX = event.clientX;
        startLeft = parseFloat(thumb.style.left) || 0;
        thumb.classList.add("dragging");
        thumb.setPointerCapture(event.pointerId);
        event.preventDefault();
      });
      thumb.addEventListener("pointermove", (event) => {
        if (!dragging) return;
        const railWidth = rail.clientWidth;
        const maxLeft = railWidth - thumb.offsetWidth;
        const overflow = pre.scrollWidth - pre.clientWidth;
        const left = Math.min(maxLeft, Math.max(0, startLeft + (event.clientX - startX)));
        pre.scrollLeft = maxLeft > 0 ? (left / maxLeft) * overflow : 0;
      });
      const stopDrag = (event) => {
        if (!dragging) return;
        dragging = false;
        thumb.classList.remove("dragging");
        try {
          thumb.releasePointerCapture(event.pointerId);
        } catch (err) {
          void err;
        }
      };
      thumb.addEventListener("pointerup", stopDrag);
      thumb.addEventListener("pointercancel", stopDrag);

      initOutputScrollbar.bound = true;
    }

    if (window.requestAnimationFrame) {
      window.requestAnimationFrame(sync);
    } else {
      sync();
    }
  }

  function fillParagraphs(id, value) {
    const host = document.querySelector("#" + id);
    if (!host) return;
    host.innerHTML = "";
    const items = Array.isArray(value) ? value : value ? [value] : [];
    items.forEach((text) => {
      const node = document.createElement("p");
      node.textContent = text;
      host.append(node);
    });
  }

  function setCodeBlock(blockId, codeId, value) {
    const block = document.querySelector("#" + blockId);
    if (!block) return;
    const items = Array.isArray(value) ? value : value ? [value] : [];
    if (!items.length) {
      block.classList.add("hidden");
      return;
    }
    setText(codeId, items.join("\n"));
    block.classList.remove("hidden");
  }

  function renderChallengeMarkup() {
    elements.challengeList.innerHTML = CHALLENGES.map((challenge, index) => {
      const number = index + 1;
      const inputId = `challengeFlag${number}`;
      return `
      <article class="lab-step" data-challenge-id="${escapeHtml(challenge.id)}">
        <span class="lab-step-number" aria-hidden="true">${number}</span>
        <div class="lab-step-body">
          <div class="lab-step-heading">
            <div class="challenge-title">
              <h3>${escapeHtml(challenge.title)}</h3>
            </div>
            <div class="challenge-heading-meta">
              <span class="difficulty-tag ${escapeHtml(challenge.difficultyClass)}">${escapeHtml(challenge.difficulty)}</span>
              <span class="challenge-complete-check hidden" data-complete-check="${escapeHtml(challenge.id)}" role="img" aria-label="Challenge completed" title="Completed">✓</span>
            </div>
          </div>
          <div class="lab-task">
            <strong>Goal</strong>
            <p>${escapeHtml(challenge.task)}</p>
          </div>
          <form class="flag-form" data-flag-form data-challenge-id="${escapeHtml(challenge.id)}">
            <label for="${inputId}">Challenge ${number} flag</label>
            <div class="flag-entry">
              <input id="${inputId}" name="flag" type="text" placeholder="FLAG{...}" autocomplete="off" spellcheck="false" required />
              <button class="primary-button" type="submit">Submit flag</button>
            </div>
            <p class="flag-feedback" aria-live="polite"></p>
          </form>
        </div>
      </article>`;
    }).join("");

    document.querySelectorAll("[data-flag-form]").forEach((form) => {
      form.addEventListener("submit", async (event) => {
        event.preventDefault();
        await submitLabFlag(form);
      });
    });
  }

  function labStorageKey() {
    return `${CONFIG.storageKey}-${labRunId}`;
  }

  function isChallengeUnlocked(challengeId) {
    return CHALLENGE_ORDER.includes(challengeId);
  }

  function renderLabProgress() {
    const total = CHALLENGE_ORDER.length;
    const complete = completedLabChallenges.size;
    const compactProgress = `${complete}/${total}`;
    renderSidebarCounts();
    elements.topbarChallengeProgress.textContent = compactProgress;
    elements.statusFlags.textContent = `${complete} / ${total}`;
    elements.incidentReport.classList.add("hidden");
  }

  function renderChallengeStates() {
    CHALLENGE_ORDER.forEach((challengeId) => {
      const complete = completedLabChallenges.has(challengeId);
      const step = document.querySelector(`.lab-step[data-challenge-id="${challengeId}"]`);
      const form = document.querySelector(`[data-flag-form][data-challenge-id="${challengeId}"]`);
      const completeCheck = document.querySelector(`[data-complete-check="${challengeId}"]`);
      if (!step || !form || !completeCheck) return;

      step.classList.toggle("completed", complete);
      completeCheck.classList.toggle("hidden", !complete);

      const input = form.querySelector("input");
      const submit = form.querySelector('button[type="submit"]');
      input.disabled = complete;
      submit.disabled = complete;
      submit.textContent = complete ? "Completed" : "Submit flag";
    });
  }

  function renderMission() {
    renderChallengeStates();
    renderLabProgress();
  }

  function forgetOtherRuns() {
    const prefix = `${CONFIG.storageKey}-`;
    const keep = labStorageKey();
    Object.keys(localStorage)
      .filter((key) => key.startsWith(prefix) && key !== keep)
      .forEach((key) => localStorage.removeItem(key));
  }

  function loadLabProgress() {
    completedLabChallenges.clear();
    let saved = { completed: [] };
    try {
      saved = JSON.parse(localStorage.getItem(labStorageKey()) || "{}") || saved;
    } catch {
      saved = { completed: [] };
    }
    (saved.completed || [])
      .filter((challengeId) => CHALLENGE_ORDER.includes(challengeId))
      .forEach((challengeId) => completedLabChallenges.add(challengeId));
    renderMission();
  }

  function saveLabProgress() {
    if (labRunId) {
      localStorage.setItem(
        labStorageKey(),
        JSON.stringify({ completed: [...completedLabChallenges] }),
      );
    }
    renderMission();
  }

  async function resetMission() {
    if (!CONFIG) return;
    try {
      const previousStorageKey = labStorageKey();
      const result = await api("/api/lab/reset", { method: "POST", body: "{}" });
      localStorage.removeItem(previousStorageKey);
      labRunId = result.run_id;
      completedLabChallenges.clear();
      document.querySelectorAll("[data-flag-form]").forEach((form) => {
        form.reset();
        const feedback = form.querySelector(".flag-feedback");
        feedback.className = "flag-feedback";
        feedback.textContent = "";
      });
      saveLabProgress();
      showToast("Progress reset with fresh flags");
    } catch (error) {
      showToast(error instanceof OfflineError ? "The lab is not reachable" : error.message);
    }
  }

  async function submitLabFlag(form) {
    const challengeId = form.dataset.challengeId;
    const input = form.querySelector('input[name="flag"]');
    const button = form.querySelector('button[type="submit"]');
    const feedback = form.querySelector(".flag-feedback");
    const candidate = input.value.trim();
    if (!candidate || !isChallengeUnlocked(challengeId)) return;

    button.disabled = true;
    button.textContent = "Checking...";
    feedback.className = "flag-feedback";
    feedback.textContent = "";

    try {
      const result = await api("/api/lab/submit", {
        method: "POST",
        body: JSON.stringify({ challenge_id: challengeId, flag: candidate }),
      });
      if (!result.correct) {
        feedback.className = "flag-feedback error";
        feedback.textContent = "Incorrect flag. Check the MCP response and try again.";
        input.focus();
        input.select();
        return;
      }

      const challengeNumber = CHALLENGE_ORDER.indexOf(challengeId) + 1;
      completedLabChallenges.add(challengeId);
      saveLabProgress();
      const completeCount = completedLabChallenges.size;
      feedback.className = "flag-feedback success";
      feedback.textContent = completeCount === CHALLENGE_ORDER.length
        ? `Flag accepted. All ${CHALLENGE_ORDER.length} challenges complete.`
        : `Flag accepted. ${completeCount} of ${CHALLENGE_ORDER.length} complete.`;
      if (completeCount !== CHALLENGE_ORDER.length) {
        showToast(`Challenge ${challengeNumber} complete`);
      }
    } catch (error) {
      feedback.className = "flag-feedback error";
      feedback.textContent = error instanceof OfflineError
        ? "The lab stopped responding. Check that it is still running."
        : error.message;
    } finally {
      if (!completedLabChallenges.has(challengeId)) {
        button.disabled = false;
        button.textContent = "Submit flag";
      }
    }
  }

  async function copyText(text, done) {
    try {
      await navigator.clipboard.writeText(text);
      showToast(done);
    } catch {
      showToast("Could not copy");
    }
  }

  function closeSidebar() {
    elements.sidebar.classList.remove("open");
    elements.sidebarScrim.classList.remove("show");
  }

  function setDetail(text, commands) {
    const nextText = text || "";
    const nextCommands = commands || "";
    const unchanged =
      nextText === elements.statusDetailText.textContent && nextCommands === pendingCommands;
    if (unchanged) {
      updateDetailVisibility();
      return;
    }

    pendingCommands = nextCommands;
    elements.statusDetailText.textContent = nextText;
    elements.statusDetailText.classList.toggle("hidden", !nextText);
    elements.statusCommandsCode.textContent = nextCommands;
    elements.statusCommands.classList.add("hidden");
    elements.statusPrimary.textContent = "Show commands";
    updateDetailVisibility();
  }

  function commandsShown() {
    return !elements.statusCommands.classList.contains("hidden");
  }

  function updateDetailVisibility() {
    const hasText = Boolean(elements.statusDetailText.textContent);
    elements.statusDetail.classList.toggle("hidden", !hasText && !commandsShown());
  }

  function toggleCommands(show) {
    elements.statusCommands.classList.toggle("hidden", !show);
    elements.statusPrimary.textContent = show ? "Hide commands" : "Show commands";
    updateDetailVisibility();
  }

  function setStatus(state, label) {
    elements.labStatus.dataset.state = state;
    elements.statusText.textContent = label;
    elements.onlineDot.classList.toggle("offline", state !== "up");
    elements.onlineDot.title = state === "up" ? "Lab available" : "Lab unreachable";
  }

  function setOffline(isOffline) {
    lastKnownRunning = !isOffline;

    if (!isOffline) {
      setStatus("up", "Running");
      elements.statusPrimary.textContent = "Copy endpoint";
      elements.statusPrimary.classList.remove("hidden");
      setDetail("", "");
      return;
    }

    setStatus("down", "Not running");
    elements.statusPrimary.textContent = "Show commands";
    elements.statusPrimary.classList.remove("hidden");

    const problem = originProblem();
    if (problem === "file") {
      setStatus("down", "Blocked");
      setDetail(
        "This page was opened straight from disk. The labs only accept browser requests from " +
          CANONICAL_ORIGIN + ", so start the GUI server and open that address instead.",
        "python3 gui/run.py",
      );
    } else if (problem === "origin") {
      setStatus("down", "Blocked");
      setDetail(
        "The labs only accept browser requests from " + CANONICAL_ORIGIN + ", but this page is on " +
          window.location.origin + ". Restart the GUI on its default port and use that address.",
        "python3 gui/run.py",
      );
    } else {
      setDetail("", startCommands());
    }
  }

  async function connect() {
    try {
      const data = await api("/api/lab/state");
      if (!data || typeof data.run_id !== "string") {
        throw new Error("The lab replied without a run id");
      }
      labRunId = data.run_id;
      forgetOtherRuns();
      loadLabProgress();
    } catch (error) {
      if (!(error instanceof OfflineError)) {
        setOffline(true);
        setStatus("down", "Error");
        setDetail(error.message, "");
      }
      renderMission();
    }
  }

  function fail(title, detail) {
    elements.challengeList.innerHTML = "";
    setStatus("down", title);
    setDetail(detail, "");
    elements.statusPrimary.classList.add("hidden");
  }

  const REQUIRED_LAB_FIELDS = ["folder", "server", "org", "avatar", "port"];

  async function openLab(labId, { push = false } = {}) {
    const token = ++loadToken;
    const stale = () => token !== loadToken;
    pendingLabId = labId;

    const entry = labEntry(labId);
    if (!entry || !entry.built) {
      fail("Unknown lab.", "Pick one of the built labs in the sidebar.");
      return;
    }
    const missing = REQUIRED_LAB_FIELDS.filter((field) => entry[field] === undefined);
    if (missing.length) {
      fail("This lab is not configured.", "registry.json is missing " + missing.join(", ") + ".");
      return;
    }

    CONFIG = null;
    labRunId = "";
    lastKnownRunning = null;
    completedLabChallenges.clear();
    renderSidebar(labId);
    setStatus("checking", "Checking");
    setDetail("", "");
    elements.incidentReport.classList.add("hidden");
    closeSidebar();

    delete window.LAB_CONFIG;
    try {
      await loadScript("labs/" + labId + ".js");
    } catch (error) {
      if (stale()) return;
      fail("Could not load this lab.", error.message);
      return;
    }
    if (stale()) return;

    const content = window.LAB_CONFIG;
    if (!content || content.id !== labId || !Array.isArray(content.challenges) || content.challenges.length === 0) {
      fail("This lab's data file is broken.", "labs/" + labId + ".js did not define its challenges.");
      return;
    }

    CONFIG = { ...entry, ...content, code: labCode(entry.n) };
    CHALLENGES = CONFIG.challenges;
    CHALLENGE_ORDER = CHALLENGES.map((challenge) => challenge.id);
    API_BASE = "http://127.0.0.1:" + CONFIG.port;

    if (push) {
      window.history.pushState({ lab: labId }, "", "?lab=" + labId);
    }

    applyConfig();
    renderChallengeMarkup();
    await refreshLabStatuses();
    if (stale()) return;
    await connect();
  }

  async function boot() {
    if (originProblem() === "file") {
      fail(
        "Open this page through the GUI server.",
        "It was opened straight from disk, so it cannot read its own files or reach any lab. " +
          "Run python3 gui/run.py and open " + CANONICAL_ORIGIN + " instead.",
      );
      return;
    }

    try {
      const response = await fetch("labs/registry.json", { cache: "no-store" });
      REGISTRY = (await response.json()).labs;
    } catch {
      fail("Could not load the lab registry.", "labs/registry.json is missing or invalid.");
      return;
    }
    if (!Array.isArray(REGISTRY) || REGISTRY.length === 0) {
      fail("The lab registry is empty.", "labs/registry.json defined no labs.");
      return;
    }
    await openLab(requestedLabId());
    window.setInterval(refreshLabStatuses, STATUS_INTERVAL);
  }

  window.addEventListener("popstate", () => {
    openLab(requestedLabId());
  });

  document.addEventListener("click", async (event) => {
    const navItem = event.target.closest("[data-lab-id]");
    if (navItem && !navItem.disabled) {
      const labId = navItem.dataset.labId;
      if (labId !== pendingLabId) {
        pendingLabId = labId;
        await openLab(labId, { push: true });
      }
      return;
    }

    if (!CONFIG) return;

    if (event.target.closest("[data-reset-lab]")) await resetMission();
    if (event.target.closest("[data-print-report]")) window.print();
    const toggle = event.target.closest("#statusToggle");
    if (toggle && !toggle.disabled) {
      const running = Boolean(labStatuses[CONFIG.id] && labStatuses[CONFIG.id].running);
      await control(CONFIG.id, running ? "stop" : "start");
    }

    if (event.target.closest("#statusPrimary")) {
      if (elements.labStatus.dataset.state === "up") {
        await copyText("http://127.0.0.1:" + CONFIG.port + "/mcp", "Endpoint copied");
      } else {
        toggleCommands(!commandsShown());
      }
    }

    if (event.target.closest("#statusCopyCommands")) {
      await copyText(pendingCommands, "Commands copied");
    }
  });

  document.querySelector("#mobileMenu").addEventListener("click", () => {
    elements.sidebar.classList.toggle("open");
    elements.sidebarScrim.classList.toggle("show");
  });
  elements.sidebarScrim.addEventListener("click", closeSidebar);

  boot();
})();
