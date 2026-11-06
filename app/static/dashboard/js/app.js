/* VulnCorrelator dashboard — talks to the same-origin API when it can
 * answer, falls back to the bundled sample case file (demo-data.js) when
 * it can't, and never pretends one is the other. */
(function () {
  "use strict";

  const $ = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  const SEV_WEIGHT = { critical: 9.5, high: 7.5, medium: 5.5, low: 2 };
  const SEV_ORDER = ["critical", "high", "medium", "low"];
  const SEV_COLOR = { critical: "var(--rust)", high: "var(--amber)", medium: "var(--green)", low: "var(--line)" };

  function escapeHtml(str) {
    if (str === null || str === undefined) return "";
    return String(str).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }

  function sevClass(sev) {
    const s = (sev || "").toLowerCase();
    return SEV_ORDER.includes(s) ? s : "low";
  }

  // ---------------------------------------------------------------- state
  const state = {
    base: localStorage.getItem("vc_api_base") || "",
    key: localStorage.getItem("vc_api_key") || "",
    live: false,
    data: { stats: null, assets: [], vulnerabilities: [], chains: [] },
    assetFilter: "all",
    assetSort: { col: "max_risk_score", dir: "desc" },
    vulnFilter: "all",
    vulnSort: { col: "risk_score", dir: "desc" },
  };

  async function apiFetch(path, opts) {
    const headers = Object.assign({}, (opts && opts.headers) || {});
    if (state.key) headers["X-API-Key"] = state.key;
    const res = await fetch(state.base + path, Object.assign({}, opts, { headers }));
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      const err = new Error(`${res.status} ${res.statusText}: ${body.slice(0, 200)}`);
      err.status = res.status;
      throw err;
    }
    return res.status === 204 ? null : res.json();
  }

  async function connectAndLoad() {
    setConn("checking", "Checking…");
    try {
      await apiFetch("/health");
      const [stats, assets, vulnerabilities, chains] = await Promise.all([
        apiFetch("/stats"),
        apiFetch("/assets?limit=200"),
        apiFetch("/vulnerabilities?limit=200"),
        apiFetch("/chains?limit=50"),
      ]);
      state.data = { stats, assets, vulnerabilities, chains };
      state.live = true;
      setConn("live", "Live — connected");
      $("#modeBanner").hidden = true;
    } catch (err) {
      state.data = window.DEMO;
      state.live = false;
      setConn("demo", "Demo data — no API reachable");
      const banner = $("#modeBanner");
      banner.hidden = false;
      banner.textContent = "Showing a sample case file — the API at \u201c" + (state.base || "/") + "\u201d didn't answer. Check Connection settings, or ingest a scan below once it's up.";
    }
    renderAll();
  }

  function setConn(kind, label) {
    $("#connDot").className = "conn-dot " + kind;
    $("#connLabel").textContent = label;
  }

  // ---------------------------------------------------------------- tabs
  function wireTabs() {
    $$(".tab").forEach((btn) => {
      btn.addEventListener("click", () => {
        $$(".tab").forEach((b) => { b.classList.remove("active"); b.setAttribute("aria-selected", "false"); });
        btn.classList.add("active");
        btn.setAttribute("aria-selected", "true");
        $$(".panel").forEach((p) => p.classList.remove("active"));
        const panel = $("#panel-" + btn.dataset.tab);
        panel.classList.add("active");
        if (btn.dataset.tab === "chains") revealChainBoard();
      });
    });
  }

  // ---------------------------------------------------------------- overview
  function renderAll() {
    renderOverview();
    renderAssets();
    renderVulns();
    renderChainList();
    renderChainBoard();
  }

  function animateCount(el, to) {
    if (reduceMotion) { el.textContent = to; return; }
    const from = 0;
    const dur = 700;
    const start = performance.now();
    function tick(now) {
      const p = Math.min(1, (now - start) / dur);
      const eased = 1 - Math.pow(1 - p, 3);
      el.textContent = Math.round(from + (to - from) * eased);
      if (p < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  }

  function renderOverview() {
    const stats = state.data.stats || { assets: 0, vulnerabilities: 0, by_severity: {}, known_exploited: 0, chains: 0, critical_chains: 0 };
    animateCount($("#statAssets"), stats.assets || 0);
    animateCount($("#statVulns"), stats.vulnerabilities || 0);
    animateCount($("#statChains"), stats.chains || 0);
    animateCount($("#statKev"), stats.known_exploited || 0);
    $("#statCriticalChains").textContent = stats.critical_chains ? `${stats.critical_chains} critical` : "";

    // composite dial value from the severity mix (findings carry the signal stats.* alone doesn't)
    const bySev = stats.by_severity || {};
    const total = SEV_ORDER.reduce((s, k) => s + (bySev[k] || 0), 0);
    const weighted = total ? SEV_ORDER.reduce((s, k) => s + (bySev[k] || 0) * SEV_WEIGHT[k], 0) / total : 0;
    const dialValue = Math.round(weighted * 10) / 10;
    $("#dialNumber").textContent = total ? dialValue.toFixed(1) : "—";
    const circumference = 578;
    const fill = $("#dialFill");
    const offset = circumference * (1 - Math.min(1, dialValue / 10));
    fill.style.stroke = dialValue >= 9 ? "var(--rust)" : dialValue >= 7 ? "var(--amber)" : "var(--green-bright)";
    requestAnimationFrame(() => { fill.style.strokeDashoffset = total ? offset : circumference; });

    // threat spectrum bar
    const bar = $("#spectrumBar");
    const legend = $("#spectrumLegend");
    bar.innerHTML = "";
    legend.innerHTML = "";
    SEV_ORDER.forEach((sev) => {
      const count = bySev[sev] || 0;
      const pct = total ? (count / total) * 100 : 0;
      const seg = document.createElement("div");
      seg.className = "spectrum-seg";
      seg.style.background = SEV_COLOR[sev];
      seg.style.flexBasis = "0%";
      bar.appendChild(seg);
      requestAnimationFrame(() => { seg.style.flexBasis = pct + "%"; });
      const li = document.createElement("li");
      li.innerHTML = `<span class="legend-dot" style="background:${SEV_COLOR[sev]}"></span>${sev[0].toUpperCase()}${sev.slice(1)} — ${count}`;
      legend.appendChild(li);
    });

    document.getElementById("app").classList.add("booting");
  }

  // ---------------------------------------------------------------- assets
  function wireAssetControls() {
    $$("#assetFilters .chip").forEach((chip) => {
      chip.addEventListener("click", () => {
        $$("#assetFilters .chip").forEach((c) => c.classList.remove("active"));
        chip.classList.add("active");
        state.assetFilter = chip.dataset.filter;
        renderAssets();
      });
    });
    $("#assetSearch").addEventListener("input", renderAssets);
    $$('#assetsTable thead th[data-sort]').forEach((th) => {
      th.addEventListener("click", () => {
        const col = th.dataset.sort;
        if (state.assetSort.col === col) state.assetSort.dir = state.assetSort.dir === "asc" ? "desc" : "asc";
        else state.assetSort = { col, dir: "desc" };
        renderAssets();
      });
    });
  }

  function renderAssets() {
    let rows = (state.data.assets || []).slice();
    if (state.assetFilter === "internet") rows = rows.filter((a) => a.internet_facing);
    if (state.assetFilter === "risky") rows = rows.filter((a) => (a.max_risk_score || 0) >= 7);
    const q = $("#assetSearch").value.trim().toLowerCase();
    if (q) rows = rows.filter((a) => (a.ip_address || "").toLowerCase().includes(q) || (a.hostname || "").toLowerCase().includes(q));

    const { col, dir } = state.assetSort;
    rows.sort((a, b) => {
      const va = a[col], vb = b[col];
      const cmp = typeof va === "string" ? (va || "").localeCompare(vb || "") : (va || 0) - (vb || 0);
      return dir === "asc" ? cmp : -cmp;
    });

    $$('#assetsTable thead th').forEach((th) => th.classList.toggle("sorted", th.dataset.sort === col));

    const body = $("#assetsBody");
    body.innerHTML = "";
    $("#assetsEmpty").hidden = rows.length > 0;
    if (!rows.length) {
      $("#assetsEmpty").textContent = (state.data.assets || []).length
        ? "No assets match that filter. Try clearing the search or switching filters."
        : "No assets logged yet. Submit a scan on the Ingest Scan tab to populate the register.";
      return;
    }
    rows.forEach((a) => {
      const risk = a.max_risk_score || 0;
      const rowSev = risk >= 9 ? "critical" : risk >= 7 ? "high" : risk >= 4 ? "medium" : "low";
      const tr = document.createElement("tr");
      tr.className = "row-" + rowSev;
      tr.innerHTML = `
        <td class="mono">${escapeHtml(a.ip_address)}</td>
        <td>${escapeHtml(a.hostname || "—")}</td>
        <td>${escapeHtml(a.os || "—")}</td>
        <td>${a.internet_facing ? '<span class="sev-tag sev-high">Internet-facing</span>' : '<span class="sev-tag sev-low">Internal</span>'}</td>
        <td class="mono">${a.vulnerability_count ?? 0}</td>
        <td class="mono">${a.max_risk_score != null ? a.max_risk_score.toFixed(1) : "—"}</td>`;
      body.appendChild(tr);
    });
  }

  // ---------------------------------------------------------------- vulnerabilities
  function wireVulnControls() {
    $$("#vulnFilters .chip").forEach((chip) => {
      chip.addEventListener("click", () => {
        $$("#vulnFilters .chip").forEach((c) => c.classList.remove("active"));
        chip.classList.add("active");
        state.vulnFilter = chip.dataset.filter;
        renderVulns();
      });
    });
    $("#vulnSearch").addEventListener("input", renderVulns);
    $$('#vulnsTable thead th[data-sort]').forEach((th) => {
      th.addEventListener("click", () => {
        const col = th.dataset.sort;
        if (state.vulnSort.col === col) state.vulnSort.dir = state.vulnSort.dir === "asc" ? "desc" : "asc";
        else state.vulnSort = { col, dir: "desc" };
        renderVulns();
      });
    });
  }

  function renderVulns() {
    let rows = (state.data.vulnerabilities || []).slice();
    if (state.vulnFilter === "critical") rows = rows.filter((v) => sevClass(v.severity) === "critical");
    if (state.vulnFilter === "high") rows = rows.filter((v) => sevClass(v.severity) === "high");
    if (state.vulnFilter === "kev") rows = rows.filter((v) => v.in_kev);
    const q = $("#vulnSearch").value.trim().toLowerCase();
    if (q) rows = rows.filter((v) => [(v.cve_id || ""), (v.product || ""), (v.title || "")].join(" ").toLowerCase().includes(q));

    const { col, dir } = state.vulnSort;
    rows.sort((a, b) => {
      const va = a[col], vb = b[col];
      const cmp = typeof va === "string" ? (va || "").localeCompare(vb || "") : (va || 0) - (vb || 0);
      return dir === "asc" ? cmp : -cmp;
    });

    $$('#vulnsTable thead th').forEach((th) => th.classList.toggle("sorted", th.dataset.sort === col));

    const body = $("#vulnsBody");
    body.innerHTML = "";
    $("#vulnsEmpty").hidden = rows.length > 0;
    if (!rows.length) {
      $("#vulnsEmpty").textContent = (state.data.vulnerabilities || []).length
        ? "No findings match that filter."
        : "No findings on file yet. They'll appear here as soon as a scan is ingested.";
      return;
    }
    rows.forEach((v) => {
      const sc = sevClass(v.severity);
      const tr = document.createElement("tr");
      tr.className = "row-" + sc;
      tr.innerHTML = `
        <td class="mono">${v.risk_score != null ? v.risk_score.toFixed(1) : "—"}</td>
        <td class="mono">${escapeHtml(v.cve_id || "—")}${v.in_kev ? '<span class="kev-flag">KEV</span>' : ""}</td>
        <td>${escapeHtml(v.title)}</td>
        <td>${escapeHtml([v.product, v.version].filter(Boolean).join(" "))}</td>
        <td class="mono">${v.port != null ? v.port + "/" + (v.protocol || "tcp") : "host"}</td>
        <td><span class="sev-tag sev-${sc}">${sc}</span></td>`;
      body.appendChild(tr);
    });
  }

  // ---------------------------------------------------------------- chains
  function roleTag(role) {
    return { "initial-access": "ENTRY", "lateral-movement": "PIVOT", "privilege-escalation": "PRIVESC" }[role] || (role || "").toUpperCase();
  }

  function assetLabel(assetId, ip) {
    const asset = (state.data.assets || []).find((a) => a.id === assetId);
    return (asset && asset.hostname) ? asset.hostname : ip;
  }

  function renderChainList() {
    const chains = state.data.chains || [];
    const list = $("#chainList");
    list.innerHTML = "";
    $("#chainsEmpty").hidden = chains.length > 0;
    if (!chains.length) {
      $("#chainsEmpty").textContent = "No chains correlated yet. Chains appear once two or more findings on related hosts line up into a path.";
      return;
    }
    chains.slice().sort((a, b) => b.risk_score - a.risk_score).forEach((c) => {
      const sc = sevClass(c.severity);
      const li = document.createElement("li");
      li.className = "case-file" + (sc === "high" ? " sev-high-border" : sc !== "critical" ? " sev-medium-border" : "");
      li.innerHTML = `
        <div class="case-file-head">
          <span class="case-file-title">${escapeHtml(c.title)}</span>
          <span class="case-file-risk">Risk ${c.risk_score.toFixed(1)} · ${sc}</span>
        </div>
        <p class="case-file-explain">${escapeHtml(c.explanation)}</p>
        <ul class="case-file-steps">${c.steps.map((s) => `<li>${roleTag(s.role)} · ${escapeHtml(s.ip_address)} · ${escapeHtml(s.cve_id || s.title)}</li>`).join("")}</ul>`;
      list.appendChild(li);
    });
  }

  function renderChainBoard() {
    const svg = $("#chainBoard");
    const chains = state.data.chains || [];
    svg.innerHTML = "";
    if (!chains.length) { svg.setAttribute("viewBox", "0 0 900 160"); return; }

    const rows = chains.slice(0, 5);
    const rowH = Math.max(70, Math.floor(280 / rows.length));
    const height = rowH * rows.length + 60;
    svg.setAttribute("viewBox", `0 0 900 ${height}`);

    const ns = "http://www.w3.org/2000/svg";
    let revealIndex = 0;

    rows.forEach((chain, ci) => {
      const y = 50 + ci * rowH;
      // unique nodes in step order
      const nodes = [];
      chain.steps.forEach((s) => {
        if (!nodes.find((n) => n.asset_id === s.asset_id)) nodes.push({ asset_id: s.asset_id, ip_address: s.ip_address });
      });
      const spacing = nodes.length > 1 ? Math.min(220, 680 / (nodes.length - 1)) : 0;
      const startX = nodes.length > 1 ? 150 : 150;
      const pos = {};
      nodes.forEach((n, i) => { pos[n.asset_id] = { x: startX + i * spacing, y }; });

      // edges, following the real step sequence (handles self-loops on one host)
      for (let i = 0; i < chain.steps.length - 1; i++) {
        const a = chain.steps[i], b = chain.steps[i + 1];
        const pa = pos[a.asset_id], pb = pos[b.asset_id];
        const path = document.createElementNS(ns, "path");
        path.setAttribute("class", "chain-edge" + (sevClass(chain.severity) === "critical" ? " crit" : ""));
        if (a.asset_id === b.asset_id) {
          path.setAttribute("d", `M ${pa.x - 14} ${pa.y - 18} C ${pa.x - 40} ${pa.y - 60}, ${pa.x + 40} ${pa.y - 60}, ${pa.x + 14} ${pa.y - 18}`);
        } else {
          const midY = pa.y - 26;
          path.setAttribute("d", `M ${pa.x + 18} ${pa.y} Q ${(pa.x + pb.x) / 2} ${midY}, ${pb.x - 18} ${pb.y}`);
        }
        prepReveal(path, revealIndex++);
        svg.appendChild(path);
      }

      nodes.forEach((n) => {
        const p = pos[n.asset_id];
        const isEntry = chain.steps[0] && chain.steps[0].asset_id === n.asset_id;
        const asset = (state.data.assets || []).find((a) => a.id === n.asset_id);
        const g = document.createElementNS(ns, "g");
        g.setAttribute("class", "chain-node" + (isEntry && asset && asset.internet_facing ? " exposed" : ""));
        g.setAttribute("transform", `translate(${p.x},${p.y})`);
        g.innerHTML = `
          <circle r="18"></circle>
          <text text-anchor="middle" dy="4">${escapeHtml(n.ip_address.split(".").slice(-1)[0])}</text>
          <text class="node-tag" text-anchor="middle" dy="34">${escapeHtml(assetLabel(n.asset_id, n.ip_address))}</text>`;
        prepReveal(g, revealIndex++);
        svg.appendChild(g);
      });
    });

    // Panels are display:none while inactive, so a hidden board shouldn't
    // burn its one reveal now — it plays when the user actually opens the
    // tab (see wireTabs). If the board is rebuilt while already visible
    // (e.g. after reconnecting), play it immediately instead.
    if ($("#panel-chains").classList.contains("active")) revealChainBoard();
  }

  function prepReveal(el, index) {
    // CSS `transform` on an SVG <g> overrides its positional `transform`
    // attribute rather than composing with it, so only edges (plain
    // <path>s, no attribute transform) get the slide; nodes just fade —
    // that keeps every node glued to its correct coordinate throughout.
    el.style.opacity = "0";
    if (el.tagName.toLowerCase() === "path") el.style.transform = "translateY(6px)";
    el.style.transitionDelay = reduceMotion ? "0ms" : `${Math.min(index * 60, 600)}ms`;
  }

  function revealChainBoard() {
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        $$("#chainBoard .chain-node").forEach((el) => { el.style.opacity = "1"; });
        $$("#chainBoard .chain-edge").forEach((el) => { el.style.opacity = "0.85"; el.style.transform = "translateY(0)"; });
      });
    });
  }

  // ---------------------------------------------------------------- ingest
  function wireIngest() {
    const dropzone = $("#dropzone");
    const fileInput = $("#fileInput");
    const dzTitle = $("#dzTitle");
    const submitBtn = $("#submitScan");
    const formatSelect = $("#formatSelect");

    const accepts = { nmap: ".xml", nessus: ".nessus", json: ".json" };
    formatSelect.addEventListener("change", () => { fileInput.accept = accepts[formatSelect.value]; });

    function setFile(file) {
      if (!file) return;
      dzTitle.textContent = file.name;
      submitBtn.disabled = false;
      submitBtn.textContent = "Submit for correlation";
      const ext = file.name.split(".").pop().toLowerCase();
      if (ext === "nessus") formatSelect.value = "nessus";
      else if (ext === "json") formatSelect.value = "json";
      else formatSelect.value = "nmap";
      fileInput._selected = file;
    }

    dropzone.addEventListener("click", () => fileInput.click());
    dropzone.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); fileInput.click(); } });
    dropzone.addEventListener("dragover", (e) => { e.preventDefault(); dropzone.classList.add("drag"); });
    dropzone.addEventListener("dragleave", () => dropzone.classList.remove("drag"));
    dropzone.addEventListener("drop", (e) => {
      e.preventDefault();
      dropzone.classList.remove("drag");
      if (e.dataTransfer.files[0]) setFile(e.dataTransfer.files[0]);
    });
    fileInput.addEventListener("change", () => setFile(fileInput.files[0]));

    $("#ingestForm").addEventListener("submit", (e) => {
      e.preventDefault();
      const file = fileInput._selected;
      if (!file) return;
      if (state.live) submitLive(file); else submitDemo(file);
    });

    function showProgress(pct) {
      $("#progressTrack").hidden = false;
      $("#progressFill").style.width = pct + "%";
    }

    function submitDemo(file) {
      submitBtn.disabled = true;
      let pct = 0;
      const timer = setInterval(() => {
        pct = Math.min(100, pct + 14);
        showProgress(pct);
        if (pct >= 100) {
          clearInterval(timer);
          submitBtn.disabled = false;
          renderTicket({
            demo: true,
            source: formatSelect.value,
            status: "completed",
            hosts_count: 1,
            findings_count: Math.floor(Math.random() * 3) + 1,
            new_count: Math.floor(Math.random() * 3) + 1,
            updated_count: 0,
          }, file.name);
        }
      }, 140);
    }

    function submitLive(file) {
      submitBtn.disabled = true;
      showProgress(4);
      const fd = new FormData();
      fd.append("file", file);
      fd.append("format", formatSelect.value);
      const params = new URLSearchParams();
      if ($("#internetFacing").checked) params.set("internet_facing", "true");
      if ($("#asyncMode").checked) params.set("async_mode", "true");
      const xhr = new XMLHttpRequest();
      xhr.open("POST", state.base + "/ingest/upload" + (params.toString() ? "?" + params.toString() : ""));
      if (state.key) xhr.setRequestHeader("X-API-Key", state.key);
      xhr.upload.onprogress = (e) => { if (e.lengthComputable) showProgress(Math.round((e.loaded / e.total) * 90)); };
      xhr.onload = () => {
        submitBtn.disabled = false;
        showProgress(100);
        if (xhr.status >= 200 && xhr.status < 300) {
          let report = {};
          try { report = JSON.parse(xhr.responseText); } catch (_) {}
          renderTicket(report, file.name);
          connectAndLoad();
        } else {
          renderTicket({ error: true, status: xhr.status, message: xhr.responseText || xhr.statusText }, file.name);
        }
      };
      xhr.onerror = () => {
        submitBtn.disabled = false;
        renderTicket({ error: true, status: 0, message: "Network error reaching the API." }, file.name);
      };
      xhr.send(fd);
    }

    function renderTicket(report, filename) {
      const ticket = $("#ingestTicket");
      ticket.hidden = false;
      if (report.error) {
        ticket.className = "ticket error";
        ticket.innerHTML = `<h4>Ingest failed</h4><p>${escapeHtml(filename)} was rejected (status ${report.status}). ${escapeHtml((report.message || "").slice(0, 300))}</p>`;
        return;
      }
      ticket.className = "ticket";
      ticket.innerHTML = `
        <h4>${report.demo ? "Demo ingest — nothing was actually sent" : "Report ticket"}</h4>
        <dl>
          <dt>File</dt><dd>${escapeHtml(filename)}</dd>
          <dt>Format</dt><dd>${escapeHtml(report.source || report.format || formatSelect.value)}</dd>
          <dt>Status</dt><dd>${escapeHtml(report.status || "—")}</dd>
          <dt>Hosts</dt><dd>${report.hosts_count ?? "—"}</dd>
          <dt>Findings</dt><dd>${report.findings_count ?? "—"}</dd>
          <dt>New</dt><dd>${report.new_count ?? "—"}</dd>
          <dt>Updated</dt><dd>${report.updated_count ?? "—"}</dd>
        </dl>
        ${report.demo ? '<p class="settings-note" style="margin-top:8px">Connect to a live API under Connection settings to ingest for real.</p>' : ""}`;
    }
  }

  // ---------------------------------------------------------------- settings
  function wireSettings() {
    $("#apiBase").value = state.base;
    $("#apiKey").value = state.key;
    $("#connBtn").addEventListener("click", () => {
      const panel = $("#settingsPanel");
      panel.open = !panel.open;
    });
    $("#saveSettings").addEventListener("click", () => {
      state.base = $("#apiBase").value.trim().replace(/\/$/, "");
      state.key = $("#apiKey").value.trim();
      localStorage.setItem("vc_api_base", state.base);
      localStorage.setItem("vc_api_key", state.key);
      connectAndLoad();
    });
  }

  // ---------------------------------------------------------------- boot
  document.addEventListener("DOMContentLoaded", () => {
    wireTabs();
    wireAssetControls();
    wireVulnControls();
    wireIngest();
    wireSettings();
    connectAndLoad();
  });
})();
