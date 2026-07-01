const state = {
  index: null,
  loadError: null,
  releases: [],
  filtered: [],
  selectedId: null,
  compareBaseId: null,
  compareTargetId: null,
  compareRequested: false,
  activeChannel: "release",
  activeView: "overview",
  details: new Map(),
  cveDetails: new Map(),
  packageDetails: new Map(),
  tab: "summary",
  cveRowStatus: "all",
  cveRowSeverity: "all",
  cveRowPackage: "all",
  cveRowQuery: "",
  packageQuery: "",
  sortKey: "date",
  sortDirection: "desc",
};

const el = {
  indexStatus: document.getElementById("indexStatus"),
  refreshButton: document.getElementById("refreshButton"),
  searchInput: document.getElementById("searchInput"),
  machineFilter: document.getElementById("machineFilter"),
  channelFilter: document.getElementById("channelFilter"),
  cveFilter: document.getElementById("cveFilter"),
  severityFilter: document.getElementById("severityFilter"),
  clearFilters: document.getElementById("clearFilters"),
  stats: document.getElementById("stats"),
  viewTabs: document.querySelectorAll(".view-tab"),
  overviewView: document.getElementById("overviewView"),
  attentionView: document.getElementById("attentionView"),
  compareView: document.getElementById("compareView"),
  lineageView: document.getElementById("lineageView"),
  channelTabs: document.querySelectorAll(".channel-tab"),
  healthStamp: document.getElementById("healthStamp"),
  healthGrid: document.getElementById("healthGrid"),
  regressionStatus: document.getElementById("regressionStatus"),
  regressionAlerts: document.getElementById("regressionAlerts"),
  attentionStatus: document.getElementById("attentionStatus"),
  attentionQueue: document.getElementById("attentionQueue"),
  lineageStatus: document.getElementById("lineageStatus"),
  lineageTree: document.getElementById("lineageTree"),
  compareStatus: document.getElementById("compareStatus"),
  compareBase: document.getElementById("compareBase"),
  compareTarget: document.getElementById("compareTarget"),
  compareSwap: document.getElementById("compareSwap"),
  compareOutput: document.getElementById("compareOutput"),
  latestList: document.getElementById("latestList"),
  releaseListTitle: document.getElementById("releaseListTitle"),
  releaseCount: document.getElementById("releaseCount"),
  releaseTable: document.getElementById("releaseTable"),
  detailsEmpty: document.getElementById("detailsEmpty"),
  detailsPanel: document.getElementById("detailsPanel"),
};

const REQUIRED_RELEASE_LAYER_NAMES = [
  "meta-northfi-distro",
  "meta-arquimea-distro-base",
  "meta-layout-base",
  "meta-arquimea-security",
];

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>'"]/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "'": "&#39;",
    '"': "&quot;",
  }[char]));
}

function shortCommit(commit) {
  return commit ? commit.slice(0, 12) : "";
}

function releaseLabel(release) {
  if (!release) return "";
  return [
    release.tag || release.artifact_label || release.id,
    release.machine,
    shortCommit(release.commit),
  ].filter(Boolean).join(" | ");
}

function inferChannel(release) {
  if (release.channel) return release.channel;
  const value = [release.tag, release.id, release.artifact_label].filter(Boolean).join(" ").toLowerCase();
  if (value.includes("-rc.")) return "rc";
  if (value.includes("northfi-swupdate-dev") || value.includes("northfi-image-dev")) return "development";
  if ((release.tag || "").startsWith("v")) return "release";
  return "development";
}

function normalizeRelease(release) {
  return {
    ...release,
    channel: inferChannel(release),
  };
}

function channelBadge(channel) {
  const normalized = channel || "unknown";
  const cls = normalized === "release" ? "ok" : normalized === "rc" ? "warn" : normalized === "development" ? "info" : "unknown";
  return `<span class="badge ${cls}">${escapeHtml(normalized)}</span>`;
}

function channelMatches(release, channel) {
  if (channel === "all") return true;
  if (channel === "release") return release.channel === "release" || release.channel === "rc";
  return release.channel === channel;
}

function channelTitle(channel) {
  if (channel === "development") return "Development";
  if (channel === "all") return "All Builds";
  if (channel === "rc") return "Release Candidates";
  return "Releases";
}

function compareCandidates() {
  return state.releases
    .filter((release) => channelMatches(release, state.activeChannel))
    .sort((a, b) => dateValue(b) - dateValue(a));
}

function syncViewTabs() {
  el.viewTabs.forEach((button) => {
    const active = button.dataset.view === state.activeView;
    button.classList.toggle("active", active);
    button.setAttribute("aria-selected", active ? "true" : "false");
  });
  el.overviewView?.classList.toggle("hidden", state.activeView !== "overview");
  el.overviewView?.classList.toggle("active", state.activeView === "overview");
  el.attentionView?.classList.toggle("hidden", state.activeView !== "attention");
  el.attentionView?.classList.toggle("active", state.activeView === "attention");
  el.compareView?.classList.toggle("hidden", state.activeView !== "compare");
  el.compareView?.classList.toggle("active", state.activeView === "compare");
  el.lineageView?.classList.toggle("hidden", state.activeView !== "lineage");
  el.lineageView?.classList.toggle("active", state.activeView === "lineage");
}

function setActiveView(view) {
  state.activeView = ["overview", "attention", "compare", "lineage"].includes(view) ? view : "overview";
  syncViewTabs();
  if (state.activeView === "attention") renderAttention();
  if (state.activeView === "compare") renderCompare();
  if (state.activeView === "lineage") renderLineage();
}

function syncChannelTabs() {
  el.channelTabs.forEach((button) => {
    const active = button.dataset.channel === state.activeChannel;
    button.classList.toggle("active", active);
    button.setAttribute("aria-selected", active ? "true" : "false");
  });
  el.channelFilter.value = state.activeChannel;
  el.releaseListTitle.textContent = channelTitle(state.activeChannel);
}

function setActiveChannel(channel, options = {}) {
  state.activeChannel = ["release", "development", "all", "rc"].includes(channel) ? channel : "release";
  if (options.resetCompare !== false) {
    state.compareBaseId = null;
    state.compareTargetId = null;
    state.compareRequested = false;
  }
  syncChannelTabs();
  populateCompareOptions();
  applyFilters();
}

function dateValue(release) {
  const candidates = [release.generated_at_utc, release.cached_at_utc, release.azure?.queued_at_utc, release.azure?.finish_time];
  for (const candidate of candidates) {
    const time = Date.parse(candidate || "");
    if (!Number.isNaN(time)) return time;
  }
  return 0;
}

function releaseName(release) {
  return release.tag || release.artifact_label || release.id || "";
}

function dateLabel(release) {
  const value = dateValue(release);
  if (!value) return "not recorded";
  return new Date(value).toISOString().replace("T", " ").slice(0, 16);
}

function cveRiskValue(release) {
  const severity = release.cve_severity || {};
  return (Number(severity.critical || 0) * 10000)
    + (Number(severity.high || 0) * 1000)
    + (Number(release.cve_summary?.unpatched || 0) * 10)
    + (release.cve_summary?.available ? 0 : 1);
}

function sortValue(release, key) {
  if (key === "name") return releaseName(release).toLowerCase();
  if (key === "channel") return release.channel || "";
  if (key === "machine") return release.machine || "";
  if (key === "manifest") return release.kas_manifest || "";
  if (key === "commit") return release.commit || "";
  if (key === "cve") return cveRiskValue(release);
  return dateValue(release);
}

function sortReleases(releases) {
  const direction = state.sortDirection === "asc" ? 1 : -1;
  return [...releases].sort((a, b) => {
    const left = sortValue(a, state.sortKey);
    const right = sortValue(b, state.sortKey);
    let result;
    if (typeof left === "number" && typeof right === "number") {
      result = left - right;
    } else {
      result = String(left).localeCompare(String(right));
    }
    return result === 0 ? dateValue(b) - dateValue(a) : result * direction;
  });
}

function setSort(key) {
  if (state.sortKey === key) {
    state.sortDirection = state.sortDirection === "asc" ? "desc" : "asc";
  } else {
    state.sortKey = key;
    state.sortDirection = key === "date" || key === "cve" ? "desc" : "asc";
  }
  applyFilters();
}

function sortIndicator(key) {
  if (state.sortKey !== key) return "";
  return state.sortDirection === "asc" ? " ^" : " v";
}

function azureBuildUrl(release, detail = {}) {
  return release.azure_build_url || release.build_url || detail.azure?.build_url || detail.azure?.url || "";
}

function buildId(release, detail = {}) {
  return release.build_id || release.azure?.build_id || detail.azure?.build_id || "";
}

function smokeStatus(detail = {}) {
  const smoke = detail.smoke_test || detail.smoke || detail.validation || {};
  if (typeof smoke === "string") return smoke;
  if (smoke.status) return smoke.status;
  if (smoke.passed === true) return "passed";
  if (smoke.passed === false) return "failed";
  return "not recorded";
}

function artifactNames(detail = {}) {
  return (detail.artifacts || []).map((artifact) => artifact.name || "");
}

function flashingReadiness(detail = {}) {
  const names = artifactNames(detail);
  const hasBoot = names.some((name) => name.startsWith("imx-boot") || name === "boot.itb");
  const hasWic = names.some((name) => /rootfs\.wic(\.gz|\.zst)?$/.test(name));
  const hasBmap = names.some((name) => name.endsWith(".wic.bmap"));
  const hasSwu = names.some((name) => name.endsWith(".swu"));
  const ready = hasBoot && hasWic && hasBmap && hasSwu;
  return { ready, hasBoot, hasWic, hasBmap, hasSwu };
}

function readinessBadge(readiness) {
  if (!readiness) return `<span class="badge unknown">Not checked</span>`;
  return readiness.ready ? `<span class="badge ok">Flashing ready</span>` : `<span class="badge warn">Incomplete</span>`;
}

function indexAgeHours() {
  const stamp = state.index?.generated_at_utc;
  const time = Date.parse(stamp || "");
  if (Number.isNaN(time)) return null;
  return (Date.now() - time) / (1000 * 60 * 60);
}

function indexFreshness() {
  const hours = indexAgeHours();
  if (hours === null) return { label: "No timestamp", className: "unknown" };
  if (hours <= 12) return { label: `${hours.toFixed(1)}h old`, className: "ok" };
  if (hours <= 48) return { label: `${hours.toFixed(1)}h old`, className: "warn" };
  return { label: `${hours.toFixed(1)}h old`, className: "danger" };
}

function cveBadge(cve) {
  if (!cve || !cve.available) return `<span class="badge unknown">No CVE report</span>`;
  const unpatched = Number(cve.unpatched || 0);
  if (unpatched > 0) return `<span class="badge danger">${unpatched} unpatched</span>`;
  return `<span class="badge ok">No unpatched</span>`;
}

function normalizeLoadError(error, path = "", fallbackKind = "load") {
  if (error && typeof error === "object") {
    return {
      kind: error.kind || error.errorKind || fallbackKind,
      path: error.path || path || "",
      status: error.status || "",
      message: error.message || error.error || "Unknown data load error",
      detail: error.detail || "",
    };
  }
  return { kind: fallbackKind, path, status: "", message: String(error || "Unknown data load error"), detail: "" };
}

function storedLoadError(path, error, fallbackKind = "load") {
  const normalized = normalizeLoadError(error, path, fallbackKind);
  return {
    error: normalized.message,
    errorKind: normalized.kind,
    path: normalized.path,
    status: normalized.status,
    detail: normalized.detail,
  };
}

function loadingState(path, label) {
  return { __loading: true, path, label };
}

function loadErrorTitle(error) {
  const normalized = normalizeLoadError(error);
  if (normalized.kind === "missing" || normalized.kind === "missing-index") return "Data file not found";
  if (normalized.kind === "invalid-json") return "JSON could not be parsed";
  if (normalized.kind === "network") return "Data request failed";
  if (normalized.kind === "empty-index") return "No builds indexed";
  return "Data could not be loaded";
}

function loadErrorMessage(error) {
  const normalized = normalizeLoadError(error);
  if (normalized.kind === "missing-index") return "No dashboard index file is available. Check that the dashboard indexer has generated releases/index.json, development/index.json, or the legacy releases-index.json.";
  if (normalized.kind === "missing") return "The expected data file is missing from the dashboard data directory.";
  if (normalized.kind === "invalid-json") return "The file was found, but its contents are not valid JSON. Regenerate the dashboard index or the affected metadata artifact.";
  if (normalized.kind === "network") return "The browser could not complete the request for this data file.";
  if (normalized.kind === "empty-index") return "The dashboard index loaded successfully, but it contains zero builds.";
  return normalized.message || "The dashboard could not load this data.";
}

function renderDataNotice(type, title, message, rows = []) {
  const details = rows.filter(Boolean).map((row) => `<div class="data-notice-meta">${escapeHtml(row)}</div>`).join("");
  return `<div class="data-notice ${escapeHtml(type)}">
    <div class="data-notice-title">${escapeHtml(title)}</div>
    <p>${escapeHtml(message)}</p>
    ${details}
  </div>`;
}

function renderLoadError(title, error) {
  const normalized = normalizeLoadError(error, error?.path || "", error?.errorKind || "load");
  const type = normalized.kind === "missing" || normalized.kind === "missing-index" || normalized.kind === "empty-index" ? "warn" : "error";
  return renderDataNotice(type, title || loadErrorTitle(normalized), loadErrorMessage(normalized), [
    normalized.path ? `Path: ${normalized.path}` : "",
    normalized.status ? `HTTP status: ${normalized.status}` : "",
    normalized.message && normalized.message !== loadErrorMessage(normalized) ? normalized.message : "",
    normalized.detail,
  ]);
}

function renderLoadingNotice(title, message, path = "") {
  return renderDataNotice("loading", title, message, [path ? `Path: ${path}` : ""]);
}

function severityClass(severity, status) {
  if (status === "Unpatched") return "danger";
  if (severity === "critical" || severity === "high") return "warn";
  if (status === "Patched") return "ok";
  return "unknown";
}

async function fetchJson(path) {
  let response;
  try {
    response = await fetch(`${path}?ts=${Date.now()}`, { cache: "no-store" });
  } catch (error) {
    throw { kind: "network", path, message: `Request failed for ${path}: ${error.message || error}` };
  }

  if (!response.ok) {
    throw {
      kind: response.status === 404 ? "missing" : "http",
      path,
      status: response.status,
      message: `${response.status} ${response.statusText}: ${path}`,
    };
  }

  const text = await response.text();
  try {
    return JSON.parse(text);
  } catch (error) {
    throw { kind: "invalid-json", path, message: `Invalid JSON in ${path}: ${error.message || error}` };
  }
}

function summarizeIndexFailures(results, paths) {
  return results.map((result, index) => {
    if (result.status === "fulfilled") return "";
    const error = normalizeLoadError(result.reason, paths[index]);
    return `${paths[index]}: ${error.kind} ${error.status || ""}`.trim();
  }).filter(Boolean).join("; ");
}

async function loadDashboardIndexes() {
  const paths = ["data/releases/index.json", "data/development/index.json"];
  const settled = await Promise.allSettled(paths.map((path) => fetchJson(path)));
  const indexes = settled
    .filter((result) => result.status === "fulfilled")
    .map((result) => result.value);

  if (!indexes.length) {
    try {
      const legacy = await fetchJson("data/releases-index.json");
      return {
        generated_at_utc: legacy.generated_at_utc,
        releases: Array.isArray(legacy.releases) ? legacy.releases : [],
      };
    } catch (legacyError) {
      const normalized = normalizeLoadError(legacyError, "data/releases-index.json");
      throw {
        kind: normalized.kind === "missing" ? "missing-index" : normalized.kind,
        path: "data/releases/index.json, data/development/index.json, data/releases-index.json",
        message: normalized.message,
        detail: summarizeIndexFailures(settled, paths),
        status: normalized.status,
      };
    }
  }

  const releases = indexes.flatMap((index) => Array.isArray(index.releases) ? index.releases : []);
  const generated = indexes
    .map((index) => index.generated_at_utc)
    .filter(Boolean)
    .sort()
    .at(-1) || "";
  return { generated_at_utc: generated, releases };
}

async function loadIndex() {
  el.indexStatus.textContent = "Loading dashboard indexes...";
  state.loadError = null;
  try {
    state.index = await loadDashboardIndexes();
    state.releases = Array.isArray(state.index.releases) ? state.index.releases.map(normalizeRelease) : [];
    state.selectedId = state.releases[0]?.id || null;
    if (!state.releases.length) {
      populateFilters();
      setActiveChannel(state.activeChannel, { resetCompare: false });
      state.loadError = { kind: "empty-index", message: "Dashboard index contains zero builds." };
      el.indexStatus.textContent = "No build entries in dashboard indexes.";
      renderAll();
      return;
    }
    el.indexStatus.textContent = `Preparing ${state.releases.length} indexed build entries...`;
    populateFilters();
    setActiveChannel(state.activeChannel, { resetCompare: false });
    const stamp = state.index.generated_at_utc || "not generated yet";
    el.indexStatus.textContent = `${state.releases.length} build entries. Index: ${stamp}`;
  } catch (error) {
    state.index = null;
    state.loadError = normalizeLoadError(error);
    state.releases = [];
    state.filtered = [];
    renderAll();
    el.indexStatus.textContent = `Could not load dashboard indexes: ${state.loadError.message}`;
  }
}

function populateFilters() {
  const machines = [...new Set(state.releases.map((item) => item.machine).filter(Boolean))].sort();
  const currentMachine = el.machineFilter.value || "all";
  el.machineFilter.innerHTML = `<option value="all">All machines</option>` + machines.map((machine) => (
    `<option value="${escapeHtml(machine)}">${escapeHtml(machine)}</option>`
  )).join("");
  el.channelFilter.innerHTML = [
    ["release", "Releases/RC"],
    ["development", "Development"],
    ["all", "All channels"],
    ["rc", "RC only"],
  ].map(([value, label]) => `<option value="${value}">${label}</option>`).join("");
  el.machineFilter.value = machines.includes(currentMachine) ? currentMachine : "all";
  el.channelFilter.value = state.activeChannel;
}

function originBuilds(release) {
  const origins = Array.isArray(release.origin_builds)
    ? release.origin_builds.filter((origin) => origin && origin.available !== false && origin.id)
    : [];
  if (origins.length) return origins;
  const origin = release.origin_build || {};
  return origin.available && origin.id ? [origin] : [];
}

function originMatchForDev(release, devId) {
  const origin = originBuilds(release).find((item) => item.id === devId);
  return origin?.match || "linked";
}

function releaseSearchText(release) {
  const releasedTags = releasedFromDevelopment(release).flatMap((item) => [item.id, item.tag, item.artifact_label, item.build_id]);
  const originTags = originBuilds(release).flatMap((origin) => [origin.id, origin.label, origin.build_id, origin.match]);
  return [
    ...releasedTags,
    ...originTags,
    release.id,
    release.tag,
    release.commit,
    release.machine,
    release.kas_manifest,
    release.artifact_label,
    release.published_artifacts?.images,
    release.published_artifacts?.metadata,
    release.channel,
    release.build_id,
    release.azure?.build_id,
    release.origin_build?.id,
    release.origin_build?.label,
    release.origin_build?.build_id,
    release.origin_build?.match,
  ].filter(Boolean).join(" ").toLowerCase();
}

function applyFilters() {
  const query = el.searchInput.value.trim().toLowerCase();
  const machine = el.machineFilter.value;
  const channel = state.activeChannel;
  const cve = el.cveFilter.value;
  const severity = el.severityFilter.value;

  state.filtered = state.releases.filter((release) => {
    if (machine !== "all" && release.machine !== machine) return false;
    if (!channelMatches(release, channel)) return false;
    if (query && !releaseSearchText(release).includes(query)) return false;
    const summary = release.cve_summary || {};
    const available = Boolean(summary.available);
    const unpatched = Number(summary.unpatched || 0);
    if (cve === "unpatched" && (!available || unpatched <= 0)) return false;
    if (cve === "clean" && (!available || unpatched > 0)) return false;
    if (cve === "missing" && available) return false;
    if (severity !== "all" && Number(release.cve_severity?.[severity] || 0) <= 0) return false;
    return true;
  });
  state.filtered = sortReleases(state.filtered);

  if (!state.filtered.some((item) => item.id === state.selectedId)) {
    state.selectedId = state.filtered[0]?.id || null;
  }
  renderAll();
}

function renderAll() {
  renderStats();
  renderHealth();
  renderRegressionAlerts();
  renderAttention();
  renderLineage();
  renderCompare();
  renderLatest();
  renderTable();
  renderDetails();
}

function renderStats() {
  const total = state.releases.length;
  const visible = state.filtered.length;
  const critical = state.releases.filter((item) => Number(item.cve_severity?.critical || 0) > 0).length;
  const missing = state.releases.filter((item) => !item.cve_summary?.available).length;
  const problem = problemBuildIds(state.releases).size;
  const development = state.releases.filter((item) => item.channel === "development").length;
  const release = state.releases.filter((item) => item.channel === "release" || item.channel === "rc").length;
  el.stats.innerHTML = [
    ["Indexed builds", total],
    ["Visible", visible],
    ["Release/RC", release],
    ["Development", development],
    ["Problem tags", problem],
    ["Critical CVEs", critical],
    ["Missing CVE report", missing],
  ].map(([label, value]) => `<div class="stat"><span>${label}</span><strong>${value}</strong></div>`).join("");
}


function healthCard(title, value, detail, className = "") {
  return `<div class="health-card ${className}"><span>${escapeHtml(title)}</span><strong>${escapeHtml(value)}</strong><small>${escapeHtml(detail || "")}</small></div>`;
}

function aggregateSeverity(builds) {
  return builds.reduce((counts, release) => {
    const severity = release.cve_severity || {};
    counts.critical += Number(severity.critical || 0);
    counts.high += Number(severity.high || 0);
    counts.medium += Number(severity.medium || 0);
    counts.low += Number(severity.low || 0);
    return counts;
  }, { critical: 0, high: 0, medium: 0, low: 0 });
}

function renderSeverityBars(counts) {
  const total = Object.values(counts).reduce((sum, value) => sum + value, 0);
  const rows = [
    ["critical", "Critical"],
    ["high", "High"],
    ["medium", "Medium"],
    ["low", "Low"],
  ];
  return `<div class="severity-panel" aria-label="CVE severity distribution">
    <div class="severity-head"><h3>CVE Severity</h3><span>${total} total issues</span></div>
    ${rows.map(([key, label]) => {
      const value = Number(counts[key] || 0);
      const width = total ? Math.max(2, Math.round((value / total) * 100)) : 0;
      return `<div class="severity-row ${key}"><span>${label}</span><div class="severity-track"><i style="width: ${width}%"></i></div><strong>${value}</strong></div>`;
    }).join("")}
  </div>`;
}

function attentionTagCandidates(builds = state.releases) {
  return builds.filter((release) => release.channel === "release" || release.channel === "rc");
}

function problemBuildIds(builds) {
  return new Set(attentionItems(builds).map((item) => item.release.id));
}

function layerTraceability(release, detail = {}) {
  if (release.layer_traceability) return release.layer_traceability;
  if (!Array.isArray(detail.layers)) return { rows: [], missing_layers: 0, missing_tags: 0, complete: false, unknown: true };
  const byName = layerByName(detail.layers);
  const rows = REQUIRED_RELEASE_LAYER_NAMES.map((name) => {
    const layer = byName.get(name) || null;
    return {
      name,
      present: Boolean(layer),
      tag: layerTag(layer),
      commit: layer?.commit || "",
      branch: layer?.branch || "",
    };
  });
  const missingLayers = rows.filter((row) => !row.present).length;
  const missingTags = rows.filter((row) => row.present && !row.tag).length;
  return { rows, missing_layers: missingLayers, missing_tags: missingTags, complete: missingLayers === 0 && missingTags === 0 };
}

function readinessChecks(release, detail = {}) {
  const flashing = release.flashing || flashingReadiness(detail);
  const cve = release.cve_summary || {};
  const trace = layerTraceability(release, detail);
  const requiresTags = requiresLayerTags(release);
  const origins = originBuilds(release);
  const origin = release.origin_build || {};
  const originDetail = origins.length
    ? `${origins.length} linked: ${origins.map((item) => item.match || "linked").join(", ")}`
    : origin.reason || "missing";
  const checks = [
    ["Artifacts", Boolean(flashing.ready), "boot + wic + bmap + swu"],
    ["CVE report", Boolean(cve.available), cve.available ? "present" : "missing"],
    ["Critical CVEs", Number(release.cve_severity?.critical || 0) === 0, `${Number(release.cve_severity?.critical || 0)} critical`],
    ["Unpatched CVEs", Number(cve.unpatched || 0) === 0, `${Number(cve.unpatched || 0)} unpatched`],
    ["Layer tags", !requiresTags || trace.complete, requiresTags ? `${Number(trace.missing_tags || 0)} missing tags, ${Number(trace.missing_layers || 0)} missing layers` : "not required"],
    ["Dev origin", !requiresTags || origins.length > 0, requiresTags ? originDetail : "not required"],
  ];
  return checks.map(([label, ok, detailText]) => ({ label, ok, detail: detailText }));
}

function readinessSummary(release, detail = {}) {
  const checks = readinessChecks(release, detail);
  const failed = checks.filter((check) => !check.ok);
  return { checks, failed, ready: failed.length === 0 };
}

function renderReadinessPanel(release, detail = {}) {
  const summary = readinessSummary(release, detail);
  return `<div class="readiness-panel ${summary.ready ? "ok" : "warn"}">
    <div class="readiness-head">
      <h3>Release Readiness</h3>
      <span class="badge ${summary.ready ? "ok" : "warn"}">${summary.ready ? "Ready" : `${summary.failed.length} blockers`}</span>
    </div>
    <div class="readiness-grid">
      ${summary.checks.map((check) => `<div class="readiness-check ${check.ok ? "ok" : "warn"}"><strong>${escapeHtml(check.label)}</strong><span>${escapeHtml(check.detail)}</span></div>`).join("")}
    </div>
  </div>`;
}

function renderHealth() {
  const freshness = indexFreshness();
  const latestRelease = latestGroups().find((item) => item.channel === "release" || item.channel === "rc");
  const latestDev = latestGroups().find((item) => item.channel === "development");
  const unpatchedBuilds = state.releases.filter((item) => Number(item.cve_summary?.unpatched || 0) > 0).length;
  const missingCve = state.releases.filter((item) => !item.cve_summary?.available).length;
  const flashingReady = state.releases.filter((item) => item.flashing?.ready).length;
  const criticalBuilds = state.releases.filter((item) => Number(item.cve_severity?.critical || 0) > 0).length;
  const problemBuilds = problemBuildIds(state.releases).size;
  const releaseBuilds = state.releases.filter((item) => item.channel === "release" || item.channel === "rc").length;
  const cveIssueBuilds = new Set(state.releases
    .filter((item) => Number(item.cve_summary?.unpatched || 0) > 0 || Number(item.cve_severity?.critical || 0) > 0)
    .map((item) => item.id)).size;

  el.healthStamp.textContent = `Index ${freshness.label}`;
  const severityCounts = aggregateSeverity(state.releases);
  const releaseReady = state.releases.filter((item) => item.channel === "release" || item.channel === "rc").filter((item) => readinessSummary(item).ready).length;
  el.healthGrid.innerHTML = [
    healthCard("Latest release", latestRelease?.tag || latestRelease?.artifact_label || "none", latestRelease?.machine || "", latestRelease ? "ok" : ""),
    healthCard("Latest development", latestDev?.artifact_label || latestDev?.tag || "none", latestDev?.machine || "", latestDev ? "info" : ""),
    healthCard("Flashing ready", `${flashingReady}/${state.releases.length}`, "boot + wic + bmap + swu", flashingReady ? "ok" : "warn"),
    healthCard("Problem tags", `${problemBuilds}/${releaseBuilds}`, "release/RC tags needing action", problemBuilds ? "danger" : "ok"),
    healthCard("Builds with CVEs", String(cveIssueBuilds), `${unpatchedBuilds} unpatched, ${criticalBuilds} critical`, cveIssueBuilds ? "danger" : "ok"),
    healthCard("Missing CVE reports", String(missingCve), "builds without CVE data", missingCve ? "warn" : "ok"),
    healthCard("Release ready", `${releaseReady}/${releaseBuilds}`, "release/RC builds passing readiness", releaseReady === releaseBuilds && releaseBuilds ? "ok" : "warn"),
    renderSeverityBars(severityCounts),
  ].join("");
}

function releaseCandidatesSorted() {
  return state.releases
    .filter((release) => release.channel === "release" || release.channel === "rc")
    .sort((a, b) => dateValue(b) - dateValue(a));
}

function releaseRegressionPair() {
  const releases = releaseCandidatesSorted();
  const latest = releases[0] || null;
  if (!latest) return { latest: null, previous: null, sameIdentity: false };
  const previousSame = releases.find((release) => release.id !== latest.id && release.machine === latest.machine && release.kas_manifest === latest.kas_manifest) || null;
  return { latest, previous: previousSame || releases[1] || null, sameIdentity: Boolean(previousSame) };
}

function packageCount(release) {
  return Number(release.package_manifest?.package_count || release.package_count || 0);
}

function flashMissingLabels(flashing = {}) {
  return [
    ["boot", flashing.hasBoot],
    ["wic", flashing.hasWic],
    ["bmap", flashing.hasBmap],
    ["swu", flashing.hasSwu],
  ].filter(([, present]) => !present).map(([label]) => label);
}

function traceRowsByName(release) {
  const rows = release.layer_traceability?.rows || [];
  return new Map(rows.map((row) => [row.name, row]));
}

function changedUntaggedLayers(latest, previous) {
  if (!latest || !previous) return [];
  const latestRows = traceRowsByName(latest);
  const previousRows = traceRowsByName(previous);
  const changed = [];
  for (const [name, row] of latestRows.entries()) {
    const prev = previousRows.get(name);
    if (!prev || !row.commit || row.commit === prev.commit) continue;
    if (!row.tag) changed.push({ name, commit: row.commit, previous: prev.commit });
  }
  return changed;
}

function regressionAlert(level, title, value, detail) {
  return { level, title, value, detail };
}

function releaseRegressionAlerts(latest, previous) {
  if (!latest || !previous) return [];
  const alerts = [];
  const latestCve = latest.cve_summary || {};
  const previousCve = previous.cve_summary || {};
  if (!latestCve.available) {
    alerts.push(regressionAlert("warn", "CVE report", "missing", "Latest release has no CVE report."));
  } else if (previousCve.available) {
    const delta = Number(latestCve.unpatched || 0) - Number(previousCve.unpatched || 0);
    if (delta > 0) alerts.push(regressionAlert("danger", "Unpatched CVEs", `+${delta}`, `${Number(previousCve.unpatched || 0)} -> ${Number(latestCve.unpatched || 0)}`));
  }

  const flashing = latest.flashing || {};
  if (!flashing.ready) {
    const missing = flashMissingLabels(flashing);
    alerts.push(regressionAlert("warn", "Flashing artifacts", "incomplete", missing.length ? `Missing: ${missing.join(", ")}` : "Required flashing artifacts are incomplete."));
  }

  const untaggedLayers = changedUntaggedLayers(latest, previous);
  if (untaggedLayers.length) {
    alerts.push(regressionAlert("warn", "Layer tag traceability", `${untaggedLayers.length} changed`, untaggedLayers.map((item) => `${item.name} ${shortCommit(item.previous)} -> ${shortCommit(item.commit)}`).join(", ")));
  }

  const latestPackages = packageCount(latest);
  const previousPackages = packageCount(previous);
  if (latestPackages && previousPackages) {
    const delta = latestPackages - previousPackages;
    const percent = previousPackages ? Math.abs(delta) / previousPackages : 0;
    if (Math.abs(delta) >= 50 && percent >= 0.10) {
      alerts.push(regressionAlert(delta > 0 ? "warn" : "info", "Package count", `${delta > 0 ? "+" : ""}${delta}`, `${previousPackages} -> ${latestPackages} packages (${(percent * 100).toFixed(1)}%)`));
    }
  }
  return alerts;
}

function attentionReason(level, category, title, detail, value = "") {
  return { level, category, title, detail, value };
}

function attentionLevelRank(level) {
  return { danger: 3, warn: 2, info: 1, ok: 0 }[level] || 0;
}

function maxAttentionLevel(reasons) {
  return reasons.reduce((level, reason) => (
    attentionLevelRank(reason.level) > attentionLevelRank(level) ? reason.level : level
  ), "info");
}

function regressionReasonsByBuild() {
  const { latest, previous } = releaseRegressionPair();
  const map = new Map();
  if (!latest || !previous) return map;
  const alerts = releaseRegressionAlerts(latest, previous);
  if (!alerts.length) return map;
  map.set(latest.id, alerts.map((alert) => attentionReason(
    alert.level,
    "Regression",
    alert.title,
    alert.detail,
    alert.value,
  )));
  return map;
}

function attentionReasonsForBuild(release, regressionReasons = new Map()) {
  const reasons = [];
  const cve = release.cve_summary || {};
  const critical = Number(release.cve_severity?.critical || 0);
  const unpatched = Number(cve.unpatched || 0);

  if (!cve.available) {
    reasons.push(attentionReason("warn", "CVE missing", "CVE report missing", "No cve-summary report is available for this build."));
  } else {
    if (critical > 0) reasons.push(attentionReason("danger", "Critical CVEs", "Critical CVEs open", `${critical} critical CVE rows are present.`, String(critical)));
    if (unpatched > 0) reasons.push(attentionReason("danger", "Unpatched CVEs", "Unpatched CVEs open", `${unpatched} unpatched CVE rows are present.`, String(unpatched)));
  }

  if (release.flashing && !release.flashing.ready) {
    const missing = flashMissingLabels(release.flashing);
    reasons.push(attentionReason("warn", "Flashing", "Flashing incomplete", missing.length ? `Missing: ${missing.join(", ")}` : "Required flashing artifacts are incomplete."));
  }

  if (requiresLayerTags(release)) {
    const origins = originBuilds(release);
    if (!origins.length) {
      reasons.push(attentionReason("warn", "Dev origin", "No development origin", release.origin_build?.reason || "No matching development build is linked."));
    }

    const trace = layerTraceability(release);
    const missingTags = Number(trace.missing_tags || 0);
    const missingLayers = Number(trace.missing_layers || 0);
    if (missingTags || missingLayers) {
      const detail = [`${missingTags} missing tags`, `${missingLayers} missing layers`].join(", ");
      reasons.push(attentionReason("warn", "Layer tags", "Layer tag traceability gap", detail, String(missingTags + missingLayers)));
    }
  }

  for (const reason of regressionReasons.get(release.id) || []) reasons.push(reason);
  return reasons;
}

function attentionItems(builds = state.releases) {
  const regressionReasons = regressionReasonsByBuild();
  return attentionTagCandidates(builds)
    .map((release) => ({ release, reasons: attentionReasonsForBuild(release, regressionReasons) }))
    .filter((item) => item.reasons.length)
    .sort((a, b) => (
      attentionLevelRank(maxAttentionLevel(b.reasons)) - attentionLevelRank(maxAttentionLevel(a.reasons)) ||
      b.reasons.length - a.reasons.length ||
      dateValue(b.release) - dateValue(a.release)
    ));
}

function attentionCategoryCounts(items) {
  const counts = new Map();
  for (const item of items) {
    for (const reason of item.reasons) counts.set(reason.category, (counts.get(reason.category) || 0) + 1);
  }
  return [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
}

function renderAttentionReason(reason) {
  return `<div class="attention-reason ${escapeHtml(reason.level)}">
    <span>${escapeHtml(reason.category)}</span>
    <strong>${escapeHtml(reason.value || reason.title)}</strong>
    <small>${escapeHtml(reason.value ? reason.title : reason.detail)}</small>
    ${reason.value ? `<small>${escapeHtml(reason.detail)}</small>` : ""}
  </div>`;
}

function renderAttentionItem(item) {
  const release = item.release;
  const level = maxAttentionLevel(item.reasons);
  const readiness = readinessSummary(release);
  return `<article class="attention-card ${escapeHtml(level)}">
    <div class="attention-card-head">
      <div>
        <button class="inline-link attention-title" type="button" data-select-build="${escapeHtml(release.id)}">${escapeHtml(releaseName(release))}</button>
        <p class="item-meta">${escapeHtml([release.machine, release.kas_manifest, dateLabel(release)].filter(Boolean).join(" | "))}</p>
        <p class="item-meta mono">${escapeHtml(shortCommit(release.commit || ""))}</p>
      </div>
      <div class="header-actions">
        ${channelBadge(release.channel)}
        <span class="badge ${level === "danger" ? "danger" : "warn"}">${item.reasons.length} action${item.reasons.length === 1 ? "" : "s"}</span>
        <span class="badge ${readiness.ready ? "ok" : "warn"}">${readiness.ready ? "ready" : `${readiness.failed.length} blockers`}</span>
      </div>
    </div>
    <div class="attention-reasons">
      ${item.reasons.map(renderAttentionReason).join("")}
    </div>
  </article>`;
}

function renderAttention() {
  if (!el.attentionQueue || !el.attentionStatus) return;
  if (!state.releases.length) {
    el.attentionStatus.textContent = "No builds indexed";
    el.attentionQueue.innerHTML = `<div class="empty-state"><p>No actionable tag items can be calculated until builds are indexed.</p></div>`;
    return;
  }

  const tags = attentionTagCandidates();
  const items = attentionItems(tags);
  const totalReasons = items.reduce((sum, item) => sum + item.reasons.length, 0);
  el.attentionStatus.textContent = items.length ? `${items.length}/${tags.length} tags | ${totalReasons} actions` : `${tags.length} tags | clean`;
  if (!items.length) {
    el.attentionQueue.innerHTML = `<div class="empty-state"><h2>No actionable tag issues</h2><p>No missing CVE reports, critical/unpatched CVEs, flashing gaps, missing dev origins, missing layer tags, or release regressions were detected for release/RC tags.</p></div>`;
    return;
  }

  const dangerCount = items.filter((item) => maxAttentionLevel(item.reasons) === "danger").length;
  const categoryCounts = attentionCategoryCounts(items);
  el.attentionQueue.innerHTML = `
    <div class="attention-summary ${dangerCount ? "danger" : "warn"}">
      <div><span>Tag action queue</span><strong>${items.length}/${tags.length} tags</strong><small>${totalReasons} actionable checks</small></div>
      <div><span>Highest priority</span><strong>${dangerCount ? `${dangerCount} critical-risk tags` : "warning only"}</strong><small>Sorted by severity, action count, then newest tag</small></div>
      <div class="attention-chips">${categoryCounts.map(([label, count]) => `<span class="attention-chip"><strong>${count}</strong>${escapeHtml(label)}</span>`).join("")}</div>
    </div>
    <div class="attention-list">${items.map(renderAttentionItem).join("")}</div>
  `;
  bindBuildLinks(el.attentionQueue);
}

function renderRegressionAlert(alert) {
  return `<div class="regression-alert ${escapeHtml(alert.level)}">
    <span>${escapeHtml(alert.title)}</span>
    <strong>${escapeHtml(alert.value)}</strong>
    <small>${escapeHtml(alert.detail || "")}</small>
  </div>`;
}

function renderRegressionAlerts() {
  if (!el.regressionAlerts || !el.regressionStatus) return;
  const { latest, previous, sameIdentity } = releaseRegressionPair();
  if (!latest) {
    el.regressionStatus.textContent = "No release tags";
    el.regressionAlerts.innerHTML = `<div class="empty-state"><p>No release/RC builds are available for regression checks.</p></div>`;
    return;
  }
  if (!previous) {
    el.regressionStatus.textContent = "Need two releases";
    el.regressionAlerts.innerHTML = `<div class="empty-state"><p>At least two release/RC builds are required for regression checks.</p></div>`;
    return;
  }

  const alerts = releaseRegressionAlerts(latest, previous);
  el.regressionStatus.textContent = `${releaseName(previous)} -> ${releaseName(latest)}${sameIdentity ? "" : " | fallback baseline"}`;
  const summaryClass = alerts.some((alert) => alert.level === "danger") ? "danger" : alerts.length ? "warn" : "ok";
  const summary = `<div class="regression-summary ${summaryClass}">
    <div>
      <span>Baseline</span>
      <button class="inline-link" type="button" data-select-build="${escapeHtml(previous.id)}">${escapeHtml(releaseLabel(previous))}</button>
    </div>
    <div>
      <span>Latest</span>
      <button class="inline-link" type="button" data-select-build="${escapeHtml(latest.id)}">${escapeHtml(releaseLabel(latest))}</button>
    </div>
    <strong>${alerts.length ? `${alerts.length} alert${alerts.length === 1 ? "" : "s"}` : "No regressions detected"}</strong>
  </div>`;
  const body = alerts.length
    ? `<div class="regression-grid">${alerts.map(renderRegressionAlert).join("")}</div>`
    : `<div class="regression-grid"><div class="regression-alert ok"><span>Regression checks</span><strong>clean</strong><small>No unpatched CVE increase, missing CVE report, flashing gap, untagged layer change, or large package-count shift.</small></div></div>`;
  el.regressionAlerts.innerHTML = summary + body;
  bindBuildLinks(el.regressionAlerts);
}

function releaseById(id) {
  return state.releases.find((release) => release.id === id) || null;
}

function populateCompareOptions() {
  const sorted = compareCandidates();
  const validIds = new Set(sorted.map((release) => release.id));
  if (!validIds.has(state.compareTargetId)) state.compareTargetId = sorted[0]?.id || "";
  if (!validIds.has(state.compareBaseId)) state.compareBaseId = sorted[1]?.id || sorted[0]?.id || "";
  const options = sorted.map((release) => `<option value="${escapeHtml(release.id)}">${escapeHtml(releaseLabel(release))}</option>`).join("");
  el.compareBase.innerHTML = options || `<option value="">No builds</option>`;
  el.compareTarget.innerHTML = options || `<option value="">No builds</option>`;
  el.compareBase.value = state.compareBaseId || "";
  el.compareTarget.value = state.compareTargetId || "";
}

function mapBy(items, keyFn) {
  const map = new Map();
  for (const item of items || []) {
    const key = keyFn(item);
    if (key) map.set(key, item);
  }
  return map;
}

function cveKey(issue) {
  return [issue.id, issue.package].filter(Boolean).join("|");
}

function cveLabel(issue) {
  return `${issue.id || "unknown"} ${issue.package || ""}`.trim();
}

function compareMaps(baseMap, targetMap, changedFn) {
  const added = [];
  const removed = [];
  const changed = [];
  for (const [key, target] of targetMap.entries()) {
    if (!baseMap.has(key)) {
      added.push(target);
      continue;
    }
    const base = baseMap.get(key);
    if (changedFn(base, target)) changed.push({ key, base, target });
  }
  for (const [key, base] of baseMap.entries()) {
    if (!targetMap.has(key)) removed.push(base);
  }
  return { added, removed, changed };
}

function renderCompareMetric(label, value, className = "") {
  return `<div class="compare-metric ${className}"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`;
}

function compareDetailCard(title, baseValue, targetValue, className = "", detail = "") {
  return `<div class="compare-detail-card ${escapeHtml(className)}">
    <span>${escapeHtml(title)}</span>
    <div class="compare-detail-values">
      <div><small>Base</small><strong>${escapeHtml(baseValue)}</strong></div>
      <div><small>Target</small><strong>${escapeHtml(targetValue)}</strong></div>
    </div>
    ${detail ? `<p>${escapeHtml(detail)}</p>` : ""}
  </div>`;
}

function compareStatusClass(changed, worse = false, better = false) {
  if (worse) return "danger";
  if (better) return "ok";
  return changed ? "warn" : "ok";
}

function packageCountFromData(release, packages = {}) {
  return Number(packages.package_count || release.package_manifest?.package_count || release.package_count || 0);
}

function compareReadinessText(release) {
  const summary = readinessSummary(release);
  return summary.ready ? "ready" : `${summary.failed.length} blockers`;
}

function compareCveText(release) {
  const summary = release.cve_summary || {};
  if (!summary.available) return "missing report";
  return `${Number(summary.unpatched || 0)} unpatched`;
}

function renderDiffList(title, items, renderItem, emptyText) {
  const body = items.length
    ? items.slice(0, 12).map(renderItem).join("")
    : `<div class="item-meta">${escapeHtml(emptyText)}</div>`;
  const more = items.length > 12 ? `<div class="item-meta">${items.length - 12} more not shown</div>` : "";
  return `<div class="compare-diff"><h3>${escapeHtml(title)}</h3>${body}${more}</div>`;
}

function lineageReleases() {
  return state.releases
    .filter((release) => release.channel === "release" || release.channel === "rc")
    .sort((a, b) => dateValue(b) - dateValue(a));
}

function originVariantLabel(origin) {
  const manifest = origin.kas_manifest || "";
  if (manifest.includes("-dev")) return "development dev";
  if (manifest.includes("-prod")) return "development prod";
  return "development";
}

function renderLineageOriginNode(origin) {
  return `<div class="lineage-node dev-node">
    <span>${escapeHtml(originVariantLabel(origin))}</span>
    <button class="inline-link" type="button" data-select-build="${escapeHtml(origin.id)}">${escapeHtml(origin.label || origin.id)}</button>
    <small>${escapeHtml([origin.build_id ? `build ${origin.build_id}` : "", origin.match || "linked"].filter(Boolean).join(" | "))}</small>
    <code>${escapeHtml(shortCommit(origin.commit || ""))}</code>
  </div>`;
}

function renderLineageReleaseNode(release) {
  return `<div class="lineage-node release-node ${release.id === state.selectedId ? "selected" : ""}">
    <span>${escapeHtml(release.channel || "release")}</span>
    <button class="inline-link" type="button" data-select-build="${escapeHtml(release.id)}">${escapeHtml(release.tag || release.artifact_label || release.id)}</button>
    <small>${escapeHtml([release.build_id ? `build ${release.build_id}` : "", release.machine, release.kas_manifest].filter(Boolean).join(" | "))}</small>
    <code>${escapeHtml(shortCommit(release.commit || ""))}</code>
  </div>`;
}

function renderLineageOutcomeNode(label, value, className, detail = "") {
  return `<div class="lineage-outcome ${escapeHtml(className)}">
    <span>${escapeHtml(label)}</span>
    <strong>${escapeHtml(value)}</strong>
    ${detail ? `<small>${escapeHtml(detail)}</small>` : ""}
  </div>`;
}

function renderLineageOutcomes(release) {
  const summary = release.cve_summary || {};
  const readiness = readinessSummary(release);
  const flashing = release.flashing || {};
  const artifactReady = Boolean(flashing.ready);
  const cveAvailable = Boolean(summary.available);
  const unpatched = Number(summary.unpatched || 0);
  return [
    renderLineageOutcomeNode("Artifacts", artifactReady ? "ready" : "incomplete", artifactReady ? "ok" : "warn", `${Number(release.artifact_count || 0)} listed`),
    renderLineageOutcomeNode("CVE", cveAvailable ? `${unpatched} unpatched` : "missing report", !cveAvailable ? "warn" : unpatched > 0 ? "danger" : "ok", cveAvailable ? `${Number(release.cve_severity?.critical || 0)} critical` : "no CVE data"),
    renderLineageOutcomeNode("Readiness", readiness.ready ? "ready" : `${readiness.failed.length} blockers`, readiness.ready ? "ok" : "warn", readiness.failed.map((check) => check.label).join(", ")),
  ].join("");
}

function renderLineageCard(release) {
  const origins = originBuilds(release);
  const originColumn = origins.length
    ? origins.map(renderLineageOriginNode).join("")
    : `<div class="lineage-node missing-node"><span>development</span><strong>No origin linked</strong><small>${escapeHtml(release.origin_build?.reason || "No matching development build was found.")}</small></div>`;
  const originCount = origins.length ? `${origins.length} development origin${origins.length === 1 ? "" : "s"}` : "no development origin";
  return `<article class="lineage-card">
    <div class="lineage-card-head">
      <div>
        <h3>${escapeHtml(release.tag || release.artifact_label || release.id)}</h3>
        <p class="item-meta">${escapeHtml(originCount)} | ${escapeHtml(dateLabel(release))}</p>
      </div>
      <div class="header-actions">
        ${channelBadge(release.channel)}
        ${readinessBadge(release.flashing)}
        ${cveBadge(release.cve_summary)}
      </div>
    </div>
    <div class="lineage-flow">
      <div class="lineage-stage lineage-origins">${originColumn}</div>
      <div class="lineage-stage lineage-release">${renderLineageReleaseNode(release)}</div>
      <div class="lineage-stage lineage-results">${renderLineageOutcomes(release)}</div>
    </div>
  </article>`;
}

function renderLineage() {
  const releases = lineageReleases();
  if (!el.lineageTree || !el.lineageStatus) return;
  if (!state.releases.length) {
    el.lineageStatus.textContent = "No builds indexed";
    el.lineageTree.innerHTML = `<div class="empty-state"><p>No release lineage can be rendered until builds are indexed.</p></div>`;
    return;
  }
  if (!releases.length) {
    el.lineageStatus.textContent = "No release tags";
    el.lineageTree.innerHTML = `<div class="empty-state"><p>No release/RC tags are available in the current dashboard index.</p></div>`;
    return;
  }
  const linked = releases.reduce((total, release) => total + originBuilds(release).length, 0);
  const missing = releases.filter((release) => originBuilds(release).length === 0).length;
  el.lineageStatus.textContent = `${releases.length} tags | ${linked} linked dev builds${missing ? ` | ${missing} missing origin` : ""}`;
  el.lineageTree.innerHTML = releases.map(renderLineageCard).join("");
  bindBuildLinks(el.lineageTree);
}

function renderCompare() {
  const candidates = compareCandidates();
  if (!state.releases.length) {
    el.compareStatus.textContent = "No builds indexed";
    el.compareOutput.innerHTML = `<div class="empty-state"><p>No builds available to compare.</p></div>`;
    return;
  }
  if (candidates.length < 2) {
    el.compareStatus.textContent = `${channelTitle(state.activeChannel)}: need two builds`;
    el.compareOutput.innerHTML = `<div class="empty-state"><p>At least two builds in ${escapeHtml(channelTitle(state.activeChannel).toLowerCase())} are required for comparison.</p></div>`;
    return;
  }

  const base = releaseById(state.compareBaseId) || candidates[1];
  const target = releaseById(state.compareTargetId) || candidates[0];
  state.compareBaseId = base?.id || "";
  state.compareTargetId = target?.id || "";
  if (el.compareBase.value !== state.compareBaseId) el.compareBase.value = state.compareBaseId;
  if (el.compareTarget.value !== state.compareTargetId) el.compareTarget.value = state.compareTargetId;

  if (!state.compareRequested) {
    el.compareStatus.textContent = `${releaseLabel(base)} -> ${releaseLabel(target)}`;
    el.compareOutput.innerHTML = `<div class="compare-lazy">
      ${renderDataNotice("info", "Comparison not loaded", "CVE and package manifests can be large. Load the comparison only when you need the full diff.")}
      <button class="link-button" type="button" data-load-compare>Load comparison</button>
    </div>`;
    el.compareOutput.querySelector("[data-load-compare]")?.addEventListener("click", () => {
      state.compareRequested = true;
      renderCompare();
    });
    return;
  }

  const pending = compareDataReady(base, target);
  if (pending.length) {
    el.compareStatus.textContent = `${releaseLabel(base)} -> ${releaseLabel(target)}`;
    el.compareOutput.innerHTML = renderLoadingNotice("Loading compare data", "Compare loads release, CVE, and package manifests only for the selected base and target builds.", pending.join("; "));
    return;
  }

  const baseDetail = state.details.get(base.id) || {};
  const targetDetail = state.details.get(target.id) || {};
  const baseCve = state.cveDetails.get(base.id) || {};
  const targetCve = state.cveDetails.get(target.id) || {};
  const basePackages = state.packageDetails.get(base.id) || {};
  const targetPackages = state.packageDetails.get(target.id) || {};

  const compareErrors = [
    ["Base release", baseDetail],
    ["Target release", targetDetail],
    ["Base CVE", baseCve],
    ["Target CVE", targetCve],
    ["Base packages", basePackages],
    ["Target packages", targetPackages],
  ].filter(([, value]) => value?.error);
  if (compareErrors.length) {
    el.compareStatus.textContent = `${releaseLabel(base)} -> ${releaseLabel(target)}`;
    el.compareOutput.innerHTML = compareErrors.map(([label, value]) => renderLoadError(label, value)).join("");
    return;
  }

  const artifactDiff = compareMaps(
    mapBy(baseDetail.artifacts || [], (artifact) => artifact.name),
    mapBy(targetDetail.artifacts || [], (artifact) => artifact.name),
    (baseArtifact, targetArtifact) => baseArtifact.sha256 !== targetArtifact.sha256 || Number(baseArtifact.size_bytes || 0) !== Number(targetArtifact.size_bytes || 0),
  );
  const layerDiff = compareMaps(
    mapBy(baseDetail.layers || [], (layer) => layer.name),
    mapBy(targetDetail.layers || [], (layer) => layer.name),
    (baseLayer, targetLayer) => baseLayer.commit !== targetLayer.commit || baseLayer.branch !== targetLayer.branch,
  );
  const cveDiff = compareMaps(
    mapBy(baseCve.issues || [], cveKey),
    mapBy(targetCve.issues || [], cveKey),
    (baseIssue, targetIssue) => baseIssue.status !== targetIssue.status || baseIssue.severity !== targetIssue.severity,
  );
  const packageDiff = compareMaps(
    mapBy(basePackages.packages || [], (pkg) => pkg.name),
    mapBy(targetPackages.packages || [], (pkg) => pkg.name),
    (basePkg, targetPkg) => basePkg.version !== targetPkg.version || basePkg.license !== targetPkg.license || basePkg.recipe !== targetPkg.recipe,
  );

  const commitChanged = (base.commit || "") !== (target.commit || "");
  const manifestChanged = (base.kas_manifest || "") !== (target.kas_manifest || "");
  const machineChanged = (base.machine || "") !== (target.machine || "");
  const unpatchedDelta = Number(target.cve_summary?.unpatched || 0) - Number(base.cve_summary?.unpatched || 0);
  const basePackageCount = packageCountFromData(base, basePackages);
  const targetPackageCount = packageCountFromData(target, targetPackages);
  const packageDelta = targetPackageCount - basePackageCount;
  const baseArtifacts = Number(baseDetail.artifacts?.length || base.artifact_count || 0);
  const targetArtifacts = Number(targetDetail.artifacts?.length || target.artifact_count || 0);
  const artifactDelta = targetArtifacts - baseArtifacts;
  const baseReadiness = readinessSummary(base);
  const targetReadiness = readinessSummary(target);
  const baseOrigins = originBuilds(base).length;
  const targetOrigins = originBuilds(target).length;

  el.compareStatus.textContent = `${releaseLabel(base)} -> ${releaseLabel(target)}`;
  el.compareOutput.innerHTML = `
    <div class="compare-summary">
      ${renderCompareMetric("Commit", commitChanged ? "changed" : "same", commitChanged ? "warn" : "ok")}
      ${renderCompareMetric("Manifest", manifestChanged ? "changed" : "same", manifestChanged ? "warn" : "ok")}
      ${renderCompareMetric("Machine", machineChanged ? "changed" : "same", machineChanged ? "warn" : "ok")}
      ${renderCompareMetric("Unpatched delta", `${unpatchedDelta > 0 ? "+" : ""}${unpatchedDelta}`, unpatchedDelta > 0 ? "danger" : unpatchedDelta < 0 ? "ok" : "")}
      ${renderCompareMetric("Artifacts", `+${artifactDiff.added.length} / -${artifactDiff.removed.length} / ~${artifactDiff.changed.length}`)}
      ${renderCompareMetric("Packages", `+${packageDiff.added.length} / -${packageDiff.removed.length} / ~${packageDiff.changed.length}`, packageDiff.added.length || packageDiff.changed.length ? "warn" : "")}
      ${renderCompareMetric("CVEs", `+${cveDiff.added.length} / -${cveDiff.removed.length} / ~${cveDiff.changed.length}`, cveDiff.added.length ? "danger" : cveDiff.removed.length ? "ok" : "")}
    </div>
    <div class="compare-identity">
      <div><span>Base commit</span><code>${escapeHtml(base.commit || "not recorded")}</code></div>
      <div><span>Target commit</span><code>${escapeHtml(target.commit || "not recorded")}</code></div>
      <div><span>Base manifest</span><code>${escapeHtml(base.kas_manifest || "not recorded")}</code></div>
      <div><span>Target manifest</span><code>${escapeHtml(target.kas_manifest || "not recorded")}</code></div>
    </div>
    <div class="compare-detail-grid">
      ${compareDetailCard("Build id", buildId(base, baseDetail) || "not recorded", buildId(target, targetDetail) || "not recorded", "")}
      ${compareDetailCard("Generated", dateLabel(base), dateLabel(target), dateValue(base) === dateValue(target) ? "ok" : "")}
      ${compareDetailCard("CVE posture", compareCveText(base), compareCveText(target), compareStatusClass(unpatchedDelta !== 0, unpatchedDelta > 0, unpatchedDelta < 0), `delta ${unpatchedDelta > 0 ? "+" : ""}${unpatchedDelta}`)}
      ${compareDetailCard("Critical CVEs", String(Number(base.cve_severity?.critical || 0)), String(Number(target.cve_severity?.critical || 0)), compareStatusClass(Number(base.cve_severity?.critical || 0) !== Number(target.cve_severity?.critical || 0), Number(target.cve_severity?.critical || 0) > Number(base.cve_severity?.critical || 0), Number(target.cve_severity?.critical || 0) < Number(base.cve_severity?.critical || 0)))}
      ${compareDetailCard("Packages", String(basePackageCount || "not recorded"), String(targetPackageCount || "not recorded"), compareStatusClass(packageDelta !== 0), `delta ${packageDelta > 0 ? "+" : ""}${packageDelta}`)}
      ${compareDetailCard("Artifacts listed", String(baseArtifacts), String(targetArtifacts), compareStatusClass(artifactDelta !== 0), `delta ${artifactDelta > 0 ? "+" : ""}${artifactDelta}`)}
      ${compareDetailCard("Flashing", base.flashing?.ready ? "ready" : "incomplete", target.flashing?.ready ? "ready" : "incomplete", compareStatusClass(Boolean(base.flashing?.ready) !== Boolean(target.flashing?.ready), !target.flashing?.ready, Boolean(target.flashing?.ready) && !base.flashing?.ready))}
      ${compareDetailCard("Release readiness", compareReadinessText(base), compareReadinessText(target), compareStatusClass(baseReadiness.ready !== targetReadiness.ready, !targetReadiness.ready, targetReadiness.ready && !baseReadiness.ready), targetReadiness.failed.map((check) => check.label).join(", "))}
      ${compareDetailCard("Dev origins", `${baseOrigins} linked`, `${targetOrigins} linked`, compareStatusClass(baseOrigins !== targetOrigins, targetOrigins < baseOrigins, targetOrigins > baseOrigins))}
    </div>
    <div class="compare-grid">
      ${renderDiffList("New artifacts", artifactDiff.added, (artifact) => `<div class="item-meta mono">${escapeHtml(artifact.name)}</div>`, "No new artifacts")}
      ${renderDiffList("Removed artifacts", artifactDiff.removed, (artifact) => `<div class="item-meta mono">${escapeHtml(artifact.name)}</div>`, "No removed artifacts")}
      ${renderDiffList("Changed layers", layerDiff.changed, (entry) => `<div class="item-meta"><strong>${escapeHtml(entry.key)}</strong><br><code>${escapeHtml(shortCommit(entry.base.commit || ""))}</code> -> <code>${escapeHtml(shortCommit(entry.target.commit || ""))}</code></div>`, "No layer commit changes")}
      ${renderDiffList("New packages", packageDiff.added, (pkg) => `<div class="item-meta"><strong>${escapeHtml(pkg.name)}</strong> ${escapeHtml(pkg.version || "")}<br>${escapeHtml(pkg.license || "")}</div>`, "No new packages")}
      ${renderDiffList("Removed packages", packageDiff.removed, (pkg) => `<div class="item-meta"><strong>${escapeHtml(pkg.name)}</strong> ${escapeHtml(pkg.version || "")}<br>${escapeHtml(pkg.license || "")}</div>`, "No removed packages")}
      ${renderDiffList("Changed packages", packageDiff.changed, (entry) => `<div class="item-meta"><strong>${escapeHtml(entry.key)}</strong><br>${escapeHtml(entry.base.version || "")} -> ${escapeHtml(entry.target.version || "")}<br>${escapeHtml(entry.base.license || "")} -> ${escapeHtml(entry.target.license || "")}</div>`, "No package version/license changes")}
      ${renderDiffList("New CVEs", cveDiff.added, (issue) => `<div class="item-meta"><strong>${escapeHtml(cveLabel(issue))}</strong> ${escapeHtml(issue.severity || "")} ${escapeHtml(issue.status || "")}</div>`, "No new CVEs")}
      ${renderDiffList("Resolved CVEs", cveDiff.removed, (issue) => `<div class="item-meta"><strong>${escapeHtml(cveLabel(issue))}</strong> ${escapeHtml(issue.severity || "")} ${escapeHtml(issue.status || "")}</div>`, "No resolved CVEs")}
      ${renderDiffList("Changed CVEs", cveDiff.changed, (entry) => `<div class="item-meta"><strong>${escapeHtml(cveLabel(entry.target))}</strong><br>${escapeHtml(entry.base.status || "")} ${escapeHtml(entry.base.severity || "")} -> ${escapeHtml(entry.target.status || "")} ${escapeHtml(entry.target.severity || "")}</div>`, "No CVE status changes")}
    </div>
  `;
}

function latestGroups() {
  const groups = new Map();
  for (const release of state.releases) {
    const key = [release.channel || "unknown", release.machine || "unknown", release.kas_manifest || "unknown"].join("|");
    const current = groups.get(key);
    if (!current || dateValue(release) >= dateValue(current)) groups.set(key, release);
  }
  return [...groups.values()].sort((a, b) => dateValue(b) - dateValue(a)).slice(0, 8);
}

function renderLatest() {
  const latest = latestGroups();
  if (!latest.length) {
    el.latestList.innerHTML = `<div class="item-meta">No builds indexed.</div>`;
    return;
  }
  el.latestList.innerHTML = latest.map((release) => `
    <button class="latest-item ${release.id === state.selectedId ? "selected" : ""}" data-id="${escapeHtml(release.id)}">
      <span>${channelBadge(release.channel)}</span>
      <strong>${escapeHtml(release.machine || "unknown")}</strong>
      <small>${escapeHtml(release.tag || release.artifact_label || release.id)}</small>
    </button>
  `).join("");
  el.latestList.querySelectorAll(".latest-item").forEach((button) => {
    button.addEventListener("click", () => {
      state.selectedId = button.dataset.id;
      state.tab = "summary";
      renderAll();
    });
  });
}

function sortableHeader(key, label) {
  return `<button class="sort-button" type="button" data-sort="${escapeHtml(key)}">${escapeHtml(label)}${escapeHtml(sortIndicator(key))}</button>`;
}

function releasedFromDevelopment(devRelease) {
  if (devRelease.channel !== "development") return [];
  return state.releases
    .filter((release) => (release.channel === "release" || release.channel === "rc") && originBuilds(release).some((origin) => origin.id === devRelease.id))
    .sort((a, b) => dateValue(b) - dateValue(a));
}

function renderLineageMeta(release) {
  if (release.channel === "release" || release.channel === "rc") {
    const origins = originBuilds(release);
    if (origins.length) {
      const links = origins.map((origin) => `<button class="inline-link" type="button" data-select-build="${escapeHtml(origin.id)}">${escapeHtml(origin.label || origin.id)}</button> <span>${escapeHtml(origin.match || "linked")}</span>`).join(", ");
      return `<div class="item-meta lineage-meta">from dev ${links}</div>`;
    }
    return `<div class="item-meta lineage-meta warn">dev origin missing</div>`;
  }
  const released = releasedFromDevelopment(release);
  if (!released.length) return "";
  return `<div class="item-meta lineage-meta">released as ${released.map((item) => `<button class="inline-link" type="button" data-select-build="${escapeHtml(item.id)}">${escapeHtml(item.tag || item.artifact_label || item.id)}</button>`).join(", ")}</div>`;
}

function renderTable() {
  el.releaseCount.textContent = `${state.filtered.length} shown | sorted by ${state.sortKey} ${state.sortDirection}`;
  if (state.filtered.length === 0) {
    el.releaseTable.innerHTML = `<div class="empty-state"><p>No builds in ${escapeHtml(channelTitle(state.activeChannel).toLowerCase())} match the current filters.</p></div>`;
    return;
  }

  const rows = state.filtered.map((release) => `
    <tr class="release-row ${release.id === state.selectedId ? "selected" : ""}" data-id="${escapeHtml(release.id)}">
      <td><strong>${escapeHtml(releaseName(release))}</strong><div class="item-meta">${escapeHtml(release.tag ? (release.artifact_label || "") : release.id)}</div>${renderLineageMeta(release)}</td>
      <td>${channelBadge(release.channel)}</td>
      <td>${escapeHtml(release.machine || "")}</td>
      <td>${escapeHtml(release.kas_manifest || "")}</td>
      <td class="mono" title="${escapeHtml(release.commit || "")}">${escapeHtml(shortCommit(release.commit || ""))}</td>
      <td>${cveBadge(release.cve_summary)}</td>
      <td class="mono" title="${escapeHtml(release.generated_at_utc || release.cached_at_utc || "")}">${escapeHtml(dateLabel(release))}</td>
    </tr>
  `).join("");

  el.releaseTable.innerHTML = `
    <table>
      <thead><tr>
        <th>${sortableHeader("name", "Build")}</th>
        <th>${sortableHeader("channel", "Channel")}</th>
        <th>${sortableHeader("machine", "Machine")}</th>
        <th>${sortableHeader("manifest", "Manifest")}</th>
        <th>${sortableHeader("commit", "Commit")}</th>
        <th>${sortableHeader("cve", "CVE")}</th>
        <th>${sortableHeader("date", "Generated")}</th>
      </tr></thead>
      <tbody>${rows}</tbody>
    </table>
  `;
  el.releaseTable.querySelectorAll("[data-sort]").forEach((button) => {
    button.addEventListener("click", () => setSort(button.dataset.sort));
  });
  bindBuildLinks(el.releaseTable);
  el.releaseTable.querySelectorAll("tr.release-row").forEach((row) => {
    row.addEventListener("click", () => {
      state.selectedId = row.dataset.id;
      state.tab = "summary";
      renderAll();
    });
  });
}

async function loadReleaseDetail(release, options = {}) {
  if (!release || state.details.has(release.id)) return state.details.get(release?.id) || null;
  const detailPath = release.release_json ? `data/${release.release_json}` : "";
  state.details.set(release.id, loadingState(detailPath, "release metadata"));
  if (options.render !== false) renderDetails();
  try {
    const detail = await fetchJson(detailPath);
    state.details.set(release.id, detail);
    release.flashing = flashingReadiness(detail);
    if (options.render !== false) renderDetails();
    return detail;
  } catch (error) {
    const stored = storedLoadError(detailPath, error, "release");
    state.details.set(release.id, stored);
    if (options.render !== false) renderDetails();
    return stored;
  }
}

async function loadReleaseCve(release, options = {}) {
  if (!release || state.cveDetails.has(release.id)) return state.cveDetails.get(release?.id) || null;
  if (!release.cve_summary_path) return null;
  const cvePath = `data/${release.cve_summary_path}`;
  state.cveDetails.set(release.id, loadingState(cvePath, "CVE report"));
  if (options.render !== false) renderDetails();
  try {
    const cve = await fetchJson(cvePath);
    state.cveDetails.set(release.id, cve);
    release.cve_severity = cve.counts_by_severity || release.cve_severity || {};
    release.cve_issue_count = Array.isArray(cve.issues) ? cve.issues.length : release.cve_issue_count || 0;
    if (options.render !== false) renderDetails();
    return cve;
  } catch (error) {
    const stored = { ...storedLoadError(cvePath, error, "cve"), issues: [] };
    state.cveDetails.set(release.id, stored);
    if (options.render !== false) renderDetails();
    return stored;
  }
}

async function loadReleasePackages(release, options = {}) {
  if (!release || state.packageDetails.has(release.id)) return state.packageDetails.get(release?.id) || null;
  if (!release.package_manifest_path) return null;
  const packagePath = `data/${release.package_manifest_path}`;
  state.packageDetails.set(release.id, loadingState(packagePath, "package manifest"));
  if (options.render !== false) renderDetails();
  try {
    const packages = await fetchJson(packagePath);
    state.packageDetails.set(release.id, packages);
    release.package_count = packages.package_count || release.package_count || 0;
    if (options.render !== false) renderDetails();
    return packages;
  } catch (error) {
    const stored = { ...storedLoadError(packagePath, error, "package"), packages: [] };
    state.packageDetails.set(release.id, stored);
    if (options.render !== false) renderDetails();
    return stored;
  }
}

function ensureTabData(release) {
  if (!release) return;
  if (!state.details.has(release.id)) {
    loadReleaseDetail(release);
    return;
  }
  if (state.tab === "cves" && release.cve_summary_path && !state.cveDetails.has(release.id)) {
    loadReleaseCve(release);
  }
  if (state.tab === "packages" && release.package_manifest_path && !state.packageDetails.has(release.id)) {
    loadReleasePackages(release);
  }
}

function compareDataReady(base, target) {
  const required = [
    [base, "release", state.details, loadReleaseDetail],
    [target, "release", state.details, loadReleaseDetail],
    [base, "CVE", state.cveDetails, loadReleaseCve],
    [target, "CVE", state.cveDetails, loadReleaseCve],
    [base, "package", state.packageDetails, loadReleasePackages],
    [target, "package", state.packageDetails, loadReleasePackages],
  ];
  const pending = [];
  for (const [release, label, store, loader] of required) {
    if (!release) continue;
    if (!store.has(release.id)) {
      pending.push(`${label}: ${releaseLabel(release)}`);
      loader(release, { render: false }).then(renderCompare);
      continue;
    }
    const value = store.get(release.id);
    if (value?.__loading) pending.push(`${label}: ${releaseLabel(release)}`);
  }
  return pending;
}


function renderDetails() {
  const release = state.filtered.find((item) => item.id === state.selectedId);
  if (!release) {
    el.detailsEmpty.classList.remove("hidden");
    el.detailsPanel.classList.add("hidden");
    if (state.loadError) {
      el.detailsEmpty.innerHTML = renderLoadError(loadErrorTitle(state.loadError), state.loadError);
    } else if (!state.releases.length) {
      el.detailsEmpty.innerHTML = renderLoadError("No build data", { kind: "empty-index", message: "No builds are available in the loaded dashboard index." });
    } else {
      el.detailsEmpty.innerHTML = `<h2>No matching build</h2><p>The dashboard has build data, but the current filters do not match any build.</p>`;
    }
    return;
  }

  el.detailsEmpty.classList.add("hidden");
  el.detailsPanel.classList.remove("hidden");

  if (!state.details.has(release.id)) {
    const path = release.release_json ? `data/${release.release_json}` : "";
    el.detailsPanel.innerHTML = `<div class="details-panel">${renderLoadingNotice("Loading build metadata", "Loading release.json before rendering build details.", path)}</div>`;
    loadReleaseDetail(release);
    return;
  }

  const detail = state.details.get(release.id) || {};
  if (detail.__loading) {
    el.detailsPanel.innerHTML = `<div class="details-panel">${renderLoadingNotice("Loading build metadata", "Loading release.json before rendering build details.", detail.path)}</div>`;
    return;
  }
  ensureTabData(release);
  const cve = state.cveDetails.get(release.id) || {};
  const packages = state.packageDetails.get(release.id) || {};
  const summary = release.cve_summary || {};
  const azureUrl = azureBuildUrl(release, detail);

  el.detailsPanel.innerHTML = `
    <div class="details-panel">
      <div class="section-head">
        <div>
          <h2>${escapeHtml(release.tag || release.artifact_label || release.id)}</h2>
          <p class="item-meta mono">${escapeHtml(release.id || "")}</p>
          <p class="item-meta mono">${escapeHtml(release.commit || "")}</p>
        </div>
        <div class="header-actions">
          ${channelBadge(release.channel)}
          ${readinessBadge(release.flashing || flashingReadiness(detail))}
          ${cveBadge(summary)}
          ${azureUrl ? `<a class="link-button" href="${escapeHtml(azureUrl)}" target="_blank" rel="noreferrer">Azure</a>` : ""}
        </div>
      </div>
      <div class="detail-grid">
        <div class="metric"><span>Channel</span><strong>${escapeHtml(release.channel || "")}</strong></div>
        <div class="metric"><span>Machine</span><strong>${escapeHtml(release.machine || "")}</strong></div>
        <div class="metric"><span>Artifacts</span><strong>${Number(release.artifact_count || detail.artifacts?.length || 0)}</strong></div>
        <div class="metric"><span>Packages</span><strong>${Number(release.package_manifest?.package_count || packages.package_count || 0)}</strong></div>
        <div class="metric"><span>Unpatched CVEs</span><strong>${Number(summary.unpatched || 0)}</strong></div>
      </div>
      ${renderTabs()}
      <div id="tabContent">${renderTabContent(release, detail, cve, packages)}</div>
    </div>
  `;
  el.detailsPanel.querySelectorAll(".tab-button").forEach((button) => {
    button.addEventListener("click", () => {
      state.tab = button.dataset.tab;
      renderDetails();
    });
  });
  bindCveControls();
  bindPackageControls();
  bindBuildLinks();
}

function renderTabs() {
  const tabs = [
    ["summary", "Summary"],
    ["artifacts", "Artifacts"],
    ["packages", "Packages"],
    ["cves", "CVEs"],
    ["layers", "Layers"],
    ["metadata", "Metadata"],
  ];
  return `<div class="tabs">${tabs.map(([id, label]) => (
    `<button class="tab-button ${state.tab === id ? "active" : ""}" data-tab="${id}">${label}</button>`
  )).join("")}</div>`;
}

function renderTabContent(release, detail, cve, packages) {
  if (detail.error) return renderLoadError("Could not load release.json", detail);
  if (state.tab === "summary") return renderSummary(release, detail, cve);
  if (state.tab === "artifacts") return renderArtifacts(detail.artifacts || []);
  if (state.tab === "packages") {
    if (release.package_manifest_path && !state.packageDetails.has(release.id)) return renderLoadingNotice("Loading package manifest", "Package manifests load only when this tab is opened.", `data/${release.package_manifest_path}`);
    return renderPackages(packages, release);
  }
  if (state.tab === "cves") {
    if (release.cve_summary_path && !state.cveDetails.has(release.id)) return renderLoadingNotice("Loading CVE report", "CVE reports load only when this tab is opened or during compare.", `data/${release.cve_summary_path}`);
    return renderCves(cve, release);
  }
  if (state.tab === "layers") return renderLayers(detail.layers || [], release);
  return renderMetadata(release, detail, cve);
}


function renderOriginBuild(release) {
  if (release.channel === "development") {
    const released = releasedFromDevelopment(release);
    if (!released.length) {
      return `<div class="item origin-card info">
        <div class="item-head"><div class="item-title">Release lineage</div><span class="badge unknown">No tag yet</span></div>
        <div class="item-meta">No release/RC currently points back to this development build.</div>
      </div>`;
    }
    return `<div class="item origin-card ok">
      <div class="item-head"><div class="item-title">Release lineage</div><span class="badge ok">${released.length} linked</span></div>
      ${released.map((item) => `<div class="item-meta">Released as: <button class="inline-link" type="button" data-select-build="${escapeHtml(item.id)}">${escapeHtml(item.tag || item.artifact_label || item.id)}</button> <span>${escapeHtml(originMatchForDev(item, release.id))}</span></div>`).join("")}
    </div>`;
  }

  if (release.channel !== "release" && release.channel !== "rc") return "";
  const origins = originBuilds(release);
  const origin = release.origin_build || {};
  if (!origins.length) {
    return `<div class="item origin-card warn">
      <div class="item-head"><div class="item-title">Development origins</div><span class="badge warn">Not linked</span></div>
      <div class="item-meta">${escapeHtml(origin.reason || "No matching development build was found for this release commit.")}</div>
    </div>`;
  }
  return `<div class="item origin-card ok">
    <div class="item-head"><div class="item-title">Development origins</div><span class="badge ok">${origins.length} linked</span></div>
    ${origins.map((item) => `<div class="origin-link-row">
      <div class="item-meta">Build: <button class="inline-link" type="button" data-select-build="${escapeHtml(item.id)}">${escapeHtml(item.label || item.id)}</button> <span>${escapeHtml(item.match || "linked")}</span></div>
      <div class="item-meta">Azure build: ${escapeHtml(item.build_id || "not recorded")}</div>
      <div class="item-meta mono">${escapeHtml(item.commit || "")}</div>
      <div class="item-meta">${escapeHtml([item.machine, item.kas_manifest, item.generated_at_utc].filter(Boolean).join(" | "))}</div>
    </div>`).join("")}
  </div>`;
}

function selectBuildById(id) {
  const target = releaseById(id);
  if (!target) return;
  el.searchInput.value = "";
  el.cveFilter.value = "all";
  el.severityFilter.value = "all";
  if ([...el.machineFilter.options].some((option) => option.value === target.machine)) {
    el.machineFilter.value = target.machine || "all";
  }
  state.selectedId = target.id;
  state.tab = "summary";
  setActiveView("overview");
  setActiveChannel(target.channel || "all", { resetCompare: false });
}

function bindBuildLinks(root = el.detailsPanel) {
  root.querySelectorAll("[data-select-build]").forEach((button) => {
    button.addEventListener("click", (event) => {
      event.stopPropagation();
      const id = button.dataset.selectBuild || "";
      selectBuildById(id);
    });
  });
}

function renderSummary(release, detail, cve) {
  const summary = release.cve_summary || {};
  const azureUrl = azureBuildUrl(release, detail);
  const id = buildId(release, detail);
  const published = detail.published_artifacts || release.published_artifacts || {};
  const smoke = smokeStatus(detail);
  const severity = cve.counts_by_severity || release.cve_severity || {};
  const readiness = release.flashing || flashingReadiness(detail);
  return `<div class="list-block">
    <div class="item">
      <div class="item-head"><div class="item-title">Build</div>${channelBadge(release.channel)}</div>
      <div class="item-meta">Build id: ${escapeHtml(id || "not recorded")}</div>
      <div class="item-meta">Generated: ${escapeHtml(release.generated_at_utc || detail.generated_at_utc || "not recorded")}</div>
      <div class="item-meta">Smoke: ${escapeHtml(smoke)}</div>
      ${azureUrl ? `<div class="item-meta"><a href="${escapeHtml(azureUrl)}" target="_blank" rel="noreferrer">Open Azure run</a></div>` : ""}
    </div>
    ${renderReadinessPanel(release, detail)}
    ${renderOriginBuild(release)}
    ${renderReleaseLayerTraceability(release, detail.layers || [])}
    <div class="item">
      <div class="item-head"><div class="item-title">Flashing readiness</div>${readinessBadge(readiness)}</div>
      <div class="item-meta">Boot: ${readiness.hasBoot ? "yes" : "no"} | WIC: ${readiness.hasWic ? "yes" : "no"} | BMAP: ${readiness.hasBmap ? "yes" : "no"} | SWU: ${readiness.hasSwu ? "yes" : "no"}</div>
    </div>
    <div class="item">
      <div class="item-head"><div class="item-title">CVE posture</div>${cveBadge(summary)}</div>
      <div class="item-meta">Packages with issues: ${Number(summary.packages_with_issues || 0)}</div>
      <div class="item-meta">Packages with unpatched: ${Number(summary.packages_with_unpatched || 0)}</div>
      <div class="item-meta">Critical: ${Number(severity.critical || 0)} | High: ${Number(severity.high || 0)} | Medium: ${Number(severity.medium || 0)}</div>
    </div>
    <div class="item">
      <div class="item-title">Published artifacts</div>
      <div class="item-meta">Images: ${escapeHtml(published.images || "not recorded")}</div>
      <div class="item-meta">Metadata: ${escapeHtml(published.metadata || "not recorded")}</div>
      <div class="item-meta">Release metadata: ${escapeHtml(published.release_metadata || "not recorded")}</div>
    </div>
  </div>`;
}

function renderArtifacts(artifacts) {
  if (!artifacts.length) return `<div class="empty-state"><p>No artifacts listed.</p></div>`;
  return `<div class="list-block">${artifacts.map((artifact) => `
    <div class="item">
      <div class="item-head"><div class="item-title">${escapeHtml(artifact.name)}</div><span class="badge unknown">${formatBytes(artifact.size_bytes)}</span></div>
      <div class="item-meta mono">sha256 ${escapeHtml(artifact.sha256 || "")}</div>
    </div>
  `).join("")}</div>`;
}

function packageLicenseCounts(packages) {
  const counts = new Map();
  for (const pkg of packages || []) {
    const license = pkg.license || "unknown";
    counts.set(license, (counts.get(license) || 0) + 1);
  }
  return [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
}

function packageSearchText(pkg) {
  return [pkg.name, pkg.version, pkg.recipe, pkg.license].filter(Boolean).join(" ").toLowerCase();
}

function bindPackageControls() {
  const input = document.getElementById("packageQuery");
  if (!input) return;
  input.addEventListener("change", () => {
    state.packageQuery = input.value || "";
    renderDetails();
  });
  document.querySelector("[data-package-filter-reset]")?.addEventListener("click", () => {
    state.packageQuery = "";
    renderDetails();
  });
}

function renderPackages(packageManifest, release = {}) {
  if (!release.package_manifest_path) return renderDataNotice("warn", "Build has no package manifest path", "The dashboard index does not point to package-manifest.json for this build.");
  if (packageManifest.__loading) return renderLoadingNotice("Loading package manifest", "Package manifests can be large. The package tab will render when package-manifest.json finishes loading.", packageManifest.path);
  if (packageManifest.error) return renderLoadError("Could not load package-manifest.json", packageManifest);
  if (!packageManifest.available) return renderDataNotice("warn", "Package manifest not imported", "The metadata artifact was loaded, but no package manifest was imported for this build.", [packageManifest.source ? `Source: ${packageManifest.source}` : ""]);
  const packages = Array.isArray(packageManifest.packages) ? packageManifest.packages : [];
  const query = (state.packageQuery || "").trim().toLowerCase();
  const filtered = packages
    .filter((pkg) => !query || packageSearchText(pkg).includes(query))
    .sort((a, b) => String(a.name || "").localeCompare(String(b.name || "")));
  const visible = filtered.slice(0, 500);
  const licenseCounts = packageLicenseCounts(packages).slice(0, 8);
  return `<div class="package-view">
    <div class="package-toolbar">
      <label class="field"><span>Search packages</span><input id="packageQuery" type="search" value="${escapeHtml(state.packageQuery || "")}" placeholder="package, recipe, license"></label>
      <button class="link-button" type="button" data-package-filter-reset>Reset</button>
    </div>
    <div class="cve-summary-grid">
      ${renderCveMetric("Installed packages", packages.length)}
      ${renderCveMetric("Visible packages", filtered.length)}
      ${renderCveMetric("Unique licenses", packageLicenseCounts(packages).length)}
      ${renderCveMetric("Image", packageManifest.image || "unknown")}
      ${renderCveMetric("Sources", packageManifest.images?.length || 0)}
    </div>
    <section class="cve-section">
      <div class="cve-section-head"><h3>Top Licenses</h3><span>By installed package count</span></div>
      <div class="license-chip-list">${licenseCounts.map(([license, count]) => `<span class="license-chip"><strong>${escapeHtml(count)}</strong> ${escapeHtml(license)}</span>`).join("")}</div>
    </section>
    <section class="cve-section">
      <div class="cve-section-head"><h3>Installed Package Manifest</h3><span>package, version, recipe, license</span></div>
      <div class="cve-table-shell">
        <table class="package-manifest-table">
          <thead><tr><th>Package</th><th>Version</th><th>Recipe</th><th>License</th></tr></thead>
          <tbody>${visible.map((pkg) => `
            <tr>
              <td><strong>${escapeHtml(pkg.name || "")}</strong></td>
              <td><span class="mono">${escapeHtml(pkg.version || "")}</span></td>
              <td>${escapeHtml(pkg.recipe || "")}</td>
              <td>${escapeHtml(pkg.license || "")}</td>
            </tr>
          `).join("")}</tbody>
        </table>
      </div>
      ${filtered.length > visible.length ? `<div class="cve-note">Showing first ${visible.length} packages. Use search to narrow the manifest.</div>` : ""}
    </section>
  </div>`;
}

function severityRank(severity) {
  return { critical: 0, high: 1, medium: 2, low: 3, none: 4, unknown: 5 }[String(severity || "unknown").toLowerCase()] ?? 5;
}

function statusRank(status) {
  return { unpatched: 0, ignored: 1, patched: 2, unknown: 3 }[String(status || "unknown").toLowerCase()] ?? 3;
}

function statusClass(status) {
  const normalized = String(status || "unknown").toLowerCase();
  if (normalized === "unpatched") return "danger";
  if (normalized === "patched") return "ok";
  if (normalized === "ignored") return "warn";
  return "unknown";
}

function normalizedStatus(issue) {
  return String(issue.status || "unknown");
}

function normalizedSeverity(issue) {
  return String(issue.severity || "unknown").toLowerCase();
}

function renderCveMetric(label, value, className = "") {
  return `<div class="cve-metric ${className}"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`;
}

function countBySeverity(issues) {
  return issues.reduce((counts, issue) => {
    const key = normalizedSeverity(issue);
    counts[key] = (counts[key] || 0) + 1;
    return counts;
  }, {});
}

function countByStatus(issues) {
  return issues.reduce((counts, issue) => {
    const key = normalizedStatus(issue);
    counts[key] = (counts[key] || 0) + 1;
    return counts;
  }, {});
}

function countUnpatchedIssues(issues) {
  return issues.filter((issue) => normalizedStatus(issue).toLowerCase() === "unpatched").length;
}

function countAffectedPackages(issues) {
  return new Set(issues.map((issue) => issue.package).filter(Boolean)).size;
}

function countUniqueCves(issues) {
  return new Set(issues.map((issue) => issue.id).filter(Boolean)).size;
}

function issueSearchText(issue) {
  return [
    issue.id,
    issue.package,
    issue.version,
    issue.layer,
    issue.status,
    issue.severity,
    issue.summary,
    issue.description,
  ].filter(Boolean).join(" ").toLowerCase();
}

function sortedStatuses(issues) {
  return [...new Set(issues.map(normalizedStatus))].sort((a, b) => statusRank(a) - statusRank(b) || a.localeCompare(b));
}

function sortedSeverities(issues) {
  return [...new Set(issues.map(normalizedSeverity))].sort((a, b) => severityRank(a) - severityRank(b) || a.localeCompare(b));
}

function sortedPackages(issues) {
  return [...new Set(issues.map((issue) => issue.package).filter(Boolean))].sort((a, b) => a.localeCompare(b));
}

function filteredCveIssues(issues) {
  const statuses = sortedStatuses(issues);
  const severities = sortedSeverities(issues);
  const packages = sortedPackages(issues);
  const status = statuses.includes(state.cveRowStatus) ? state.cveRowStatus : "all";
  const severity = severities.includes(state.cveRowSeverity) ? state.cveRowSeverity : "all";
  const selectedPackage = packages.includes(state.cveRowPackage) ? state.cveRowPackage : "all";
  const query = (state.cveRowQuery || "").trim().toLowerCase();
  return issues.filter((issue) => {
    if (status !== "all" && normalizedStatus(issue) !== status) return false;
    if (severity !== "all" && normalizedSeverity(issue) !== severity) return false;
    if (selectedPackage !== "all" && issue.package !== selectedPackage) return false;
    if (query && !issueSearchText(issue).includes(query)) return false;
    return true;
  });
}

function filterValue(id, fallback = "all") {
  return document.getElementById(id)?.value || fallback;
}

function clearFilters() {
  el.searchInput.value = "";
  el.machineFilter.value = "all";
  el.cveFilter.value = "all";
  el.severityFilter.value = "all";
  setActiveChannel("release", { resetCompare: false });
}

function bindCveControls() {
  const status = document.getElementById("cveRowStatus");
  if (!status) return;

  status.addEventListener("change", () => {
    state.cveRowStatus = filterValue("cveRowStatus");
    renderDetails();
  });
  document.getElementById("cveRowSeverity")?.addEventListener("change", () => {
    state.cveRowSeverity = filterValue("cveRowSeverity");
    renderDetails();
  });
  document.getElementById("cveRowPackage")?.addEventListener("change", () => {
    state.cveRowPackage = filterValue("cveRowPackage");
    renderDetails();
  });
  document.getElementById("cveRowQuery")?.addEventListener("change", () => {
    state.cveRowQuery = filterValue("cveRowQuery", "");
    renderDetails();
  });
  document.querySelector("[data-cve-filter-reset]")?.addEventListener("click", () => {
    state.cveRowStatus = "all";
    state.cveRowSeverity = "all";
    state.cveRowPackage = "all";
    state.cveRowQuery = "";
    renderDetails();
  });
  el.detailsPanel.querySelectorAll("[data-cve-package-filter]").forEach((button) => {
    button.addEventListener("click", () => {
      state.cveRowPackage = button.dataset.cvePackageFilter || "all";
      state.cveRowStatus = "all";
      state.cveRowSeverity = "all";
      state.cveRowQuery = "";
      renderDetails();
    });
  });
}

function renderCveOption(value, label, selected) {
  return `<option value="${escapeHtml(value)}" ${value === selected ? "selected" : ""}>${escapeHtml(label)}</option>`;
}

function renderCveControls(issues) {
  const statuses = sortedStatuses(issues);
  const severities = sortedSeverities(issues);
  const packages = sortedPackages(issues);
  const selectedStatus = statuses.includes(state.cveRowStatus) ? state.cveRowStatus : "all";
  const selectedSeverity = severities.includes(state.cveRowSeverity) ? state.cveRowSeverity : "all";
  const selectedPackage = packages.includes(state.cveRowPackage) ? state.cveRowPackage : "all";

  return `<div class="cve-filter-panel">
    <label class="field"><span>Status</span><select id="cveRowStatus">
      ${renderCveOption("all", "All statuses", selectedStatus)}
      ${statuses.map((status) => renderCveOption(status, status, selectedStatus)).join("")}
    </select></label>
    <label class="field"><span>Severity</span><select id="cveRowSeverity">
      ${renderCveOption("all", "All severities", selectedSeverity)}
      ${severities.map((severity) => renderCveOption(severity, severity, selectedSeverity)).join("")}
    </select></label>
    <label class="field"><span>Package</span><select id="cveRowPackage">
      ${renderCveOption("all", "All packages", selectedPackage)}
      ${packages.map((pkg) => renderCveOption(pkg, pkg, selectedPackage)).join("")}
    </select></label>
    <label class="field"><span>Search rows</span><input id="cveRowQuery" type="search" value="${escapeHtml(state.cveRowQuery || "")}" placeholder="CVE, package, layer"></label>
    <button class="link-button" type="button" data-cve-filter-reset>Reset</button>
  </div>`;
}

function countStatusSeverity(issues) {
  const matrix = new Map();
  for (const issue of issues) {
    const status = normalizedStatus(issue);
    const severity = normalizedSeverity(issue);
    if (!matrix.has(status)) matrix.set(status, {});
    const row = matrix.get(status);
    row[severity] = (row[severity] || 0) + 1;
    row.total = (row.total || 0) + 1;
  }
  return [...matrix.entries()].sort((a, b) => statusRank(a[0]) - statusRank(b[0]));
}

function packageSummaries(issues) {
  const packages = new Map();
  for (const issue of issues) {
    const name = issue.package || "unknown package";
    if (!packages.has(name)) {
      packages.set(name, {
        name,
        layers: new Set(),
        versions: new Set(),
        total: 0,
        unique: new Set(),
        unpatched: 0,
        patched: 0,
        ignored: 0,
        critical: 0,
        high: 0,
        medium: 0,
      });
    }
    const item = packages.get(name);
    item.total += 1;
    if (issue.id) item.unique.add(issue.id);
    if (issue.layer) item.layers.add(issue.layer);
    if (issue.version) item.versions.add(issue.version);
    const status = normalizedStatus(issue).toLowerCase();
    const severity = normalizedSeverity(issue);
    if (status === "unpatched") item.unpatched += 1;
    if (status === "patched") item.patched += 1;
    if (status === "ignored") item.ignored += 1;
    if (severity === "critical") item.critical += 1;
    if (severity === "high") item.high += 1;
    if (severity === "medium") item.medium += 1;
  }
  return [...packages.values()].sort((a, b) => (
    b.unpatched - a.unpatched ||
    b.critical - a.critical ||
    b.high - a.high ||
    b.total - a.total ||
    a.name.localeCompare(b.name)
  ));
}

function renderStatusMatrix(issues) {
  const severities = ["critical", "high", "medium", "low", "none", "unknown"];
  const rows = countStatusSeverity(issues).map(([status, counts]) => `
    <tr>
      <td><span class="badge ${statusClass(status)}">${escapeHtml(status)}</span></td>
      <td>${Number(counts.total || 0)}</td>
      ${severities.map((severity) => `<td>${Number(counts[severity] || 0)}</td>`).join("")}
    </tr>
  `).join("");
  return `<section class="cve-section">
    <div class="cve-section-head">
      <h3>Status by Severity</h3>
      <span>Rows split by remediation state</span>
    </div>
    <div class="cve-table-shell">
      <table class="cve-matrix">
        <thead><tr><th>Status</th><th>Total</th>${severities.map((severity) => `<th>${escapeHtml(severity)}</th>`).join("")}</tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  </section>`;
}

function renderPackageSummary(issues) {
  const packages = packageSummaries(issues);
  const visible = packages.slice(0, 40);
  const rows = visible.map((pkg) => `
    <tr>
      <td><button class="package-link" type="button" data-cve-package-filter="${escapeHtml(pkg.name)}">${escapeHtml(pkg.name)}</button><div class="item-meta">${escapeHtml([...pkg.layers].slice(0, 2).join(", ") || "layer not recorded")}</div></td>
      <td>${pkg.total}</td>
      <td>${pkg.unique.size}</td>
      <td class="danger-text">${pkg.unpatched}</td>
      <td>${pkg.patched}</td>
      <td>${pkg.ignored}</td>
      <td>${pkg.critical}</td>
      <td>${pkg.high}</td>
      <td><span class="mono">${escapeHtml([...pkg.versions].slice(0, 2).join(", ") || "")}</span></td>
    </tr>
  `).join("");
  const more = packages.length > visible.length ? `<div class="cve-note">Showing top ${visible.length} packages by open risk. ${packages.length - visible.length} additional packages are present in the full report or visible with filters.</div>` : "";
  return `<section class="cve-section">
    <div class="cve-section-head">
      <h3>Packages With CVE Rows</h3>
      <span>Click a package to drill down</span>
    </div>
    <div class="cve-table-shell">
      <table class="cve-package-table">
        <thead><tr><th>Package</th><th>Rows</th><th>Unique CVEs</th><th>Unpatched</th><th>Patched</th><th>Ignored</th><th>Critical</th><th>High</th><th>Version</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
    ${more}
  </section>`;
}

function renderCves(cve, release = {}) {
  if (!release.cve_summary_path) return renderDataNotice("warn", "Build has no CVE report path", "The dashboard index does not point to cve-summary.json for this build.");
  if (cve.__loading) return renderLoadingNotice("Loading CVE report", "Large CVE reports can take several seconds to download and parse. This tab will render automatically when loading completes.", cve.path);
  if (cve.error) return renderLoadError("Could not load cve-summary.json", cve);
  const issues = Array.isArray(cve.issues) ? cve.issues : [];
  if (!cve.available) return renderDataNotice("warn", "CVE report not imported", "No real CVE report was found in the metadata artifact for this build. Test-data reports are ignored.", [(cve.report_files || []).length ? `Report files: ${(cve.report_files || []).join(", ")}` : "No report files recorded"]);
  if (!issues.length) return renderDataNotice("info", "CVE report is clean", "The CVE report is present and has no issues.");

  const filteredIssues = filteredCveIssues(issues);
  const severity = countBySeverity(issues);
  const status = countByStatus(issues);
  const filteredSeverity = countBySeverity(filteredIssues);
  const unpatchedRows = countUnpatchedIssues(issues);
  const filteredUnpatchedRows = countUnpatchedIssues(filteredIssues);
  const affectedPackages = countAffectedPackages(issues);
  const ordered = [...filteredIssues].sort((a, b) => (
    statusRank(a.status) - statusRank(b.status) ||
    severityRank(a.severity) - severityRank(b.severity) ||
    Number(b.scorev3 || 0) - Number(a.scorev3 || 0) ||
    String(a.id || "").localeCompare(String(b.id || ""))
  ));
  const visibleIssues = ordered.slice(0, 200);
  const hiddenCount = Math.max(0, ordered.length - visibleIssues.length);

  return `<div class="cve-view">
    ${renderCveControls(issues)}
    <div class="cve-summary-grid">
      ${renderCveMetric("Visible rows", `${filteredIssues.length}/${issues.length}`)}
      ${renderCveMetric("Visible unique CVEs", `${countUniqueCves(filteredIssues)}/${countUniqueCves(issues)}`)}
      ${renderCveMetric("Visible unpatched", filteredUnpatchedRows, filteredUnpatchedRows ? "danger" : "ok")}
      ${renderCveMetric("All patched rows", status.Patched || 0, "ok")}
      ${renderCveMetric("Affected packages", affectedPackages)}
    </div>
    <div class="cve-summary-grid compact">
      ${renderCveMetric("All critical", severity.critical || 0, Number(severity.critical || 0) ? "danger" : "ok")}
      ${renderCveMetric("Visible critical", filteredSeverity.critical || 0, Number(filteredSeverity.critical || 0) ? "danger" : "ok")}
      ${renderCveMetric("All high", severity.high || 0, Number(severity.high || 0) ? "warn" : "ok")}
      ${renderCveMetric("Visible high", filteredSeverity.high || 0, Number(filteredSeverity.high || 0) ? "warn" : "ok")}
      ${renderCveMetric("All ignored", status.Ignored || 0, Number(status.Ignored || 0) ? "warn" : "ok")}
    </div>
    <div class="cve-note">Rows are package/recipe findings. Unique CVEs deduplicate by CVE ID, so one CVE affecting multiple packages counts as several rows but one unique CVE.</div>
    ${renderStatusMatrix(filteredIssues)}
    ${renderPackageSummary(filteredIssues)}
    ${hiddenCount ? `<div class="cve-note">Showing the first ${visibleIssues.length} filtered rows by risk. Narrow the filters to inspect a smaller set.</div>` : ""}
    <section class="cve-section">
      <div class="cve-section-head">
        <h3>Filtered CVE Rows</h3>
        <span>Unpatched rows first, then critical/high severity</span>
      </div>
      <div class="list-block cve-list">${visibleIssues.map((issue) => `
        <div class="item cve-item">
          <div class="item-head cve-item-head">
            <div class="item-title cve-title">
              <span>${escapeHtml(issue.id)}</span>
              <small>${escapeHtml(issue.package || "unknown package")} ${escapeHtml(issue.version || "")}</small>
            </div>
            <span class="badge ${severityClass(issue.severity, issue.status)}">${escapeHtml(issue.status || "unknown")} ${escapeHtml(issue.severity || "")}</span>
          </div>
          <div class="item-meta cve-meta">Layer: ${escapeHtml(issue.layer || "not recorded")} | CVSSv3: ${escapeHtml(issue.scorev3 || "n/a")} | <a href="${escapeHtml(issue.link || "#")}" target="_blank" rel="noreferrer">NVD</a></div>
          <div class="issue-summary">${escapeHtml(issue.summary || issue.description || "")}</div>
        </div>
      `).join("") || `<div class="empty-state"><p>No CVE rows match the current filters.</p></div>`}</div>
    </section>
  </div>`;
}

function requiresLayerTags(release) {
  return release?.channel === "release" || release?.channel === "rc";
}

function layerTag(layer) {
  if (layer?.tag) return layer.tag;
  if (Array.isArray(layer?.tags) && layer.tags.length) return layer.tags[0];
  return "";
}

function layerByName(layers) {
  const map = new Map();
  for (const layer of layers || []) {
    if (layer.name) map.set(layer.name, layer);
  }
  return map;
}

function releaseLayerRows(layers) {
  const byName = layerByName(layers);
  return REQUIRED_RELEASE_LAYER_NAMES.map((name) => ({ name, layer: byName.get(name) || null }));
}

function releaseLayerStatus(release, layers) {
  const required = requiresLayerTags(release);
  const rows = releaseLayerRows(layers);
  const missingLayers = rows.filter(({ layer }) => !layer);
  const missingTags = rows.filter(({ layer }) => layer && !layerTag(layer));
  if (required && (missingLayers.length || missingTags.length)) return "warn";
  if (required) return "ok";
  return "info";
}

function renderLayerTagBadge(release, layer) {
  if (!layer) return `<span class="badge danger">missing layer</span>`;
  const tag = layerTag(layer);
  if (tag) return `<span class="badge ok">${escapeHtml(tag)}</span>`;
  return requiresLayerTags(release)
    ? `<span class="badge warn">missing tag</span>`
    : `<span class="badge unknown">no tag</span>`;
}

function renderReleaseLayerTraceability(release, layers) {
  const rows = releaseLayerRows(layers);
  const status = releaseLayerStatus(release, layers);
  const required = requiresLayerTags(release);
  const missingTagCount = rows.filter(({ layer }) => layer && !layerTag(layer)).length;
  const missingLayerCount = rows.filter(({ layer }) => !layer).length;
  const title = required ? "Release layer tags" : "Layer tag traceability";
  const detail = required
    ? `${missingTagCount + missingLayerCount ? `${missingTagCount} missing tags, ${missingLayerCount} missing layers` : "all required layer tags present"}`
    : "tags are shown when present; they are not required for development builds";
  return `<div class="item release-layer-card ${status}">
    <div class="item-head"><div class="item-title">${escapeHtml(title)}</div><span class="badge ${status === "ok" ? "ok" : status === "warn" ? "warn" : "info"}">${escapeHtml(detail)}</span></div>
    <div class="release-layer-grid">
      ${rows.map(({ name, layer }) => `
        <div class="release-layer-row">
          <strong>${escapeHtml(name)}</strong>
          ${renderLayerTagBadge(release, layer)}
          <code>${escapeHtml(shortCommit(layer?.commit || ""))}</code>
          <small>${escapeHtml(layer?.branch || "")}</small>
        </div>
      `).join("")}
    </div>
  </div>`;
}

function renderLayers(layers, release = {}) {
  if (!layers.length) return `<div class="empty-state"><p>No layers listed.</p></div>`;
  return `<div class="list-block">
    ${renderReleaseLayerTraceability(release, layers)}
    ${layers.map((layer) => `
      <div class="item">
        <div class="item-head"><div class="item-title">${escapeHtml(layer.name)}</div>${renderLayerTagBadge(release, layer)}</div>
        <div class="item-meta mono">${escapeHtml(layer.commit || "")}</div>
        <div class="item-meta">Branch: ${escapeHtml(layer.branch || "")}</div>
        <div class="item-meta">${escapeHtml(layer.remote || "")}</div>
      </div>
    `).join("")}
  </div>`;
}

function renderMetadata(release, detail, cve) {
  const published = detail.published_artifacts || release.published_artifacts || {};
  return `<div class="list-block">
    <div class="item"><div class="item-title">Published artifacts</div><div class="item-meta">Images: ${escapeHtml(published.images || "")}</div><div class="item-meta">Metadata: ${escapeHtml(published.metadata || "")}</div><div class="item-meta">Release metadata: ${escapeHtml(published.release_metadata || "")}</div><div class="item-meta">Azure build: ${escapeHtml(buildId(release, detail) || "")}</div></div>
    <div class="item"><div class="item-title">Local files</div><div class="item-meta mono">${escapeHtml(release.release_json || "")}</div><div class="item-meta mono">${escapeHtml(release.cve_summary_path || "")}</div><div class="item-meta mono">${escapeHtml(release.build_manifest || "")}</div></div>
    <div class="item"><div class="item-title">CVE source reports</div><div class="item-meta">${(cve.report_files || []).map(escapeHtml).join("<br>") || "No files"}</div></div>
  </div>`;
}

function formatBytes(value) {
  const bytes = Number(value || 0);
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let size = bytes / 1024;
  let index = 0;
  while (size >= 1024 && index < units.length - 1) {
    size /= 1024;
    index += 1;
  }
  return `${size.toFixed(size >= 10 ? 1 : 2)} ${units[index]}`;
}

el.refreshButton.addEventListener("click", loadIndex);
el.clearFilters.addEventListener("click", clearFilters);
el.searchInput.addEventListener("input", applyFilters);
el.machineFilter.addEventListener("change", applyFilters);
el.channelFilter.addEventListener("change", () => setActiveChannel(el.channelFilter.value));
el.viewTabs.forEach((button) => {
  button.addEventListener("click", () => setActiveView(button.dataset.view));
});
el.channelTabs.forEach((button) => {
  button.addEventListener("click", () => setActiveChannel(button.dataset.channel));
});
el.cveFilter.addEventListener("change", applyFilters);
el.severityFilter.addEventListener("change", applyFilters);
el.compareBase.addEventListener("change", () => {
  state.compareBaseId = el.compareBase.value;
  state.compareRequested = true;
  renderCompare();
});
el.compareTarget.addEventListener("change", () => {
  state.compareTargetId = el.compareTarget.value;
  state.compareRequested = true;
  renderCompare();
});
el.compareSwap.addEventListener("click", () => {
  state.compareRequested = true;
  const nextBase = state.compareTargetId;
  state.compareTargetId = state.compareBaseId;
  state.compareBaseId = nextBase;
  el.compareBase.value = state.compareBaseId || "";
  el.compareTarget.value = state.compareTargetId || "";
  renderCompare();
});
syncViewTabs();
loadIndex();
