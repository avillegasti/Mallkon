import {
  OPTIONAL_RELEASE_REVIEW_CHECKS,
  RELEASE_REVIEW_CHECKS,
  REQUIRED_RELEASE_LAYER_NAMES,
  REVIEW_ACTOR_STORAGE_KEY,
  REVIEW_STORAGE_KEY,
} from "./config.js";
import {
  fetchJson,
  loadErrorMessage,
  loadErrorTitle,
  loadingState,
  normalizeLoadError,
  storedLoadError,
} from "./data.js";
import { escapeHtml, shortCommit } from "./format.js";
import { el, state } from "./state.js";

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

function inferPackageType(release, detail = {}) {
  const names = [...artifactNames(detail), release.artifact_label || "", release.tag || "", release.kas_manifest || "", release.id || ""];
  const text = names.filter(Boolean).join(" ").toLowerCase();
  if (text.includes("ostree")) return "OSTREE";
  if (text.includes("swupdate") || text.includes(".swu")) return "SWUpdate Image";
  if (text.includes("image") || text.includes("rootfs")) return "Image";
  if (release.flashing?.hasSwu) return "SWUpdate Image";
  if (text.includes("container") || text.includes("docker") || text.includes("torizon")) return "Container";
  return "Build Artifact";
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
        ${reviewBadge(release)}
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
  ensureReviewDataFor(releases, { render: false, renderLineage: true });
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
  if ((state.tab === "summary" || state.tab === "security" || state.tab === "metadata") && release.cve_summary_path && !state.cveDetails.has(release.id)) {
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


function isReleaseTag(release) {
  return release?.channel === "release" || release?.channel === "rc";
}

function reviewIdentity(release) {
  return [release?.tag || release?.artifact_label || release?.id, release?.machine, release?.kas_manifest]
    .filter(Boolean)
    .join("::");
}

function reviewApiPath(release) {
  return `/api/reviews/${encodeURIComponent(reviewIdentity(release))}`;
}

function reviewQuery(release) {
  const params = new URLSearchParams({
    tag: release?.tag || "",
    build: release?.artifact_label || release?.id || "",
    machine: release?.machine || "",
    manifest: release?.kas_manifest || "",
    commit: release?.commit || "",
  });
  return `${reviewApiPath(release)}?${params.toString()}`;
}

function reviewReleaseMetadata(release) {
  return {
    tag: release?.tag || "",
    build: release?.artifact_label || release?.id || "",
    machine: release?.machine || "",
    manifest: release?.kas_manifest || "",
    commit: release?.commit || "",
  };
}

function readReviewStore() {
  try {
    const raw = window.localStorage.getItem(REVIEW_STORAGE_KEY);
    const parsed = raw ? JSON.parse(raw) : {};
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  } catch (error) {
    return {};
  }
}

function writeReviewStore(store) {
  try {
    window.localStorage.setItem(REVIEW_STORAGE_KEY, JSON.stringify(store));
    return true;
  } catch (error) {
    return false;
  }
}

function cleanReviewerName(value = "") {
  const reviewer = String(value || "").trim();
  return reviewer.toLowerCase() === "unknown" ? "" : reviewer;
}

function currentReviewer(fallback = "") {
  try {
    const stored = cleanReviewerName(window.localStorage.getItem(REVIEW_ACTOR_STORAGE_KEY));
    if (stored) return stored;
    if (window.localStorage.getItem(REVIEW_ACTOR_STORAGE_KEY)) window.localStorage.removeItem(REVIEW_ACTOR_STORAGE_KEY);
    return cleanReviewerName(fallback);
  } catch (error) {
    return cleanReviewerName(fallback);
  }
}

function rememberReviewer(actor) {
  try {
    const reviewer = cleanReviewerName(actor);
    if (reviewer) window.localStorage.setItem(REVIEW_ACTOR_STORAGE_KEY, reviewer);
  } catch (error) {
    // Ignore browser storage failures; the backend still receives the actor.
  }
}

function emptyReview() {
  return {
    status: "Draft",
    owner: "",
    jira: "",
    note: "",
    actor: currentReviewer(),
    updatedAt: "",
    updatedBy: "",
    lastReviewedAt: "",
    source: "local",
    apiError: "",
    checks: Object.fromEntries(RELEASE_REVIEW_CHECKS.map(([key]) => [key, false])),
    checkMeta: Object.fromEntries(RELEASE_REVIEW_CHECKS.map(([key]) => [key, { checkedBy: "", checkedAt: "", updatedAt: "" }])),
  };
}

function normalizeApiReview(data = {}) {
  const base = emptyReview();
  const checks = { ...base.checks };
  const checkMeta = { ...base.checkMeta };
  for (const item of data.checklist || []) {
    if (!item?.key) continue;
    checks[item.key] = Boolean(item.checked);
    checkMeta[item.key] = {
      checkedBy: item.checked_by || item.checkedBy || "",
      checkedAt: item.checked_at || item.checkedAt || "",
      updatedAt: item.updated_at || item.updatedAt || "",
    };
  }
  return {
    ...base,
    status: data.status || base.status,
    owner: data.owner || "",
    jira: data.jira || data.jira_url || "",
    note: data.note || data.decision_note || "",
    updatedAt: data.updated_at || data.updatedAt || "",
    updatedBy: data.updated_by || data.updatedBy || "",
    lastReviewedAt: data.last_reviewed_at || data.lastReviewedAt || "",
    source: data.source || "database",
    checks,
    checkMeta,
  };
}

function localReview(release) {
  const key = reviewIdentity(release);
  const stored = readReviewStore()[key] || {};
  const base = emptyReview();
  return {
    ...base,
    ...stored,
    jira: stored.jira || stored.jira_url || "",
    note: stored.note || stored.decision_note || "",
    updatedBy: stored.updatedBy || stored.updated_by || "",
    lastReviewedAt: stored.lastReviewedAt || stored.last_reviewed_at || stored.updatedAt || "",
    source: stored.source || "local",
    checks: { ...base.checks, ...(stored.checks || {}) },
    checkMeta: { ...base.checkMeta, ...(stored.checkMeta || {}) },
  };
}

function releaseReview(release) {
  const cached = state.reviews.get(release?.id);
  if (cached && !cached.__loading) return cached;
  const fallback = localReview(release);
  return cached?.__loading ? { ...fallback, __loading: true } : fallback;
}

function saveLocalReleaseReview(release, review, apiError = "") {
  const key = reviewIdentity(release);
  if (!key) return null;
  const now = new Date().toISOString();
  const actor = cleanReviewerName(review.actor) || cleanReviewerName(review.owner);
  const previous = localReview(release);
  const checkMeta = { ...previous.checkMeta };
  for (const [checkKey, checked] of Object.entries(review.checks || {})) {
    const wasChecked = Boolean(previous.checks?.[checkKey]);
    if (checked && !wasChecked) checkMeta[checkKey] = { checkedBy: actor, checkedAt: now, updatedAt: now };
    if (!checked && wasChecked) checkMeta[checkKey] = { checkedBy: "", checkedAt: "", updatedAt: now };
  }
  const storedReview = {
    status: review.status || "Draft",
    owner: review.owner || "",
    jira: review.jira || "",
    note: review.note || "",
    actor,
    updatedAt: now,
    updatedBy: actor,
    lastReviewedAt: now,
    source: apiError ? "local-fallback" : "local",
    apiError,
    checks: { ...emptyReview().checks, ...(review.checks || {}) },
    checkMeta,
  };
  const store = readReviewStore();
  store[key] = storedReview;
  if (!writeReviewStore(store)) return null;
  state.reviews.set(release.id, storedReview);
  return storedReview;
}

async function loadReleaseReview(release, options = {}) {
  if (!isReleaseTag(release)) return null;
  if (!state.reviews.has(release.id)) state.reviews.set(release.id, { __loading: true });
  try {
    const data = await fetchJson(reviewQuery(release));
    const normalized = normalizeApiReview(data);
    state.reviews.set(release.id, normalized);
    if (options.renderLineage && state.activeView === "lineage") renderLineage();
    else if (options.render !== false) renderDetails();
    return normalized;
  } catch (error) {
    const fallback = { ...localReview(release), apiError: normalizeLoadError(error).message, source: "local-fallback" };
    state.reviews.set(release.id, fallback);
    if (options.renderLineage && state.activeView === "lineage") renderLineage();
    else if (options.render !== false) renderDetails();
    return fallback;
  }
}

async function loadReleaseAudit(release, options = {}) {
  if (!isReleaseTag(release)) return null;
  if (!state.reviewAudits.has(release.id)) state.reviewAudits.set(release.id, { __loading: true, events: [] });
  try {
    const data = await fetchJson(`${reviewApiPath(release)}/audit`);
    const audit = { events: Array.isArray(data.events) ? data.events : [] };
    state.reviewAudits.set(release.id, audit);
    if (options.render !== false) renderDetails();
    return audit;
  } catch (error) {
    const normalized = normalizeLoadError(error);
    const audit = { error: normalized.message, events: [] };
    state.reviewAudits.set(release.id, audit);
    if (options.render !== false) renderDetails();
    return audit;
  }
}

function ensureReviewAuditData(release, options = {}) {
  if (!isReleaseTag(release) || state.reviewAudits.has(release.id)) return;
  state.reviewAudits.set(release.id, { __loading: true, events: [] });
  loadReleaseAudit(release, options);
}

function resetReviewAudit(release) {
  if (release?.id) state.reviewAudits.delete(release.id);
}

function auditActionLabel(event = {}) {
  if (event.action === "create_review") return "Created decision";
  if (event.action === "update_decision") return `Changed ${event.field || "decision"}`;
  if (event.action === "update_checklist") {
    const check = RELEASE_REVIEW_CHECKS.find(([key]) => key === event.field);
    return `Checklist: ${check ? check[1] : event.field || "item"}`;
  }
  return event.action || "Audit event";
}

function auditValue(value) {
  if (value === "True") return "checked";
  if (value === "False") return "unchecked";
  return value || "empty";
}

function renderReviewAudit(release) {
  const audit = state.reviewAudits.get(release.id) || { __loading: true, events: [] };
  if (audit.__loading) {
    return `<section class="review-audit"><div class="review-audit-head"><h3>Audit history</h3><span>Loading...</span></div></section>`;
  }
  if (audit.error) {
    return `<section class="review-audit"><div class="review-audit-head"><h3>Audit history</h3><span>Unavailable</span></div><div class="data-notice warn"><div class="data-notice-title">Could not load audit log</div><p>${escapeHtml(audit.error)}</p></div></section>`;
  }
  const events = audit.events || [];
  return `<section class="review-audit">
    <div class="review-audit-head">
      <h3>Audit history</h3>
      <span>${events.length ? `${events.length} events` : "No events"}</span>
    </div>
    <div class="review-audit-list">
      ${events.length ? events.slice(0, 20).map((event) => `
        <div class="review-audit-event">
          <div>
            <strong>${escapeHtml(auditActionLabel(event))}</strong>
            <span>${escapeHtml(event.actor || "unknown")} | ${escapeHtml(reviewTimestampLabel(event.created_at))}</span>
          </div>
          <code>${escapeHtml(auditValue(event.old_value))} -> ${escapeHtml(auditValue(event.new_value))}</code>
        </div>
      `).join("") : `<div class="item-meta">No audit events saved for this tag yet.</div>`}
    </div>
  </section>`;
}

function ensureReviewData(release, options = {}) {
  if (!isReleaseTag(release) || state.reviews.has(release.id)) return;
  state.reviews.set(release.id, { __loading: true });
  loadReleaseReview(release, options);
}

function ensureReviewDataFor(releases, options = {}) {
  for (const release of releases || []) ensureReviewData(release, options);
}

async function saveReleaseReview(release, review) {
  const actor = (review.actor || "").trim();
  if (!actor) return null;
  rememberReviewer(actor);
  const payload = {
    actor,
    release: reviewReleaseMetadata(release),
    status: review.status || "Draft",
    owner: review.owner || "",
    jira: review.jira || "",
    note: review.note || "",
    checks: { ...emptyReview().checks, ...(review.checks || {}) },
  };
  try {
    const response = await fetch(reviewApiPath(release), {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
    const data = await response.json();
    const normalized = normalizeApiReview(data);
    state.reviews.set(release.id, normalized);
    return normalized;
  } catch (error) {
    return saveLocalReleaseReview(release, { ...payload, actor }, `API unavailable: ${error.message || error}`);
  }
}

function reviewTimestampLabel(value) {
  const time = Date.parse(value || "");
  if (Number.isNaN(time)) return "not reviewed yet";
  return new Date(time).toISOString().replace("T", " ").slice(0, 16);
}

function reviewProgress(review) {
  const checks = review?.checks || {};
  const requiredChecks = RELEASE_REVIEW_CHECKS.filter(([key]) => !OPTIONAL_RELEASE_REVIEW_CHECKS.has(key));
  const done = requiredChecks.filter(([key]) => Boolean(checks[key])).length;
  return { done, total: requiredChecks.length };
}

function reviewStatusClass(status) {
  const value = String(status || "").toLowerCase();
  if (value === "approved" || value === "released") return "ok";
  if (value === "blocked") return "danger";
  if (value === "under review") return "warn";
  return "unknown";
}

function reviewBadge(release) {
  if (!isReleaseTag(release)) return "";
  const review = releaseReview(release);
  const progress = reviewProgress(review);
  const loading = review.__loading ? " loading" : "";
  return `<span class="badge ${reviewStatusClass(review.status)}" title="Release review: ${progress.done}/${progress.total} checks${loading}">${escapeHtml(review.status)} ${progress.done}/${progress.total}</span>`;
}

function previousReleaseFor(release) {
  if (!isReleaseTag(release)) return null;
  const releases = releaseCandidatesSorted();
  const currentTime = dateValue(release);
  const older = releases.filter((item) => item.id !== release.id && dateValue(item) <= currentTime);
  return older.find((item) => item.machine === release.machine && item.kas_manifest === release.kas_manifest) || older[0] || null;
}

function reportFileBase(release) {
  return safeFileName([release.tag || release.artifact_label || release.id, release.machine].filter(Boolean).join("-")) || "release-report";
}

function safeFileName(value) {
  return String(value || "")
    .replace(/[^A-Za-z0-9._-]+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 120);
}

function md(value) {
  return String(value ?? "").replace(/\r?\n/g, " ").trim() || "not recorded";
}

function mdCell(value) {
  return md(value).replace(/\|/g, "\\|");
}

function markdownTable(headers, rows) {
  if (!rows.length) return "No entries recorded.\n";
  return [
    `| ${headers.map(mdCell).join(" | ")} |`,
    `| ${headers.map(() => "---").join(" | ")} |`,
    ...rows.map((row) => `| ${row.map(mdCell).join(" | ")} |`),
  ].join("\n") + "\n";
}

function cveSeverityText(release, cve = {}) {
  const severity = cve.counts_by_severity || release.cve_severity || {};
  return `critical ${Number(severity.critical || 0)}, high ${Number(severity.high || 0)}, medium ${Number(severity.medium || 0)}, low ${Number(severity.low || 0)}`;
}

function cveReportRows(cve = {}) {
  const issues = Array.isArray(cve.issues) ? cve.issues : [];
  return issues
    .filter((issue) => String(issue.status || "").toLowerCase() === "unpatched" || String(issue.severity || "").toLowerCase() === "critical")
    .sort((a, b) => (
      statusRank(a.status) - statusRank(b.status) ||
      severityRank(a.severity) - severityRank(b.severity) ||
      String(a.id || "").localeCompare(String(b.id || ""))
    ))
    .slice(0, 25)
    .map((issue) => [issue.id || "", issue.package || "", issue.status || "", issue.severity || "", issue.layer || ""]);
}

function releaseReportModel(release, detail = {}, cve = {}) {
  const previous = previousReleaseFor(release);
  const regressions = previous ? releaseRegressionAlerts(release, previous) : [];
  const readiness = readinessSummary(release, detail);
  const origins = originBuilds(release);
  const summary = release.cve_summary || {};
  const artifacts = Array.isArray(detail.artifacts) ? detail.artifacts : [];
  const trace = layerTraceability(release, detail);
  return { previous, regressions, readiness, origins, summary, artifacts, trace, cve };
}

function buildReleaseReportMarkdown(release, detail = {}, cve = {}) {
  const model = releaseReportModel(release, detail, cve);
  const lines = [];
  lines.push(`# Release Report: ${md(release.tag || release.artifact_label || release.id)}`);
  lines.push("");
  lines.push(`Generated: ${new Date().toISOString()}`);
  lines.push("");
  lines.push("## Build");
  lines.push(`- Tag: ${md(release.tag || "not a tag")}`);
  lines.push(`- Build: ${md(release.artifact_label || release.id)}`);
  lines.push(`- Channel: ${md(release.channel)}`);
  lines.push(`- Machine: ${md(release.machine)}`);
  lines.push(`- Manifest: ${md(release.kas_manifest)}`);
  lines.push(`- Commit: ${md(release.commit)}`);
  lines.push(`- Azure build: ${md(buildId(release, detail))}`);
  lines.push(`- Generated: ${md(release.generated_at_utc || detail.generated_at_utc)}`);
  lines.push("");

  lines.push("## Development origins");
  lines.push(markdownTable(["Build", "Match", "Azure build", "Commit", "Manifest"], model.origins.map((origin) => [
    origin.label || origin.id,
    origin.match || "linked",
    origin.build_id || "",
    shortCommit(origin.commit || ""),
    origin.kas_manifest || "",
  ])).trim());
  lines.push("");

  lines.push("## Readiness");
  lines.push(`- Result: ${model.readiness.ready ? "ready" : `${model.readiness.failed.length} blocker(s)`}`);
  lines.push(markdownTable(["Check", "Status", "Detail"], model.readiness.checks.map((check) => [check.label, check.ok ? "OK" : "BLOCKED", check.detail])).trim());
  lines.push("");

  lines.push("## CVEs");
  lines.push(`- CVE report: ${model.summary.available ? "present" : "missing"}`);
  lines.push(`- Unpatched: ${Number(model.summary.unpatched || 0)}`);
  lines.push(`- Severity: ${cveSeverityText(release, cve)}`);
  const cveRows = cveReportRows(cve);
  lines.push(cveRows.length ? markdownTable(["CVE", "Package", "Status", "Severity", "Layer"], cveRows).trim() : "No critical or unpatched CVE rows were found in the loaded report.");
  lines.push("");

  lines.push("## Artifacts");
  lines.push(`- Total: ${model.artifacts.length || Number(release.artifact_count || 0)}`);
  lines.push(markdownTable(["Name", "Size", "SHA256"], model.artifacts.map((artifact) => [artifact.name || "", formatBytes(artifact.size_bytes), artifact.sha256 || ""])).trim());
  lines.push("");

  lines.push("## Regression vs previous tag");
  if (!model.previous) {
    lines.push("No previous release/RC tag found for comparison.");
  } else {
    lines.push(`- Baseline: ${md(releaseLabel(model.previous))}`);
    lines.push(`- Target: ${md(releaseLabel(release))}`);
    lines.push(model.regressions.length
      ? markdownTable(["Level", "Check", "Value", "Detail"], model.regressions.map((alert) => [alert.level, alert.title, alert.value, alert.detail])).trim()
      : "No regressions detected by dashboard checks.");
  }
  lines.push("");

  lines.push("## Release layer tags");
  lines.push(markdownTable(["Layer", "Present", "Tag", "Commit", "Branch"], (model.trace.rows || []).map((row) => [row.name, row.present ? "yes" : "no", row.tag || "", shortCommit(row.commit || ""), row.branch || ""])).trim());
  lines.push("");
  return lines.join("\n");
}

function buildReleaseReportHtml(release, detail = {}, cve = {}) {
  const markdown = buildReleaseReportMarkdown(release, detail, cve);
  const body = markdown
    .split("\n")
    .map((line) => {
      if (line.startsWith("# ")) return `<h1>${escapeHtml(line.slice(2))}</h1>`;
      if (line.startsWith("## ")) return `<h2>${escapeHtml(line.slice(3))}</h2>`;
      if (line.startsWith("- ")) return `<p>${escapeHtml(line)}</p>`;
      if (line.startsWith("| ")) return `<pre>${escapeHtml(line)}</pre>`;
      return line ? `<p>${escapeHtml(line)}</p>` : "";
    })
    .join("\n");
  return `<!doctype html><html><head><meta charset="utf-8"><title>${escapeHtml(releaseName(release))} report</title><style>body{font-family:system-ui,sans-serif;margin:32px;line-height:1.45;color:#111827}h1,h2{margin-top:24px}pre{background:#f8fafc;border:1px solid #d8e0e8;border-radius:6px;padding:8px;overflow:auto}p{margin:6px 0}</style></head><body>${body}</body></html>`;
}

function downloadTextFile(filename, content, type) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}


function cveExportIssues(cve = {}) {
  const issues = Array.isArray(cve.issues) ? cve.issues : [];
  return [...issues].sort((a, b) => (
    statusRank(a.status) - statusRank(b.status) ||
    severityRank(a.severity) - severityRank(b.severity) ||
    Number(b.scorev3 || 0) - Number(a.scorev3 || 0) ||
    String(a.package || "").localeCompare(String(b.package || "")) ||
    String(a.id || "").localeCompare(String(b.id || ""))
  ));
}

function cveExportRows(release, cve = {}) {
  return cveExportIssues(cve).map((issue) => ({
    tag: release.tag || "",
    build: release.artifact_label || release.id || "",
    machine: release.machine || "",
    manifest: release.kas_manifest || "",
    commit: release.commit || "",
    package: issue.package || "",
    version: issue.version || "",
    cve: issue.id || "",
    cve_web: issue.link || "",
    status: issue.status || "",
    severity: issue.severity || "",
    cvss_v3: issue.scorev3 || "",
    cvss_v2: issue.scorev2 || "",
    layer: issue.layer || "",
    summary: issue.summary || issue.description || "",
    detail: issue.detail || "",
  }));
}

function csvCell(value) {
  const text = String(value ?? "").replace(/\r?\n/g, " ");
  return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

function buildFullCveCsv(release, cve = {}) {
  const columns = [
    "tag", "build", "machine", "manifest", "commit", "package", "version", "cve", "cve_web",
    "status", "severity", "cvss_v3", "cvss_v2", "layer", "summary", "detail",
  ];
  const rows = cveExportRows(release, cve);
  return [columns.join(","), ...rows.map((row) => columns.map((key) => csvCell(row[key])).join(","))].join("\n") + "\n";
}

function buildFullCveJson(release, cve = {}) {
  const rows = cveExportRows(release, cve);
  const payload = {
    schema_version: 1,
    exported_at_utc: new Date().toISOString(),
    tag: release.tag || "",
    build: release.artifact_label || release.id || "",
    machine: release.machine || "",
    manifest: release.kas_manifest || "",
    commit: release.commit || "",
    cve_report_available: Boolean(cve.available),
    counts_by_status: cve.counts_by_status || {},
    counts_by_severity: cve.counts_by_severity || release.cve_severity || {},
    issue_count: rows.length,
    columns: ["package", "version", "cve", "cve_web", "status", "severity", "cvss_v3", "cvss_v2", "layer", "summary", "detail"],
    issues: rows,
  };
  return JSON.stringify(payload, null, 2) + "\n";
}

async function exportFullCve(releaseId, format = "csv") {
  const release = releaseById(releaseId);
  if (!release) return;
  if (!release.cve_summary_path) {
    alert("This build has no CVE report path.");
    return;
  }
  const cve = await loadReleaseCve(release, { render: false }) || {};
  if (cve.error) {
    alert(`Could not export full CVE report: ${cve.error}`);
    return;
  }
  const base = reportFileBase(release);
  if (format === "json") {
    downloadTextFile(`${base}-full-cve.json`, buildFullCveJson(release, cve), "application/json;charset=utf-8");
  } else {
    downloadTextFile(`${base}-full-cve.csv`, buildFullCveCsv(release, cve), "text/csv;charset=utf-8");
  }
}

async function exportReleaseReport(releaseId, format = "markdown") {
  const release = releaseById(releaseId);
  if (!release) return;
  const detail = await loadReleaseDetail(release, { render: false }) || {};
  const cve = release.cve_summary_path ? await loadReleaseCve(release, { render: false }) || {} : {};
  if (detail.error) {
    alert(`Could not export report: ${detail.error}`);
    return;
  }
  const base = reportFileBase(release);
  if (format === "html") {
    downloadTextFile(`${base}-release-report.html`, buildReleaseReportHtml(release, detail, cve), "text/html;charset=utf-8");
  } else {
    downloadTextFile(`${base}-release-report.md`, buildReleaseReportMarkdown(release, detail, cve), "text/markdown;charset=utf-8");
  }
}

function bindReportExports(root = el.detailsPanel) {
  root.querySelectorAll("[data-export-report]").forEach((button) => {
    button.addEventListener("click", (event) => {
      event.stopPropagation();
      const releaseId = button.dataset.releaseId || state.selectedId || "";
      const format = button.dataset.exportReport || "markdown";
      const previousText = button.textContent;
      button.disabled = true;
      button.textContent = format === "html" ? "Exporting HTML..." : "Exporting...";
      exportReleaseReport(releaseId, format).finally(() => {
        button.disabled = false;
        button.textContent = previousText;
      });
    });
  });
}


function bindCveExports(root = el.detailsPanel) {
  root.querySelectorAll("[data-export-cve]").forEach((button) => {
    button.addEventListener("click", (event) => {
      event.stopPropagation();
      const releaseId = button.dataset.releaseId || state.selectedId || "";
      const format = button.dataset.exportCve || "csv";
      const previousText = button.textContent;
      button.disabled = true;
      button.textContent = format === "json" ? "Exporting JSON..." : "Exporting CSV...";
      exportFullCve(releaseId, format).finally(() => {
        button.disabled = false;
        button.textContent = previousText;
      });
    });
  });
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
  if (state.tab === "review" && !isReleaseTag(release)) state.tab = "summary";
  ensureTabData(release);
  ensureReviewData(release);
  if (state.tab === "review") ensureReviewAuditData(release);
  const cve = state.cveDetails.get(release.id) || {};
  const packages = state.packageDetails.get(release.id) || {};
  const summary = release.cve_summary || {};
  const azureUrl = azureBuildUrl(release, detail);
  const sbom = detail.sbom || release.sbom || {};
  const sbomBundlePath = sbom.bundle?.path || "";
  const cyclonedxPath = sbom.cyclonedx?.path || "";

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
          ${reviewBadge(release)}
          ${cyclonedxPath ? `<a class="link-button subtle" href="data/${escapeHtml(cyclonedxPath)}" download>CycloneDX</a>` : ""}
          ${sbomBundlePath ? `<a class="link-button subtle" href="data/${escapeHtml(sbomBundlePath)}" download>SPDX</a>` : ""}
          ${isReleaseTag(release) ? `<button class="link-button" type="button" data-export-report="markdown" data-release-id="${escapeHtml(release.id)}">Export report</button><button class="link-button subtle" type="button" data-export-report="html" data-release-id="${escapeHtml(release.id)}">HTML</button><button class="link-button subtle" type="button" data-export-cve="csv" data-release-id="${escapeHtml(release.id)}">CVE CSV</button><button class="link-button subtle" type="button" data-export-cve="json" data-release-id="${escapeHtml(release.id)}">CVE JSON</button>` : ""}
          ${azureUrl ? `<a class="link-button" href="${escapeHtml(azureUrl)}" target="_blank" rel="noreferrer">Azure</a>` : ""}
        </div>
      </div>
      <div class="detail-grid">
        <div class="metric"><span>Channel</span><strong>${escapeHtml(release.channel || "")}</strong></div>
        <div class="metric"><span>Machine</span><strong>${escapeHtml(release.machine || "")}</strong></div>
        <div class="metric"><span>Artifacts</span><strong>${Number(release.artifact_count || detail.artifacts?.length || 0)}</strong></div>
        <div class="metric"><span>Packages</span><strong>${Number(release.package_manifest?.package_count || packages.package_count || 0)}</strong></div>
        <div class="metric"><span>SBOM docs</span><strong>${Number(sbom.document_count || 0)}</strong></div>
        <div class="metric"><span>Unpatched CVEs</span><strong>${Number(summary.unpatched || 0)}</strong></div>
      </div>
      ${renderTabs(release)}
      <div id="tabContent">${renderTabContent(release, detail, cve, packages)}</div>
    </div>
  `;
  el.detailsPanel.querySelectorAll(".tab-button").forEach((button) => {
    button.addEventListener("click", () => {
      state.tab = button.dataset.tab;
      renderDetails();
    });
  });
  el.detailsPanel.querySelectorAll("[data-toggle-security-expand]").forEach((button) => {
    button.addEventListener("click", () => {
      state.securityExpanded = !state.securityExpanded;
      if (release.cve_summary_path && !state.cveDetails.has(release.id)) {
        loadReleaseCve(release);
      } else {
        renderDetails();
      }
    });
  });
  el.detailsPanel.querySelectorAll("[data-cve-bd-severity]").forEach((button) => {
    button.addEventListener("click", () => {
      state.cveRowSeverity = button.dataset.cveBdSeverity;
      renderDetails();
    });
  });
  el.detailsPanel.querySelectorAll("[data-cve-bd-status]").forEach((button) => {
    button.addEventListener("click", () => {
      state.cveRowStatus = button.dataset.cveBdStatus;
      renderDetails();
    });
  });
  el.detailsPanel.querySelectorAll("[data-cve-bd-search]").forEach((input) => {
    input.addEventListener("change", () => {
      state.cveRowQuery = input.value || "";
      renderDetails();
    });
  });
  bindCveControls();
  bindPackageControls();
  bindReportExports();
  bindCveExports();
  bindReviewControls(release);
  bindBuildLinks();
}

function renderTabs(release) {
  const tabs = [
    ["summary", "Summary"],
    ["security", "Security"],
    ["artifacts", "Artifacts"],
    ["packages", "Packages"],
    ["sbom", "SBOM"],
    ["layers", "Layers"],
    ...(isReleaseTag(release) ? [["review", "Review"]] : []),
    ["metadata", "Metadata"],
  ];
  return `<div class="tabs">${tabs.map(([id, label]) => (
    `<button class="tab-button ${state.tab === id ? "active" : ""}" data-tab="${id}">${label}</button>`
  )).join("")}</div>`;
}

function renderTabContent(release, detail, cve, packages) {
  if (detail.error) return renderLoadError("Could not load release.json", detail);
  if (state.tab === "summary") return renderSummary(release, detail, cve);
  if (state.tab === "security") return renderSecurity(release, detail, cve);
  if (state.tab === "artifacts") return renderArtifacts(detail.artifacts || []);
  if (state.tab === "packages") {
    if (release.package_manifest_path && !state.packageDetails.has(release.id)) return renderLoadingNotice("Loading package manifest", "Package manifests load only when this tab is opened.", `data/${release.package_manifest_path}`);
    return renderPackages(packages, release);
  }
  if (state.tab === "cves") { state.tab = "security"; return renderSecurity(release, detail, cve); }
  if (state.tab === "sbom") return renderSbom(release, detail);
  if (state.tab === "layers") return renderLayers(detail.layers || [], release);
  if (state.tab === "review") return renderReleaseReview(release);
  if (release.cve_summary_path && !state.cveDetails.has(release.id)) return renderLoadingNotice("Loading CVE metadata", "Metadata includes CVE source report paths from cve-summary.json.", `data/${release.cve_summary_path}`);
  return renderMetadata(release, detail, cve);
}

function renderReleaseReview(release) {
  if (!isReleaseTag(release)) return renderDataNotice("info", "Review applies to release tags", "Development builds do not have a release management checklist.");
  const review = releaseReview(release);
  const progress = reviewProgress(review);
  const updated = reviewTimestampLabel(review.lastReviewedAt || review.updatedAt);
  const sourceLabel = review.source === "database" ? "Saved in portal DB" : review.source === "local-fallback" ? "API unavailable, saved locally" : review.__loading ? "Loading portal review" : "Local draft";
  return `<form class="review-form" data-review-form="${escapeHtml(release.id)}">
    <div class="review-summary ${reviewStatusClass(review.status)}">
      <div>
        <span>Release decision</span>
        <strong>${escapeHtml(review.status)} · ${progress.done}/${progress.total} checks</strong>
      </div>
      <div class="item-meta">Last reviewed: ${escapeHtml(updated)}${review.updatedBy ? ` by ${escapeHtml(review.updatedBy)}` : ""}<br>${escapeHtml(sourceLabel)}</div>
    </div>
    ${review.apiError ? `<div class="data-notice warn"><div class="data-notice-title">Portal API fallback</div><p>${escapeHtml(review.apiError)}</p></div>` : ""}
    <div class="review-grid">
      <label class="field">
        <span>Status</span>
        <select data-review-field="status">
          ${["Draft", "Under review", "Blocked", "Approved", "Released"].map((status) => `<option value="${escapeHtml(status)}" ${review.status === status ? "selected" : ""}>${escapeHtml(status)}</option>`).join("")}
        </select>
      </label>
      <label class="field">
        <span>Owner</span>
        <input data-review-field="owner" type="text" value="${escapeHtml(review.owner)}" placeholder="release owner">
      </label>
      <label class="field">
        <span>Reviewer</span>
        <input data-review-field="actor" type="text" value="${escapeHtml(currentReviewer(review.updatedBy || review.actor || review.owner))}" placeholder="who is updating this review" required>
      </label>
      <label class="field">
        <span>Jira</span>
        <input data-review-field="jira" type="url" value="${escapeHtml(review.jira)}" placeholder="https://...">
      </label>
    </div>
    <div class="review-checklist">
      ${RELEASE_REVIEW_CHECKS.map(([key, label, help]) => {
        const meta = review.checkMeta?.[key] || {};
        const stamp = meta.checkedAt ? reviewTimestampLabel(meta.checkedAt) : "";
        const checkedBy = meta.checkedBy ? `Checked by ${escapeHtml(meta.checkedBy)}${stamp ? ` at ${escapeHtml(stamp)}` : ""}` : "Not checked";
        const optional = OPTIONAL_RELEASE_REVIEW_CHECKS.has(key);
        return `
        <label class="review-check">
          <input data-review-check="${escapeHtml(key)}" type="checkbox" ${review.checks[key] ? "checked" : ""}>
          <span>
            <strong>${escapeHtml(label)}${optional ? ' <span class="review-check-optional">optional</span>' : ""}</strong>
            <small>${escapeHtml(help)}</small>
            <small class="review-check-meta">${checkedBy}</small>
          </span>
        </label>`;
      }).join("")}
    </div>
    <label class="field review-note">
      <span>Decision note</span>
      <textarea data-review-field="note" rows="4" placeholder="Review notes, risk acceptance, pending actions">${escapeHtml(review.note)}</textarea>
    </label>
    ${renderReviewAudit(release)}
    <div class="review-actions">
      <button class="link-button" type="submit">Save decision</button>
      ${review.jira ? `<a class="link-button subtle" href="${escapeHtml(review.jira)}" target="_blank" rel="noreferrer">Open Jira</a>` : ""}
      <span class="item-meta">Release key: ${escapeHtml(reviewIdentity(release) || release.id)}</span>
    </div>
  </form>`;
}

function bindReviewControls(release) {
  const form = el.detailsPanel.querySelector("[data-review-form]");
  if (!form || !isReleaseTag(release)) return;
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const valueFor = (name) => form.querySelector(`[data-review-field="${name}"]`)?.value?.trim() || "";
    const actor = valueFor("actor");
    if (!actor) {
      alert("Reviewer name is required before saving a release decision.");
      form.querySelector('[data-review-field="actor"]')?.focus();
      return;
    }
    const button = form.querySelector('button[type="submit"]');
    const previousText = button?.textContent || "Save decision";
    if (button) {
      button.disabled = true;
      button.textContent = "Saving...";
    }
    const checks = {};
    form.querySelectorAll("[data-review-check]").forEach((input) => {
      checks[input.dataset.reviewCheck] = input.checked;
    });
    const saved = await saveReleaseReview(release, {
      status: valueFor("status") || "Draft",
      owner: valueFor("owner"),
      actor,
      jira: valueFor("jira"),
      note: valueFor("note"),
      checks,
    });
    if (!saved) {
      alert("Could not save the release review.");
      if (button) {
        button.disabled = false;
        button.textContent = previousText;
      }
      return;
    }
    resetReviewAudit(release);
    await loadReleaseAudit(release, { render: false });
    renderDetails();
  });
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
  const azureUrl = azureBuildUrl(release, detail);
  const id = buildId(release, detail);
  const published = detail.published_artifacts || release.published_artifacts || {};
  const smoke = smokeStatus(detail);
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
      <div class="item-title">Published artifacts</div>
      <div class="item-meta">Images: ${escapeHtml(published.images || "not recorded")}</div>
      <div class="item-meta">Metadata: ${escapeHtml(published.metadata || "not recorded")}</div>
      <div class="item-meta">Release metadata: ${escapeHtml(published.release_metadata || "not recorded")}</div>
    </div>
  </div>`;
}

function renderSecurity(release, detail, cve) {
  const summary = release.cve_summary || {};
  const severity = cve.counts_by_severity || release.cve_severity || {};
  const totalCves = Array.isArray(cve.issues) ? cve.issues.length : 0;
  const cveAvailable = Boolean(summary.available);
  const criticalCount = Number(severity.critical || 0);
  const highCount = Number(severity.high || 0);
  const hasCveWarning = cveAvailable && (Number(summary.unpatched || 0) > 0 || criticalCount > 0);
  const issues = Array.isArray(cve.issues) ? cve.issues : [];
  const expanded = state.securityExpanded && cveAvailable && issues.length;

  let detailsHtml = "";
  if (expanded) {
    detailsHtml = `
      ${renderSecurityOverviewPanel(issues, release)}
      ${renderCveBreakdown(issues, release)}
    `;
  } else if (cveAvailable && !issues.length) {
    detailsHtml = renderDataNotice("info", "CVE report is clean", "The CVE report is present and has no issues.");
  } else if (!cveAvailable) {
    detailsHtml = renderDataNotice("warn", "CVE report not available", "No CVE report was found for this build.");
  }

  return `<div class="list-block">
    <div class="security-analysis">
      <div class="security-head">
        <div class="security-title-row">
          <h3>Security Analysis</h3>
          ${cveAvailable
            ? (hasCveWarning
              ? `<span class="security-badge danger">Attention Required</span>`
              : `<span class="security-badge ok">No Issues</span>`)
            : `<span class="security-badge unknown">No Report</span>`}
        </div>
        ${hasCveWarning
          ? `<div class="security-warning">
              <p>This version has critical vulnerabilities. Review recommended.</p>
            </div>`
          : cveAvailable
            ? `<div class="security-clean"><p>No critical or unpatched vulnerabilities detected.</p></div>`
            : `<div class="security-warning warn"><p>CVE report is not available for this build.</p></div>`}
      </div>
      ${cveAvailable ? `<div class="security-cve-counts">
        <div class="cve-count-item total">
          <span class="cve-count-label">TOTAL CVES</span>
          <strong class="cve-count-value">${totalCves}</strong>
        </div>
        <div class="cve-count-item critical">
          <span class="cve-count-label">CRITICAL</span>
          <strong class="cve-count-value">${criticalCount}</strong>
        </div>
        <div class="cve-count-item high">
          <span class="cve-count-label">HIGH</span>
          <strong class="cve-count-value">${highCount}</strong>
        </div>
        <div class="security-cve-actions">
          <button class="link-button view-full-cve-btn" type="button" data-toggle-security-expand>${expanded ? "Hide Full CVE Analysis" : "View Full CVE Analysis"}</button>
          <button class="link-button subtle" type="button" data-export-cve="csv" data-release-id="${escapeHtml(release.id)}">Download CVE Report</button>
        </div>
      </div>` : ""}
    </div>
    <div class="package-meta-grid">
      <div class="package-meta-item">
        <span class="package-meta-label">Supported Component</span>
        <strong class="package-meta-value">${escapeHtml(release.machine || "—")}</strong>
      </div>
      <div class="package-meta-item">
        <span class="package-meta-label">Source</span>
        <strong class="package-meta-value">${escapeHtml(release.kas_manifest || release.channel || "—")}</strong>
      </div>
      <div class="package-meta-item">
        <span class="package-meta-label">Package Type</span>
        <strong class="package-meta-value">${escapeHtml(inferPackageType(release, detail))}</strong>
      </div>
      <div class="package-meta-item">
        <span class="package-meta-label">Hash</span>
        <strong class="package-meta-value mono">${escapeHtml(release.commit || "—")}</strong>
      </div>
    </div>
    ${detailsHtml}
  </div>`;
}

function renderSecurityOverviewPanel(issues, release) {
  const severity = countBySeverity(issues);
  const total = issues.length;
  const critical = Number(severity.critical || 0);
  const high = Number(severity.high || 0);
  const unpatchedCount = countUnpatchedIssues(issues);

  return `<div class="cve-overview">
    <div class="cve-overview-head">
      <h2>CVEs Overview</h2>
      <div class="cve-overview-actions">
        <span class="sbom-download-link" data-export-cve="csv" data-release-id="${escapeHtml(release.id)}">Download SBOM (CycloneDX+VEX)</span>
      </div>
    </div>
    <div class="cve-overview-body">
      ${renderCveDonutChart(issues)}
      <div class="cve-overview-counts">
        <div class="cve-ov-count total">
          <span class="cve-ov-label">Total</span>
          <strong class="cve-ov-value">${total}</strong>
        </div>
        <div class="cve-ov-count critical">
          <span class="cve-ov-label">Critical</span>
          <strong class="cve-ov-value">${critical}</strong>
        </div>
        <div class="cve-ov-count high">
          <span class="cve-ov-label">High</span>
          <strong class="cve-ov-value">${high}</strong>
        </div>
        <div class="cve-ov-count">
          <span class="cve-ov-label">Vulnerable</span>
          <strong class="cve-ov-value">${unpatchedCount}</strong>
        </div>
        <div class="cve-ov-count warning">
          <span class="cve-ov-label">Exploited</span>
          <strong class="cve-ov-value">0</strong>
        </div>
      </div>
    </div>
  </div>`;
}

function renderCveBreakdown(issues, release) {
  const severities = sortedSeverities(issues);
  const statuses = sortedStatuses(issues);
  const searchQuery = (state.cveRowQuery || "").trim().toLowerCase();

  const filtered = issues.filter((issue) => {
    if (state.cveRowSeverity !== "all" && normalizedSeverity(issue) !== state.cveRowSeverity) return false;
    if (state.cveRowStatus !== "all" && normalizedStatus(issue) !== state.cveRowStatus) return false;
    if (state.cveRowPackage !== "all" && issue.package !== state.cveRowPackage) return false;
    if (searchQuery && !issueSearchText(issue).includes(searchQuery)) return false;
    return true;
  });

  const sorted = [...filtered].sort((a, b) => (
    statusRank(a.status) - statusRank(b.status) ||
    severityRank(a.severity) - severityRank(b.severity) ||
    Number(b.scorev3 || 0) - Number(a.scorev3 || 0)
  ));
  const visible = sorted.slice(0, 100);
  const hidden = sorted.length - visible.length;

  return `<div class="torizon-cve-list">
    <table class="t-cve-table">
      <thead>
        <tr>
          <th style="width: 40px"></th>
          <th>CVE ID</th>
          <th>Component</th>
          <th>Severity ↓</th>
          <th>Score</th>
          <th>Analysis</th>
          <th>Justification</th>
        </tr>
      </thead>
      <tbody>
        ${visible.map((issue) => {
          const sev = escapeHtml(issue.severity || "Unknown");
          const score = escapeHtml(issue.scorev3 || "N/A");
          const component = `${escapeHtml(issue.package || "unknown")} (${escapeHtml(issue.version || "")})`;
          const analysisStr = escapeHtml(issue.status || "Awaiting Triage");
          
          return `
          <tr class="t-cve-row" data-cve-toggle-target="${escapeHtml(issue.id)}">
            <td class="t-cve-caret"><span class="caret-icon">›</span></td>
            <td class="t-cve-id">${escapeHtml(issue.id)}</td>
            <td>${component}</td>
            <td>${sev}</td>
            <td>${score}</td>
            <td class="t-cve-analysis"><span class="analysis-icon">⚠</span> ${analysisStr}</td>
            <td><span class="t-cve-justification">....................</span></td>
          </tr>
          <tr class="t-cve-details-row hidden" id="cve-details-${escapeHtml(issue.id)}">
            <td colspan="7">
              <div class="t-cve-details-content">
                <div class="t-cve-section">
                  <h4 class="t-cve-section-title">CVE Analysis ℹ️</h4>
                  <div class="t-cve-analysis-box">
                    <strong>Current Status:</strong><br>
                    <span class="analysis-icon">⚠</span> ${analysisStr}
                  </div>
                </div>
                
                <div class="t-cve-section">
                  <h4 class="t-cve-section-title">CVE Information ℹ️</h4>
                  <div class="t-cve-info-content">
                    <p><strong>Description:</strong><br>${escapeHtml(issue.summary || issue.description || "")}</p>
                    <p><strong>Severity:</strong><br>${sev} (CVSS Score: ${score})</p>
                    <p><strong>Affected Components:</strong><br><span class="t-code-badge">${component}</span></p>
                    
                    ${issue.link ? `<a href="${escapeHtml(issue.link)}" target="_blank" rel="noreferrer" class="t-cve-link">View full details on National Vulnerability Database ↗</a>` : ""}
                  </div>
                </div>
              </div>
            </td>
          </tr>
          `;
        }).join("") || `<tr><td colspan="7" class="t-cve-empty">No CVE rows match the current filters.</td></tr>`}
      </tbody>
    </table>
    ${hidden > 0 ? `<div class="cve-note">Showing the first ${visible.length} filtered rows. ${hidden} more hidden.</div>` : ""}
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

function sbomInfo(release = {}, detail = {}) {
  return detail.sbom || release.sbom || {};
}

function renderSbomDownload(label, path, className = "link-button") {
  if (!path) return "";
  return `<a class="${escapeHtml(className)}" href="data/${escapeHtml(path)}" download>${escapeHtml(label)}</a>`;
}

function renderSbom(release, detail = {}) {
  const sbom = sbomInfo(release, detail);
  if (!sbom.available) {
    return renderDataNotice("warn", "SBOM not imported", "No deploy-sbom SPDX documents were found in the metadata artifact for this build.", [
      release.sbom_manifest_path ? `Manifest: ${release.sbom_manifest_path}` : "",
    ]);
  }
  const documents = Array.isArray(sbom.documents) ? sbom.documents : [];
  const bundle = sbom.bundle || {};
  const cyclonedx = sbom.cyclonedx || {};
  const counts = Object.entries(sbom.counts || {})
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([kind, count]) => `${kind}: ${count}`)
    .join(" | ");
  return `<div class="list-block">
    <div class="item">
      <div class="item-head"><div class="item-title">CycloneDX image SBOM</div><span class="badge ok">${escapeHtml(cyclonedx.format || "CycloneDX JSON")}</span></div>
      <div class="item-meta">Components: ${Number(cyclonedx.component_count || 0)} | Size: ${escapeHtml(formatBytes(cyclonedx.size_bytes || 0))}</div>
      <div class="item-meta">Generated from the installed package manifest and linked to the source SPDX bundle.</div>
      <div class="item-actions">${renderSbomDownload("Download CycloneDX JSON", cyclonedx.path)}</div>
    </div>
    <div class="item">
      <div class="item-head"><div class="item-title">Complete SPDX bundle</div><span class="badge ok">${escapeHtml(sbom.format || "SPDX JSON")}</span></div>
      <div class="item-meta">Profile: ${escapeHtml(sbom.profile || "OpenEmbedded SPDX")}</div>
      <div class="item-meta">Documents: ${Number(sbom.document_count || bundle.document_count || 0)}${counts ? ` | ${escapeHtml(counts)}` : ""}</div>
      <div class="item-meta">Bundle: ${escapeHtml(bundle.format || "SPDX JSON documents in tar.gz")} ${bundle.size_bytes ? `(${escapeHtml(formatBytes(bundle.size_bytes))})` : ""}</div>
      <div class="item-actions">${renderSbomDownload("Download SPDX bundle", bundle.path)}</div>
    </div>
    <div class="item">
      <div class="item-title">Primary SPDX documents</div>
      <div class="item-meta">These are the image or SWUpdate recipe documents. Use the complete bundle when a tool needs all external SPDX document references.</div>
    </div>
    ${documents.length ? documents.map((doc) => `
      <div class="item">
        <div class="item-head"><div class="item-title">${escapeHtml(doc.label || doc.document_name || doc.source || "SPDX document")}</div><span class="badge unknown">${escapeHtml(doc.spdx_version || doc.format || "SPDX")}</span></div>
        <div class="item-meta mono">${escapeHtml(doc.source || "")}</div>
        <div class="item-meta">Packages: ${Number(doc.packages || 0)} | External refs: ${Number(doc.external_document_refs || 0)} | Relationships: ${Number(doc.relationships || 0)} | Size: ${escapeHtml(formatBytes(doc.size_bytes || 0))}</div>
        <div class="item-actions">${renderSbomDownload("Download SPDX JSON", doc.path, "link-button subtle")}</div>
      </div>
    `).join("") : `<div class="empty-state"><p>No primary SBOM documents were selected. Download the complete bundle.</p></div>`}
  </div>`;
}

function severityRank(severity) {
  return { critical: 0, high: 1, medium: 2, low: 3, none: 4, unknown: 5 }[String(severity || "unknown").toLowerCase()] ?? 5;
}

function truncateText(text, maxLen) {
  if (!text) return "";
  return text.length > maxLen ? text.slice(0, maxLen) + "…" : text;
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

  // Accordion toggle logic for CVE Torizon table
  el.detailsPanel.querySelectorAll("[data-cve-toggle-target]").forEach((row) => {
    row.addEventListener("click", () => {
      const detailsRow = row.nextElementSibling;
      if (detailsRow && detailsRow.classList.contains("t-cve-details-row")) {
        const isHidden = detailsRow.classList.contains("hidden");
        detailsRow.classList.toggle("hidden");
        // toggle caret
        const caret = row.querySelector(".caret-icon");
        if (caret) {
          caret.style.transform = isHidden ? "rotate(90deg)" : "rotate(0deg)";
        }
      }
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

function cveConcentricDonut(issues) {
  // Colors
  const severityColors = {
    critical: "#b42318", high: "#d66b08", medium: "#d6a008",
    low: "#4f7d95", none: "#94a3b8", unknown: "#cbd5e1",
  };
  const typeColors = { kernel: "#2563eb", other: "#7c3aed", unknown: "#cbd5e1" };

  // Inner ring: severity
  const severityCounts = {};
  let total = 0;
  for (const issue of issues) {
    const sev = normalizedSeverity(issue);
    severityCounts[sev] = (severityCounts[sev] || 0) + 1;
    total++;
  }
  const sevOrder = ["critical", "high", "medium", "low", "none", "unknown"];

  // Outer ring: type (kernel layer vs other)
  const typeCounts = {};
  for (const issue of issues) {
    const layer = (issue.layer || "").toLowerCase();
    const type = layer.includes("kernel") ? "kernel" : "other";
    typeCounts[type] = (typeCounts[type] || 0) + 1;
  }
  const typeOrder = ["kernel", "other"];

  if (!total) return "";

  const size = 200;
  const cx = size / 2;
  const cy = size / 2;
  const innerR = 50;
  const outerR = 72;
  const strokeInner = 18;
  const strokeOuter = 14;
  const circumferenceInner = 2 * Math.PI * innerR;
  const circumferenceOuter = 2 * Math.PI * outerR;

  function buildCircle(segments, circum, r, sw) {
    let offset = 0;
    return segments.map(({ key, value, color }) => {
      const len = (value / total) * circum;
      const seg = { color, offset, length: len, key, value };
      offset += len;
      return seg;
    }).map((seg) =>
      `<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="${seg.color}" stroke-width="${sw}"
        stroke-dasharray="${seg.length} ${circum - seg.length}"
        stroke-dashoffset="${-seg.offset}"
        transform="rotate(-90 ${cx} ${cy})"
        stroke-linecap="butt"/>`
    ).join("");
  }

  const innerData = sevOrder
    .filter((k) => (severityCounts[k] || 0) > 0)
    .map((k) => ({ key: k, value: severityCounts[k], color: severityColors[k] || severityColors.unknown }));
  const outerData = typeOrder
    .filter((k) => (typeCounts[k] || 0) > 0)
    .map((k) => ({ key: k, value: typeCounts[k], color: typeColors[k] || typeColors.unknown }));

  // Legend items combining both rings
  const legendItems = [
    ...innerData.map((d) => ({ label: d.key, count: d.value, color: d.color })),
    ...outerData.map((d) => ({ label: d.key === "kernel" ? "Kernel" : "Other", count: d.value, color: d.color })),
  ];

  // Text labels around the donut
  const labelRadius = outerR + 20;
  function labelPositions() {
    const items = [];
    let cumulative = 0;
    for (const d of innerData) {
      const startAngle = (cumulative / total) * 360 - 90;
      const midAngle = startAngle + ((d.value / total) * 360) / 2;
      const rad = (midAngle * Math.PI) / 180;
      items.push({
        label: d.key,
        x: cx + labelRadius * Math.cos(rad),
        y: cy + labelRadius * Math.sin(rad),
        color: d.color,
      });
      cumulative += d.value;
    }
    return items;
  }
  const labels = labelPositions();

  return `<div class="cve-donut-wrapper">
    <svg width="${size + 40}" height="${size + 40}" viewBox="0 0 ${size + 40} ${size + 40}" class="cve-donut-svg">
      <!-- Background circles -->
      <circle cx="${cx + 20}" cy="${cy + 20}" r="${innerR}" fill="none" stroke="#e8edf2" stroke-width="${strokeInner}"/>
      <circle cx="${cx + 20}" cy="${cy + 20}" r="${outerR}" fill="none" stroke="#e8edf2" stroke-width="${strokeOuter}"/>
      <!-- Inner ring segments -->
      ${buildCircle(innerData, circumferenceInner, innerR, strokeInner)}
      <!-- Outer ring segments -->
      ${buildCircle(outerData, circumferenceOuter, outerR, strokeOuter)}
      <!-- Center text -->
      <text x="${cx + 20}" y="${cy + 16}" text-anchor="middle" fill="var(--ink)" font-size="22" font-weight="800">${total}</text>
      <text x="${cx + 20}" y="${cy + 32}" text-anchor="middle" fill="var(--muted)" font-size="10" font-weight="650">Total</text>
      <!-- Labels around donut -->
      ${labels.map((l) => {
        const textAnchor = l.x > cx + 20 ? "start" : l.x < cx + 20 ? "end" : "middle";
        const dy = l.y > cy + 20 ? "12" : "-4";
        return `
          <text x="${l.x + 20}" y="${l.y + 22 + Number(dy)}" text-anchor="${textAnchor}" fill="${l.color}" font-size="10" font-weight="700" dy="${dy}">${escapeHtml(l.label)}</text>
          <circle cx="${l.x + 20 - 8}" cy="${l.y + 20 + 2}" r="3" fill="${l.color}"/>`;
      }).join("")}
    </svg>
    <div class="cve-donut-legend">
      <div class="cve-donut-legend-group"><span class="cve-donut-legend-title">Severity</span>
        ${innerData.map((d) =>
          `<span class="cve-donut-legend-item"><i style="background:${d.color}"></i>${escapeHtml(d.key)} (${d.value})</span>`
        ).join("")}
      </div>
      <div class="cve-donut-legend-group"><span class="cve-donut-legend-title">Type</span>
        ${outerData.map((d) =>
          `<span class="cve-donut-legend-item"><i style="background:${d.color}"></i>${escapeHtml(d.key === "kernel" ? "Kernel" : "Other")} (${d.value})</span>`
        ).join("")}
      </div>
    </div>
  </div>`;
}

function renderCveDonutChart(data) {
  // Accept either issues array or severity counts object (backward compat)
  if (Array.isArray(data)) return cveConcentricDonut(data);
  return ""; // old-style call with counts — no longer supported
}

function renderCveOverviewHeader(issues, release, cve) {
  const severity = countBySeverity(issues);
  const total = issues.length;
  const critical = Number(severity.critical || 0);
  const high = Number(severity.high || 0);
  const vulnerable = countAffectedPackages(issues);
  const exploited = 0; // not available in current data
  const unpatchedCount = countUnpatchedIssues(issues);

  return `<div class="cve-overview">
    <div class="cve-overview-head">
      <h2>CVEs Overview</h2>
      <div class="cve-overview-actions">
        <button class="link-button" type="button" data-export-cve="csv" data-release-id="${escapeHtml(release.id)}">Download CVE Report (CSV)</button>
        <button class="link-button subtle" type="button" data-export-cve="json" data-release-id="${escapeHtml(release.id)}">JSON</button>
      </div>
    </div>
    <div class="cve-overview-body">
      ${renderCveDonutChart(severity)}
      <div class="cve-overview-counts">
        <div class="cve-ov-count total">
          <span class="cve-ov-label">Total</span>
          <strong class="cve-ov-value">${total}</strong>
        </div>
        <div class="cve-ov-count critical">
          <span class="cve-ov-label">Critical</span>
          <strong class="cve-ov-value">${critical}</strong>
        </div>
        <div class="cve-ov-count high">
          <span class="cve-ov-label">High</span>
          <strong class="cve-ov-value">${high}</strong>
        </div>
        <div class="cve-ov-count">
          <span class="cve-ov-label">Vulnerable</span>
          <strong class="cve-ov-value">${unpatchedCount}</strong>
        </div>
        <div class="cve-ov-count warning">
          <span class="cve-ov-label">Exploited</span>
          <strong class="cve-ov-value">${exploited}</strong>
        </div>
      </div>
    </div>
  </div>`;
}

function renderCveDetails(issues, release, cve) {
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

  return `<div class="cve-view" id="cveDetailSection">
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

function renderCves(cve, release = {}) {
  if (!release.cve_summary_path) return renderDataNotice("warn", "Build has no CVE report path", "The dashboard index does not point to cve-summary.json for this build.");
  if (cve.__loading) return renderLoadingNotice("Loading CVE report", "Large CVE reports can take several seconds to download and parse. This tab will render automatically when loading completes.", cve.path);
  if (cve.error) return renderLoadError("Could not load cve-summary.json", cve);
  const issues = Array.isArray(cve.issues) ? cve.issues : [];
  if (!cve.available) return renderDataNotice("warn", "CVE report not imported", "No real CVE report was found in the metadata artifact for this build. Test-data reports are ignored.", [(cve.report_files || []).length ? `Report files: ${(cve.report_files || []).join(", ")}` : "No report files recorded"]);
  if (!issues.length) return renderDataNotice("info", "CVE report is clean", "The CVE report is present and has no issues.");

  return `<div class="cve-view">
    ${renderCveOverviewHeader(issues, release, cve)}
    <div class="cve-view-divider"></div>
    ${renderCveDetails(issues, release, cve)}
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

function cveSourceReportFiles(cve = {}) {
  return [
    ...(Array.isArray(cve.text_report_files) ? cve.text_report_files : []),
    ...(Array.isArray(cve.report_files) ? cve.report_files : []),
  ];
}

function renderMetadata(release, detail, cve) {
  const published = detail.published_artifacts || release.published_artifacts || {};
  const metadataBase = release.release_json ? release.release_json.replace(/release\.json$/, "") : "";
  const sbomManifestPath = release.sbom_manifest_path || (detail.metadata?.sbom_manifest && metadataBase ? `${metadataBase}${detail.metadata.sbom_manifest}` : "");
  const cveReports = cveSourceReportFiles(cve);
  const visibleReports = cveReports.slice(0, 80);
  const moreReports = Math.max(0, cveReports.length - visibleReports.length);
  const cveReportBody = cve.__loading
    ? "Loading cve-summary.json..."
    : cve.error
      ? `Could not load cve-summary.json: ${cve.error}`
      : visibleReports.map(escapeHtml).join("<br>") || "No source report paths recorded in cve-summary.json";
  return `<div class="list-block">
    <div class="item"><div class="item-title">Published artifacts</div><div class="item-meta">Images: ${escapeHtml(published.images || "")}</div><div class="item-meta">Metadata: ${escapeHtml(published.metadata || "")}</div><div class="item-meta">Release metadata: ${escapeHtml(published.release_metadata || "")}</div><div class="item-meta">Azure build: ${escapeHtml(buildId(release, detail) || "")}</div></div>
    <div class="item"><div class="item-title">Local files</div><div class="item-meta mono">${escapeHtml(release.release_json || "")}</div><div class="item-meta mono">${escapeHtml(release.cve_summary_path || "")}</div><div class="item-meta mono">${escapeHtml(release.build_manifest || "")}</div><div class="item-meta mono">${escapeHtml(release.package_manifest_path || "")}</div><div class="item-meta mono">${escapeHtml(sbomManifestPath || "")}</div></div>
    <div class="item"><div class="item-title">CVE source reports</div><div class="item-meta">${cveReportBody}${moreReports ? `<br>${escapeHtml(`${moreReports} more source report paths not shown`)}` : ""}</div></div>
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
