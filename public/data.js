export function normalizeLoadError(error, path = "", fallbackKind = "load") {
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

export function storedLoadError(path, error, fallbackKind = "load") {
  const normalized = normalizeLoadError(error, path, fallbackKind);
  return {
    error: normalized.message,
    errorKind: normalized.kind,
    path: normalized.path,
    status: normalized.status,
    detail: normalized.detail,
  };
}

export function loadingState(path, label) {
  return { __loading: true, path, label };
}

export function loadErrorTitle(error) {
  const normalized = normalizeLoadError(error);
  if (normalized.kind === "missing" || normalized.kind === "missing-index") return "Data file not found";
  if (normalized.kind === "invalid-json") return "JSON could not be parsed";
  if (normalized.kind === "network") return "Data request failed";
  if (normalized.kind === "empty-index") return "No builds indexed";
  return "Data could not be loaded";
}

export function loadErrorMessage(error) {
  const normalized = normalizeLoadError(error);
  if (normalized.kind === "missing-index") return "No dashboard index file is available. Check that the dashboard indexer has generated releases/index.json, development/index.json, or the legacy releases-index.json.";
  if (normalized.kind === "missing") return "The expected data file is missing from the dashboard data directory.";
  if (normalized.kind === "invalid-json") return "The file was found, but its contents are not valid JSON. Regenerate the dashboard index or the affected metadata artifact.";
  if (normalized.kind === "network") return "The browser could not complete the request for this data file.";
  if (normalized.kind === "empty-index") return "The dashboard index loaded successfully, but it contains zero builds.";
  return normalized.message || "The dashboard could not load this data.";
}

export async function fetchJson(path) {
  let response;
  try {
    const separator = path.includes("?") ? "&" : "?";
    response = await fetch(`${path}${separator}ts=${Date.now()}`, { cache: "no-store" });
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
