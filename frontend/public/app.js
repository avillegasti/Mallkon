import {
  OPTIONAL_RELEASE_REVIEW_CHECKS,
  RELEASE_REVIEW_CHECKS,
  REQUIRED_RELEASE_LAYER_NAMES,
  REVIEW_ACTOR_STORAGE_KEY,
  REVIEW_STORAGE_KEY,
  KEYCLOAK_ISSUER,
  KEYCLOAK_CLIENT_ID,
  KEYCLOAK_REDIRECT_URI,
  KEYCLOAK_SCOPE,
  AUTH_STORAGE_KEY,
  OAUTH_STATE_KEY,
  PKCE_VERIFIER_KEY,
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

function randomString(length = 32) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function base64UrlEncode(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function sha256_fallback(ascii) {
  function rightRotate(value, amount) {
    return (value >>> amount) | (value << (32 - amount));
  }
  const mathPow = Math.pow;
  const maxWord = mathPow(2, 32);
  const words = [];
  const asciiLength = ascii.length * 8;
  let hash = [];
  const k = [];
  let primeCounter = 0;

  const isPrime = (n) => {
    for (let factor = 2; factor * factor <= n; factor++) {
      if (n % factor === 0) return false;
    }
    return true;
  };

  let candidate = 2;
  while (primeCounter < 64) {
    if (isPrime(candidate)) {
      if (primeCounter < 8) {
        hash[primeCounter] = (mathPow(candidate, .5) * maxWord) | 0;
      }
      k[primeCounter] = (mathPow(candidate, 1 / 3) * maxWord) | 0;
      primeCounter++;
    }
    candidate++;
  }
  
  const bytes = [];
  for (let i = 0; i < ascii.length; i++) {
    bytes.push(ascii.charCodeAt(i));
  }
  
  bytes.push(0x80);
  while ((bytes.length % 64) !== 56) {
    bytes.push(0);
  }
  
  bytes.push(0, 0, 0, 0);
  bytes.push(
    (asciiLength >>> 24) & 0xff,
    (asciiLength >>> 16) & 0xff,
    (asciiLength >>> 8) & 0xff,
    asciiLength & 0xff
  );
  
  for (let i = 0; i < bytes.length; i += 4) {
    words.push((bytes[i] << 24) | (bytes[i + 1] << 16) | (bytes[i + 2] << 8) | bytes[i + 3]);
  }
  
  for (let i = 0; i < words.length; i += 16) {
    const w = words.slice(i, i + 16);
    let oldHash = hash.slice(0);
    
    for (let j = 0; j < 64; j++) {
      if (j >= 16) {
        const s0 = rightRotate(w[j - 15], 7) ^ rightRotate(w[j - 15], 18) ^ (w[j - 15] >>> 3);
        const s1 = rightRotate(w[j - 2], 17) ^ rightRotate(w[j - 2], 19) ^ (w[j - 2] >>> 10);
        w[j] = (w[j - 16] + s0 + w[j - 7] + s1) | 0;
      }
      
      const ch = (hash[4] & hash[5]) ^ (~hash[4] & hash[6]);
      const maj = (hash[0] & hash[1]) ^ (hash[0] & hash[2]) ^ (hash[1] & hash[2]);
      const S0 = rightRotate(hash[0], 2) ^ rightRotate(hash[0], 13) ^ rightRotate(hash[0], 22);
      const S1 = rightRotate(hash[4], 6) ^ rightRotate(hash[4], 11) ^ rightRotate(hash[4], 25);
      
      const temp1 = (hash[7] + S1 + ch + k[j] + w[j]) | 0;
      const temp2 = (S0 + maj) | 0;
      
      hash = [(temp1 + temp2) | 0].concat(hash);
      hash[4] = (hash[4] + temp1) | 0;
      hash.length = 8;
    }
    
    for (let j = 0; j < 8; j++) {
      hash[j] = (hash[j] + oldHash[j]) | 0;
    }
  }
  
  const buffer = new ArrayBuffer(32);
  const view = new DataView(buffer);
  for (let i = 0; i < 8; i++) {
    view.setInt32(i * 4, hash[i]);
  }
  return buffer;
}

async function sha256(value) {
  if (window.isSecureContext && window.crypto && window.crypto.subtle) {
    const data = new TextEncoder().encode(value);
    return crypto.subtle.digest("SHA-256", data);
  }
  return sha256_fallback(value);
}

async function buildPkceChallenge() {
  const verifier = randomString(64);
  const digest = await sha256(verifier);
  return { verifier, challenge: base64UrlEncode(digest) };
}

function decodeJwtPayload(token) {
  if (!token) return null;
  const parts = token.split(".");
  if (parts.length < 2) return null;
  try {
    const payload = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const decoded = atob(payload);
    return JSON.parse(decodeURIComponent(Array.from(decoded, (c) => `%${c.charCodeAt(0).toString(16).padStart(2, "0")}`).join("")));
  } catch (error) {
    return null;
  }
}

function loadAuthState() {
  try {
    const raw = window.localStorage.getItem(AUTH_STORAGE_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch (error) {
    return null;
  }
}

function saveAuthState(auth) {
  try {
    window.localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(auth));
  } catch (error) {
    // ignore local storage errors
  }
}

function clearAuthState() {
  try {
    window.localStorage.removeItem(AUTH_STORAGE_KEY);
  } catch (error) {
    // ignore local storage errors
  }
}

function isAuthExpired(auth) {
  return !auth || !auth.expiresAt || Date.now() >= Number(auth.expiresAt);
}

function currentUserName() {
  const auth = loadAuthState();
  const payload = decodeJwtPayload(auth?.idToken || auth?.accessToken);
  return payload?.preferred_username || payload?.email || payload?.sub || "";
}

function currentUserFullName() {
  const auth = loadAuthState();
  const payload = decodeJwtPayload(auth?.idToken || auth?.accessToken);
  return payload?.name || payload?.given_name || payload?.preferred_username || "User";
}

function currentUserEmail() {
  const auth = loadAuthState();
  const payload = decodeJwtPayload(auth?.idToken || auth?.accessToken);
  return payload?.email || "";
}


function currentUserSub() {
  const auth = loadAuthState();
  const payload = decodeJwtPayload(auth?.idToken || auth?.accessToken);
  return payload?.sub || "";
}


function currentUserRoles() {
  const auth = loadAuthState();
  const payload = decodeJwtPayload(auth?.accessToken);
  if (!payload) return [];
  const realmRoles = payload?.realm_access?.roles || [];
  const clientRoles = payload?.resource_access?.[KEYCLOAK_CLIENT_ID]?.roles || [];
  const groups = (payload?.groups || []).map(group => group.replace(/^\//, ""));
  const allRoles = [...new Set([...realmRoles, ...clientRoles, ...groups])];
  return allRoles.filter(role => !role.startsWith("default-roles") && role !== "offline_access" && role !== "uma_authorization");
}

async function loadUserProfile() {
  if (!el.infoJiraToken) return;
  try {
    const data = await fetchJson("/api/profile");
    if (data && data.jira_token !== undefined) {
      el.infoJiraToken.value = data.jira_token;
    }
  } catch (error) {
    console.error("Failed to load user profile:", error);
  }
  renderProjectSettings();
}

async function renderProjectSettings() {
  const roles = currentUserRoles();
  const isAdmin = roles.includes("admin");
  
  if (isAdmin) {
    if (el.globalAdminSection) el.globalAdminSection.style.display = "block";
  } else {
    if (el.globalAdminSection) el.globalAdminSection.style.display = "none";
  }

  const activeProj = state.projects.find(p => p.id === state.activeProjectId);
  if (!activeProj) {
    if (el.projectSettingsSection) el.projectSettingsSection.style.display = "none";
    return;
  }

  // Check project membership role
  let userProjectRole = null;
  let members = [];
  try {
    const membersData = await fetchJson(`/api/projects/${encodeURIComponent(state.activeProjectId)}/members`);
    members = Array.isArray(membersData.members) ? membersData.members : [];
    const self = members.find(m => m.user_sub === currentUserSub());
    userProjectRole = self ? self.role : null;
  } catch (err) {
    console.error("Could not fetch project members", err);
  }

  const isProjectAdmin = isAdmin || userProjectRole === "admin";
  if (isProjectAdmin || userProjectRole === "approver" || userProjectRole === "viewer") {
    if (el.projectSettingsSection) el.projectSettingsSection.style.display = "block";
    if (el.projectConfigId) el.projectConfigId.textContent = activeProj.id;
    if (el.projectConfigName) el.projectConfigName.textContent = activeProj.name;
    if (el.projectConfigArtifactPath) el.projectConfigArtifactPath.textContent = activeProj.artifact_path;

    // Render members
    if (el.projectMembersTableBody) {
      el.projectMembersTableBody.innerHTML = members.map(member => `
        <tr style="border-bottom: 1px solid #444c56; color: #adbac7;">
          <td style="padding: 8px 0;">${escapeHtml(member.user_sub)}</td>
          <td style="padding: 8px 0;"><span class="badge info" style="font-size: 11px; padding: 2px 8px; border-radius: 4px; background-color: #ddf4ff; color: #0969da; font-weight: 600; text-transform: uppercase;">${escapeHtml(member.role)}</span></td>
          <td style="padding: 8px 0; text-align: right;">
            ${isProjectAdmin ? `<button class="btn delete-member-btn" data-sub="${escapeHtml(member.user_sub)}" style="background-color: #cf222e; color: white; border: none; padding: 4px 8px; border-radius: 4px; font-size: 11px; cursor: pointer;">Remove</button>` : "-"}
          </td>
        </tr>
      `).join("");

      // Bind delete events
      el.projectMembersTableBody.querySelectorAll(".delete-member-btn").forEach(btn => {
        btn.addEventListener("click", async () => {
          const sub = btn.dataset.sub;
          if (confirm(`Are you sure you want to remove member ${sub}?`)) {
            try {
              await fetchJson(`/api/projects/${encodeURIComponent(state.activeProjectId)}/members/${encodeURIComponent(sub)}`, { method: "DELETE" });
              renderProjectSettings();
            } catch (err) {
              alert(`Error removing member: ${err.message || err}`);
            }
          }
        });
      });
    }
  } else {
    if (el.projectSettingsSection) el.projectSettingsSection.style.display = "none";
  }

  // Bind Add Member button once
  if (el.addMemberBtn) {
    const newBtn = el.addMemberBtn.cloneNode(true);
    el.addMemberBtn.parentNode.replaceChild(newBtn, el.addMemberBtn);
    el.addMemberBtn = newBtn;
    el.addMemberBtn.addEventListener("click", async () => {
      const sub = el.newMemberSub.value.trim();
      const role = el.newMemberRole.value;
      if (!sub) return alert("Please enter User Sub ID");
      try {
        await fetchJson(`/api/projects/${encodeURIComponent(state.activeProjectId)}/members`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ user_sub: sub, role })
        });
        el.newMemberSub.value = "";
        renderProjectSettings();
      } catch (err) {
        alert(`Error adding member: ${err.message || err}`);
      }
    });
  }

  // Bind Create Project button once
  if (el.createProjectBtn) {
    const newBtn = el.createProjectBtn.cloneNode(true);
    el.createProjectBtn.parentNode.replaceChild(newBtn, el.createProjectBtn);
    el.createProjectBtn = newBtn;
    el.createProjectBtn.addEventListener("click", async () => {
      const id = el.newProjectId.value.trim();
      const name = el.newProjectName.value.trim();
      const path = el.newProjectArtifactPath.value.trim();
      if (!id || !name || !path) return alert("All fields are required");
      el.createProjectStatus.textContent = "Creating...";
      el.createProjectStatus.style.color = "#adbac7";
      try {
        await fetchJson("/api/projects", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ id, name, artifact_path: path })
        });
        el.createProjectStatus.textContent = "Project created successfully!";
        el.createProjectStatus.style.color = "#2da44e";
        el.newProjectId.value = "";
        el.newProjectName.value = "";
        el.newProjectArtifactPath.value = "";
        await initializeProjects();
        renderProjectSettings();
      } catch (err) {
        el.createProjectStatus.textContent = `Error: ${err.message || err}`;
        el.createProjectStatus.style.color = "#cf222e";
      }
    });
  }
}

function updateAuthUi() {
  const auth = loadAuthState();
  const signedIn = auth && !isAuthExpired(auth);
  el.authButton.textContent = signedIn ? "Logout" : "Login";
  el.authStatus.textContent = signedIn ? `Signed in as ${currentUserName() || "user"}` : "Not signed in";
  el.authButton.title = signedIn ? "Sign out of the dashboard" : "Sign in with Keycloak";

  const profileEl = document.querySelector(".user-profile");
  if (profileEl) {
    if (signedIn) {
      profileEl.style.display = "flex";
      const name = currentUserFullName();
      const email = currentUserEmail();
      const roles = currentUserRoles();
      const nameEl = profileEl.querySelector(".user-name");
      if (nameEl) nameEl.textContent = name;
      
      const avatarEl = profileEl.querySelector(".avatar");
      if (avatarEl) {
        const initials = name
          .split(/[-_.\s]+/)
          .filter(Boolean)
          .map(part => part[0].toUpperCase())
          .join("")
          .slice(0, 2) || "U";
        avatarEl.textContent = initials;
      }
      
      const repoEl = profileEl.querySelector(".user-repo");
      if (repoEl) {
        repoEl.textContent = roles.length ? `Role: ${roles[0]}` : "Authenticated via Keycloak";
      }

      // Update dropdown contents
      if (el.dropdownName) el.dropdownName.textContent = name;
      if (el.dropdownEmail) el.dropdownEmail.textContent = email;
      if (el.dropdownRole) {
        el.dropdownRole.textContent = roles.length ? `Roles: ${roles.join(", ")}` : "Role: user";
      }

      // Update Settings / Information View panel
      if (el.infoFullName) el.infoFullName.textContent = name;
      if (el.infoUsername) el.infoUsername.textContent = currentUserName();
      if (el.infoEmail) el.infoEmail.textContent = email || "No email available";
      if (el.infoRoles) {
        el.infoRoles.innerHTML = roles.length
          ? roles.map(role => `<span class="badge info" style="font-size: 11px; padding: 2px 8px; border-radius: 4px; background-color: #ddf4ff; color: #0969da; font-weight: 600; text-transform: uppercase;">${role}</span>`).join(" ")
          : `<span class="badge info" style="font-size: 11px; padding: 2px 8px; border-radius: 4px; background-color: #ddf4ff; color: #0969da; font-weight: 600; text-transform: uppercase;">user</span>`;
      }
      if (el.infoIssuer) el.infoIssuer.textContent = KEYCLOAK_ISSUER;
      if (el.infoClientId) el.infoClientId.textContent = KEYCLOAK_CLIENT_ID;
      if (el.infoExpiry) {
        el.infoExpiry.textContent = auth.expiresAt ? new Date(auth.expiresAt).toLocaleString() : "N/A";
      }
      loadUserProfile();
    } else {
      profileEl.style.display = "none";
    }
  }
}

async function exchangeCodeForToken(code, verifier) {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: KEYCLOAK_CLIENT_ID,
    code,
    redirect_uri: KEYCLOAK_REDIRECT_URI,
    code_verifier: verifier,
  });
  const response = await fetch(`${KEYCLOAK_ISSUER}/protocol/openid-connect/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  });
  if (!response.ok) {
    throw new Error(`Keycloak token exchange failed: ${response.status} ${response.statusText}`);
  }
  const data = await response.json();
  if (!data.access_token) {
    throw new Error("Keycloak token exchange did not return an access token.");
  }
  const auth = {
    accessToken: data.access_token,
    refreshToken: data.refresh_token,
    idToken: data.id_token,
    expiresAt: Date.now() + Number(data.expires_in || 0) * 1000,
  };
  saveAuthState(auth);
  return auth;
}

function getQueryParams() {
  return new URLSearchParams(window.location.search);
}

async function processAuthRedirect() {
  const params = getQueryParams();
  const code = params.get("code");
  const state = params.get("state");
  const error = params.get("error");
  if (error) {
    console.warn("Keycloak login error:", params.get("error_description") || error);
    window.history.replaceState({}, "", window.location.pathname);
    return;
  }
  if (!code || !state) return;

  const savedState = window.localStorage.getItem(OAUTH_STATE_KEY);
  const savedVerifier = window.localStorage.getItem(PKCE_VERIFIER_KEY);
  if (!savedState || savedState !== state || !savedVerifier) {
    console.warn("Invalid Keycloak state or missing PKCE verifier.");
    window.history.replaceState({}, "", window.location.pathname);
    return;
  }

  try {
    await exchangeCodeForToken(code, savedVerifier);
    updateAuthUi();
  } catch (err) {
    console.error(err);
  } finally {
    window.localStorage.removeItem(OAUTH_STATE_KEY);
    window.localStorage.removeItem(PKCE_VERIFIER_KEY);
    window.history.replaceState({}, "", window.location.pathname);
  }
}

async function signIn() {
  const stateValue = randomString(22);
  const pkce = await buildPkceChallenge();
  window.localStorage.setItem(OAUTH_STATE_KEY, stateValue);
  window.localStorage.setItem(PKCE_VERIFIER_KEY, pkce.verifier);
  const authUrl = new URL(`${KEYCLOAK_ISSUER}/protocol/openid-connect/auth`);
  authUrl.searchParams.set("client_id", KEYCLOAK_CLIENT_ID);
  authUrl.searchParams.set("redirect_uri", KEYCLOAK_REDIRECT_URI);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("scope", KEYCLOAK_SCOPE);
  authUrl.searchParams.set("code_challenge", pkce.challenge);
  authUrl.searchParams.set("code_challenge_method", "S256");
  authUrl.searchParams.set("state", stateValue);
  window.location.href = authUrl.toString();
}

function signOut() {
  const auth = loadAuthState();
  const idToken = auth?.idToken;

  clearAuthState();
  updateAuthUi();

  const logoutUrl = new URL(`${KEYCLOAK_ISSUER}/protocol/openid-connect/logout`);
  if (idToken) {
    logoutUrl.searchParams.set("id_token_hint", idToken);
    logoutUrl.searchParams.set("post_logout_redirect_uri", KEYCLOAK_REDIRECT_URI);
  } else {
    logoutUrl.searchParams.set("client_id", KEYCLOAK_CLIENT_ID);
    logoutUrl.searchParams.set("post_logout_redirect_uri", KEYCLOAK_REDIRECT_URI);
  }

  window.location.href = logoutUrl.toString();
}

function bindAuthControls() {
  if (!el.authButton) return;
  el.authButton.addEventListener("click", () => {
    const auth = loadAuthState();
    if (auth && !isAuthExpired(auth)) {
      signOut();
    } else {
      signIn();
    }
  });

  const profileEl = document.querySelector(".user-profile");
  if (profileEl && el.profileDropdown) {
    profileEl.addEventListener("click", (e) => {
      if (e.target.closest(".profile-dropdown")) return;
      e.stopPropagation();
      const isHidden = el.profileDropdown.classList.contains("hidden");
      el.profileDropdown.classList.toggle("hidden", !isHidden);
    });

    document.addEventListener("click", () => {
      el.profileDropdown.classList.add("hidden");
    });
  }

  if (el.dropdownMyAccount) {
    el.dropdownMyAccount.addEventListener("click", (e) => {
      e.preventDefault();
      if (el.settingsMenu) {
        el.settingsMenu.open = true;
      }
      setActiveView("information");
    });
  }

  if (el.dropdownSignOut) {
    el.dropdownSignOut.addEventListener("click", (e) => {
      e.preventDefault();
      signOut();
    });
  }

  if (el.saveJiraTokenBtn) {
    el.saveJiraTokenBtn.addEventListener("click", async () => {
      const tokenVal = el.infoJiraToken.value.trim();
      el.saveJiraTokenBtn.disabled = true;
      el.jiraTokenStatus.textContent = "Saving...";
      el.jiraTokenStatus.style.color = "#adbac7";
      try {
        await fetchJson("/api/profile", {
          method: "PUT",
          headers: {
            "Content-Type": "application/json"
          },
          body: JSON.stringify({ jira_token: tokenVal })
        });
        el.jiraTokenStatus.textContent = "Token saved successfully!";
        el.jiraTokenStatus.style.color = "#2da44e";
        setTimeout(() => {
          el.jiraTokenStatus.textContent = "";
        }, 3000);
      } catch (error) {
        el.jiraTokenStatus.textContent = `Error: ${error.message || error}`;
        el.jiraTokenStatus.style.color = "#dc2626";
      } finally {
        el.saveJiraTokenBtn.disabled = false;
      }
    });
  }
}

function initializeAuth() {
  bindAuthControls();
  updateAuthUi();

  const params = getQueryParams();
  const hasCode = params.has("code") && params.has("state");
  const hasError = params.has("error");

  if (hasCode || hasError) {
    return processAuthRedirect();
  }

  const auth = loadAuthState();
  if (!auth || isAuthExpired(auth)) {
    document.body.style.display = "none";
    signIn();
    return new Promise(() => {}); // Block loadIndex from fetching any data
  }

  return Promise.resolve();
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
    let active = false;
    const view = button.dataset.view;
    if (view === "development") {
      active = (state.activeView === "releases" && state.activeChannel === "development");
    } else if (view === "releases") {
      active = (state.activeView === "releases" && state.activeChannel !== "development");
    } else {
      active = view === state.activeView;
    }
    button.classList.toggle("active", active);
    button.setAttribute("aria-selected", active ? "true" : "false");
  });
  el.overviewView?.classList.toggle("hidden", state.activeView !== "overview");
  el.overviewView?.classList.toggle("active", state.activeView === "overview");
  el.releasesView?.classList.toggle("hidden", state.activeView !== "releases");
  el.releasesView?.classList.toggle("active", state.activeView === "releases");
  el.attentionView?.classList.toggle("hidden", state.activeView !== "attention");
  el.attentionView?.classList.toggle("active", state.activeView === "attention");
  el.compareView?.classList.toggle("hidden", state.activeView !== "compare");
  el.compareView?.classList.toggle("active", state.activeView === "compare");
  el.lineageView?.classList.toggle("hidden", state.activeView !== "lineage");
  el.informationView?.classList.toggle("hidden", state.activeView !== "information");
  el.informationView?.classList.toggle("active", state.activeView === "information");
  if (el.channelTabsContainer) el.channelTabsContainer.style.display = "none";
  if (el.channelFilterContainer) el.channelFilterContainer.style.display = "none";
}

function setActiveView(view) {
  if (view === "development") {
    state.activeView = "releases";
    setActiveChannel("development");
  } else if (view === "releases") {
    state.activeView = "releases";
    if (state.activeChannel === "development") {
      setActiveChannel("release");
    }
  } else {
    state.activeView = ["overview", "releases", "attention", "compare", "lineage", "information"].includes(view) ? view : "overview";
  }
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
  syncViewTabs();
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
  const prefix = state.activeProjectId === "default" ? "data" : `data/projects/${state.activeProjectId}`;
  const paths = [`${prefix}/releases/index.json`, `${prefix}/development/index.json`];
  const settled = await Promise.allSettled(paths.map((path) => fetchJson(path)));
  const indexes = settled
    .filter((result) => result.status === "fulfilled")
    .map((result) => result.value);

  if (!indexes.length) {
    try {
      const legacy = await fetchJson(`${prefix}/releases-index.json`);
      return {
        generated_at_utc: legacy.generated_at_utc,
        releases: Array.isArray(legacy.releases) ? legacy.releases : [],
      };
    } catch (legacyError) {
      const normalized = normalizeLoadError(legacyError, `${prefix}/releases-index.json`);
      throw {
        kind: normalized.kind === "missing" ? "missing-index" : normalized.kind,
        path: `${prefix}/releases/index.json, ${prefix}/development/index.json, ${prefix}/releases-index.json`,
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
  const { latest, previous, sameIdentity } = releaseRegressionPair();
  const renderTo = (statusEl, alertsEl) => {
    if (!statusEl || !alertsEl) return;
    if (!latest) {
      statusEl.textContent = "No release tags";
      alertsEl.innerHTML = `<div class="empty-state"><p>No release/RC builds are available for regression checks.</p></div>`;
      return;
    }
    if (!previous) {
      statusEl.textContent = "Need two releases";
      alertsEl.innerHTML = `<div class="empty-state"><p>At least two release/RC builds are required for regression checks.</p></div>`;
      return;
    }

    const alerts = releaseRegressionAlerts(latest, previous);
    statusEl.textContent = `${releaseName(previous)} -> ${releaseName(latest)}${sameIdentity ? "" : " | fallback baseline"}`;
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
    alertsEl.innerHTML = summary + body;
    bindBuildLinks(alertsEl);
  };

  renderTo(el.regressionStatus, el.regressionAlerts);
  renderTo(el.regressionStatusDashboard, el.regressionAlertsDashboard);
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
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px;">
      <button class="link-button" type="button" data-export-compare="csv">Export compare CSV</button>
      <button class="link-button subtle" type="button" data-export-compare="json">Export compare JSON</button>
    </div>
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
  bindCompareExports(el.compareOutput);
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
      state.tab = "security";
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
      state.tab = "security";
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
    project_id: state.activeProjectId,
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
    const data = await fetchJson(`${reviewApiPath(release)}/audit?project_id=${encodeURIComponent(state.activeProjectId)}`);
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
    const data = await fetchJson(`${reviewApiPath(release)}?project_id=${encodeURIComponent(state.activeProjectId)}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
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

function compareFileBase(base, target) {
  return safeFileName([releaseLabel(base), releaseLabel(target), "compare"].filter(Boolean).join("-")) || "compare-export";
}

function buildCompareExportJson(base, target, baseDetail, targetDetail, baseCve, targetCve, basePackages, targetPackages) {
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

  return JSON.stringify({
    schema_version: 1,
    exported_at_utc: new Date().toISOString(),
    base: {
      id: base.id,
      tag: base.tag,
      artifact_label: base.artifact_label,
      machine: base.machine,
      kas_manifest: base.kas_manifest,
      commit: base.commit,
      generated: dateLabel(base),
    },
    target: {
      id: target.id,
      tag: target.tag,
      artifact_label: target.artifact_label,
      machine: target.machine,
      kas_manifest: target.kas_manifest,
      commit: target.commit,
      generated: dateLabel(target),
    },
    summary: {
      commit_changed: base.commit !== target.commit,
      manifest_changed: base.kas_manifest !== target.kas_manifest,
      machine_changed: base.machine !== target.machine,
      unpatched_delta: Number(target.cve_summary?.unpatched || 0) - Number(base.cve_summary?.unpatched || 0),
      base_package_count: packageCountFromData(base, basePackages),
      target_package_count: packageCountFromData(target, targetPackages),
      base_artifact_count: Number(baseDetail.artifacts?.length || base.artifact_count || 0),
      target_artifact_count: Number(targetDetail.artifacts?.length || target.artifact_count || 0),
      cve_added: cveDiff.added.length,
      cve_removed: cveDiff.removed.length,
      cve_changed: cveDiff.changed.length,
      package_added: packageDiff.added.length,
      package_removed: packageDiff.removed.length,
      package_changed: packageDiff.changed.length,
      artifact_added: artifactDiff.added.length,
      artifact_removed: artifactDiff.removed.length,
      artifact_changed: artifactDiff.changed.length,
      layer_changed: layerDiff.changed.length,
    },
    diffs: {
      artifacts: artifactDiff,
      layers: layerDiff,
      packages: packageDiff,
      cves: cveDiff,
    },
    base_cve: baseCve,
    target_cve: targetCve,
    base_packages: basePackages,
    target_packages: targetPackages,
  }, null, 2) + "\n";
}

function buildCompareExportCsv(base, target, baseDetail, targetDetail, baseCve, targetCve, basePackages, targetPackages) {
  const rows = [];
  const push = (type, category, key, baseValue, targetValue, detail = "") => {
    rows.push([type, category, key, String(baseValue || ""), String(targetValue || ""), String(detail || "")]);
  };

  push("metadata", "base", "id", base.id, "");
  push("metadata", "base", "tag", base.tag, "");
  push("metadata", "base", "machine", base.machine, "");
  push("metadata", "target", "id", target.id, "");
  push("metadata", "target", "tag", target.tag, "");
  push("metadata", "target", "machine", target.machine, "");
  push("summary", "commit_changed", "commit", base.commit, target.commit);
  push("summary", "manifest_changed", "manifest", base.kas_manifest, target.kas_manifest);
  push("summary", "machine_changed", "machine", base.machine, target.machine);
  push("summary", "unpatched_delta", "unpatched", Number(base.cve_summary?.unpatched || 0), Number(target.cve_summary?.unpatched || 0));
  push("summary", "package_count", "package_count", packageCountFromData(base, basePackages), packageCountFromData(target, targetPackages));
  push("summary", "artifact_count", "artifact_count", Number(baseDetail.artifacts?.length || base.artifact_count || 0), Number(targetDetail.artifacts?.length || target.artifact_count || 0));

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

  for (const artifact of artifactDiff.added) {
    push("artifact_added", "artifact", artifact.name, "", JSON.stringify(artifact));
  }
  for (const artifact of artifactDiff.removed) {
    push("artifact_removed", "artifact", artifact.name, JSON.stringify(artifact), "");
  }
  for (const entry of artifactDiff.changed) {
    push("artifact_changed", "artifact", entry.key, JSON.stringify(entry.base), JSON.stringify(entry.target));
  }
  for (const entry of layerDiff.changed) {
    push("layer_changed", "layer", entry.key, JSON.stringify(entry.base), JSON.stringify(entry.target));
  }
  for (const pkg of packageDiff.added) {
    push("package_added", "package", pkg.name, "", JSON.stringify(pkg));
  }
  for (const pkg of packageDiff.removed) {
    push("package_removed", "package", pkg.name, JSON.stringify(pkg), "");
  }
  for (const entry of packageDiff.changed) {
    push("package_changed", "package", entry.key, JSON.stringify(entry.base), JSON.stringify(entry.target));
  }
  for (const issue of cveDiff.added) {
    push("cve_added", "cve", cveLabel(issue), "", JSON.stringify(issue));
  }
  for (const issue of cveDiff.removed) {
    push("cve_removed", "cve", cveLabel(issue), JSON.stringify(issue), "");
  }
  for (const entry of cveDiff.changed) {
    push("cve_changed", "cve", cveLabel(entry.target), JSON.stringify(entry.base), JSON.stringify(entry.target));
  }

  const escapeCell = (value) => String(value || "").replace(/"/g, '""');
  const columns = ["type", "category", "key", "base", "target", "detail"];
  return [columns.join(","), ...rows.map((row) => row.map((cell) => `"${escapeCell(cell)}"`).join(","))].join("\n") + "\n";
}

async function exportCompare(baseId, targetId, format = "csv") {
  const base = releaseById(baseId);
  const target = releaseById(targetId);
  if (!base || !target) return;
  const [baseDetail, targetDetail] = await Promise.all([loadReleaseDetail(base, { render: false }), loadReleaseDetail(target, { render: false })]);
  const [baseCve, targetCve] = await Promise.all([loadReleaseCve(base, { render: false }), loadReleaseCve(target, { render: false })]);
  const [basePackages, targetPackages] = await Promise.all([loadReleasePackages(base, { render: false }), loadReleasePackages(target, { render: false })]);
  if (baseDetail?.error || targetDetail?.error || baseCve?.error || targetCve?.error || basePackages?.error || targetPackages?.error) {
    alert("Could not export comparison because one or more data files failed to load.");
    return;
  }
  const fileBase = compareFileBase(base, target);
  if (format === "json") {
    downloadTextFile(`${fileBase}-compare.json`, buildCompareExportJson(base, target, baseDetail, targetDetail, baseCve, targetCve, basePackages, targetPackages), "application/json;charset=utf-8");
  } else {
    downloadTextFile(`${fileBase}-compare.csv`, buildCompareExportCsv(base, target, baseDetail, targetDetail, baseCve, targetCve, basePackages, targetPackages), "text/csv;charset=utf-8");
  }
}

function bindCompareExports(root = el.compareOutput) {
  root.querySelectorAll("[data-export-compare]").forEach((button) => {
    button.addEventListener("click", (event) => {
      event.stopPropagation();
      const format = button.dataset.exportCompare || "csv";
      const prevText = button.textContent;
      button.disabled = true;
      button.textContent = format === "json" ? "Exporting JSON..." : "Exporting CSV...";
      const base = state.compareBaseId;
      const target = state.compareTargetId;
      exportCompare(base, target, format).finally(() => {
        button.disabled = false;
        button.textContent = prevText;
      });
    });
  });
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


function getSiblingVersions(release) {
  let siblings = state.releases.filter(r => 
    r.machine === release.machine && 
    (r.kas_manifest === release.kas_manifest || (!r.kas_manifest && !release.kas_manifest))
  );
  
  if (siblings.length <= 1) {
    siblings = state.releases.filter(r => 
      r.machine === release.machine && 
      r.channel === release.channel
    );
  }
  
  siblings.sort((a, b) => dateValue(a) - dateValue(b));
  
  const currentIndex = siblings.findIndex(r => r.id === release.id);
  const prev = currentIndex > 0 ? siblings[currentIndex - 1] : null;
  const next = currentIndex < siblings.length - 1 && currentIndex >= 0 ? siblings[currentIndex + 1] : null;
  
  return {
    prev,
    next,
    total: siblings.length
  };
}

function formatDetailDate(dateStr) {
  const parsed = Date.parse(dateStr);
  if (Number.isNaN(parsed)) return dateStr || "not recorded";
  const date = new Date(parsed);
  return date.toLocaleString('en-US', {
    month: '2-digit',
    day: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: true
  });
}

function renderDetails() {
  const scrollX = window.scrollX || window.pageXOffset;
  const scrollY = window.scrollY || window.pageYOffset;
  const activeElId = document.activeElement ? document.activeElement.id : null;
  let selectionStart = null;
  let selectionEnd = null;
  if (activeElId) {
    const activeEl = document.activeElement;
    if (activeEl.tagName === "INPUT" || activeEl.tagName === "TEXTAREA") {
      try {
        selectionStart = activeEl.selectionStart;
        selectionEnd = activeEl.selectionEnd;
      } catch (e) {
        // Ignored
      }
    }
  }

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
  if (state.tab === "review" && !isReleaseTag(release)) state.tab = "security";
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

  const manifestPath = (release.kas_manifest || release.id || "").replace(/\.yml$/, "");
  const versionString = release.tag || release.artifact_label || release.id || "";
  const formattedDate = formatDetailDate(new Date(dateValue(release)));
  const { prev, next, total } = getSiblingVersions(release);

  el.detailsPanel.innerHTML = `
    <div class="details-panel">
      <!-- Breadcrumbs / Top info -->
      <div style="font-size: 13px; color: #57606a; margin-bottom: 12px; display: flex; align-items: center; gap: 8px;">
        <span style="display: inline-flex; align-items: center; justify-content: center; background: #eef2f6; width: 24px; height: 24px; border-radius: 4px;">
          <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-settings" style="color: #57606a;"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg>
        </span>
        <span style="font-weight: 500;">Operating System</span>
        <span style="background: #e1f5fe; color: #0288d1; font-size: 11px; font-weight: 600; padding: 2px 8px; border-radius: 4px; text-transform: uppercase;">CVE Analysis</span>
      </div>

      <!-- Title & Main Info -->
      <div style="margin-bottom: 16px; display: flex; justify-content: space-between; align-items: flex-start; gap: 16px;">
        <div>
          <h1 style="font-size: 26px; font-weight: 700; margin: 0 0 8px 0; color: #111827; word-break: break-all; font-family: Inter, sans-serif;">${escapeHtml(manifestPath)}</h1>
          <h2 style="font-size: 18px; font-weight: 500; margin: 0 0 12px 0; color: #4b5563;">${escapeHtml(versionString)}</h2>
          
          <!-- Metadata row -->
          <div style="display: flex; gap: 20px; font-size: 13px; color: #6b7280; flex-wrap: wrap;">
            <div style="display: flex; align-items: center; gap: 6px;">
              <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-calendar"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"></rect><line x1="16" y1="2" x2="16" y2="6"></line><line x1="8" y1="2" x2="8" y2="6"></line><line x1="3" y1="10" x2="21" y2="10"></line></svg>
              <span>${escapeHtml(formattedDate)}</span>
            </div>
            <div style="display: flex; align-items: center; gap: 6px;">
              <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-monitor"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"></rect><line x1="8" y1="21" x2="16" y2="21"></line><line x1="12" y1="17" x2="12" y2="21"></line></svg>
              <span>Not installed on any device</span>
            </div>
          </div>
        </div>
        ${currentUserRoles().includes("admin")
          ? `<button type="button" class="delete-build-btn" data-build-id="${escapeHtml(release.id)}" style="background-color: #dc2626; color: white; border: none; padding: 8px 16px; border-radius: 6px; font-size: 13px; font-weight: 600; cursor: pointer; display: flex; align-items: center; gap: 6px; transition: background-color 0.2s;" onmouseover="this.style.backgroundColor='#b91c1c'" onmouseout="this.style.backgroundColor='#dc2626'">
              <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-trash-2"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path><line x1="10" y1="11" x2="10" y2="17"></line><line x1="14" y1="11" x2="14" y2="17"></line></svg>
              Delete Build
             </button>`
          : ""
        }
      </div>

      <!-- Version Navigation -->
      <div style="display: flex; justify-content: space-between; align-items: center; padding: 12px 16px; border-top: 1px solid #e5e7eb; border-bottom: 1px solid #e5e7eb; margin: 20px 0; font-size: 13px; font-weight: 500;">
        <div>
          ${prev 
            ? `<a href="#" class="prev-version-link" data-release-id="${escapeHtml(prev.id)}" style="color: #0288d1; text-decoration: none; display: flex; align-items: center; gap: 4px;">&larr; ${escapeHtml(prev.tag || prev.id)}</a>`
            : `<span style="color: #9ca3af; display: flex; align-items: center; gap: 4px;">&larr; None</span>`
          }
        </div>
        <div>
          <span style="color: #0288d1; font-weight: 600;">View All ${total} Versions</span>
        </div>
        <div>
          ${next 
            ? `<a href="#" class="next-version-link" data-release-id="${escapeHtml(next.id)}" style="color: #0288d1; text-decoration: none; display: flex; align-items: center; gap: 4px;">${escapeHtml(next.tag || next.id)} &rarr;</a>`
            : `<span style="color: #9ca3af; display: flex; align-items: center; gap: 4px;">None &rarr;</span>`
          }
        </div>
      </div>

      <!-- Header actions / Downloads -->
      <div style="display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 20px;">
        ${channelBadge(release.channel)}
        ${readinessBadge(release.flashing || flashingReadiness(detail))}
        ${cveBadge(summary)}
        ${reviewBadge(release)}
        ${cyclonedxPath ? `<a class="link-button subtle" href="data/${escapeHtml(cyclonedxPath)}" download>CycloneDX</a>` : ""}
        ${sbomBundlePath ? `<a class="link-button subtle" href="data/${escapeHtml(sbomBundlePath)}" download>SPDX</a>` : ""}
        ${isReleaseTag(release) ? `<button class="link-button" type="button" data-export-report="markdown" data-release-id="${escapeHtml(release.id)}">Export report</button><button class="link-button subtle" type="button" data-export-report="html" data-release-id="${escapeHtml(release.id)}">HTML</button><button class="link-button subtle" type="button" data-export-cve="csv" data-release-id="${escapeHtml(release.id)}">CVE CSV</button><button class="link-button subtle" type="button" data-export-cve="json" data-release-id="${escapeHtml(release.id)}">CVE JSON</button>` : ""}
        ${azureUrl ? `<a class="link-button" href="${escapeHtml(azureUrl)}" target="_blank" rel="noreferrer">Azure</a>` : ""}
      </div>

      ${renderTabs(release)}
      <div id="tabContent" style="margin-top: 20px;">${renderTabContent(release, detail, cve, packages)}</div>
    </div>
  `;
  el.detailsPanel.querySelectorAll(".tab-button").forEach((button) => {
    button.addEventListener("click", () => {
      state.tab = button.dataset.tab;
      renderDetails();
    });
  });
  el.detailsPanel.querySelectorAll(".prev-version-link, .next-version-link").forEach((link) => {
    link.addEventListener("click", (e) => {
      e.preventDefault();
      state.selectedId = link.dataset.releaseId;
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
      const val = button.dataset.cveBdStatus;
      if (val === "Unpatched" || val === "unpatched") state.cveRowAnalysis = "Awaiting Triage";
      else if (val === "Patched" || val === "patched") state.cveRowAnalysis = "Fixed";
      else if (val === "Ignored" || val === "ignored") state.cveRowAnalysis = "Not Affected";
      else state.cveRowAnalysis = val || "all";
      renderDetails();
    });
  });
  el.detailsPanel.querySelectorAll("[data-cve-bd-search]").forEach((input) => {
    input.addEventListener("change", () => {
      state.cveRowQuery = input.value || "";
      renderDetails();
    });
  });
  el.detailsPanel.querySelectorAll(".copy-btn").forEach((button) => {
    button.addEventListener("click", () => {
      const text = button.dataset.copyText;
      navigator.clipboard.writeText(text).then(() => {
        const originalHtml = button.innerHTML;
        button.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-check" style="color: #1a7f37;"><polyline points="20 6 9 17 4 12"></polyline></svg>`;
        setTimeout(() => {
          button.innerHTML = originalHtml;
        }, 1500);
      });
    });
  });
  el.detailsPanel.querySelectorAll(".delete-build-btn").forEach((button) => {
    button.addEventListener("click", async () => {
      const buildId = button.dataset.buildId;
      if (!confirm(`Are you sure you want to delete the build "${buildId}"? This will permanently remove the build metadata and the source archive files from the filesystem.`)) {
        return;
      }
      button.disabled = true;
      button.textContent = "Deleting...";
      
      try {
        await fetchJson(`/api/builds/${encodeURIComponent(buildId)}`, {
          method: "DELETE"
        });
        
        alert("Build successfully deleted.");
        state.details.delete(buildId);
        state.cveDetails.delete(buildId);
        state.packageDetails.delete(buildId);
        
        await loadIndex();
        
      } catch (err) {
        alert(`Failed to delete build: ${err.message || err}`);
        button.disabled = false;
        button.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-trash-2"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path><line x1="10" y1="11" x2="10" y2="17"></line><line x1="14" y1="11" x2="14" y2="17"></line></svg> Delete Build`;
      }
    });
  });

  bindCveControls();
  bindPackageControls();
  bindReportExports();
  bindCveExports();
  bindReviewControls(release);
  bindBuildLinks();

  // Restore focus and cursor position
  if (activeElId) {
    const activeEl = document.getElementById(activeElId);
    if (activeEl) {
      activeEl.focus({ preventScroll: true });
      if (selectionStart !== null && selectionEnd !== null && typeof activeEl.setSelectionRange === 'function') {
        activeEl.setSelectionRange(selectionStart, selectionEnd);
      }
    }
  }
  // Restore scroll position
  window.scrollTo(scrollX, scrollY);
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

function isReviewEditable() {
  const roles = currentUserRoles();
  return roles.includes("admin") || roles.includes("approver");
}

function renderReleaseReview(release) {
  if (!isReleaseTag(release)) return renderDataNotice("info", "Review applies to release tags", "Development builds do not have a release management checklist.");
  const review = releaseReview(release);
  const progress = reviewProgress(review);
  const updated = reviewTimestampLabel(review.lastReviewedAt || review.updatedAt);
  const sourceLabel = review.source === "database" ? "Saved in portal DB" : review.source === "local-fallback" ? "API unavailable, saved locally" : review.__loading ? "Loading portal review" : "Local draft";
  
  const editable = isReviewEditable();
  const disabledAttr = editable ? "" : "disabled";
  
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
        <select data-review-field="status" ${disabledAttr}>
          ${["Draft", "Under review", "Blocked", "Approved", "Released"].map((status) => `<option value="${escapeHtml(status)}" ${review.status === status ? "selected" : ""}>${escapeHtml(status)}</option>`).join("")}
        </select>
      </label>
      <label class="field">
        <span>Owner</span>
        <input data-review-field="owner" type="text" value="${escapeHtml(review.owner)}" placeholder="release owner" ${disabledAttr}>
      </label>
      <label class="field">
        <span>Reviewer</span>
        <input data-review-field="actor" type="text" value="${escapeHtml(currentReviewer(review.updatedBy || review.actor || review.owner))}" placeholder="who is updating this review" required ${disabledAttr}>
      </label>
      <label class="field">
        <span>Jira</span>
        <input data-review-field="jira" type="url" value="${escapeHtml(review.jira)}" placeholder="https://..." ${disabledAttr}>
      </label>
    </div>
    <div class="review-checklist">
      ${RELEASE_REVIEW_CHECKS.map(([key, label, help]) => {
        const meta = review.checkMeta?.[key] || {};
        const stamp = meta.checkedAt ? reviewTimestampLabel(meta.checkedAt) : "";
        const checkedBy = meta.checkedBy ? `Checked by ${escapeHtml(meta.checkedBy)}${stamp ? ` at ${escapeHtml(stamp)}` : ""}` : "Not checked";
        const optional = OPTIONAL_RELEASE_REVIEW_CHECKS.has(key);
        const inputHtml = editable
          ? `<input data-review-check="${escapeHtml(key)}" type="checkbox" ${review.checks[key] ? "checked" : ""}>`
          : (review.checks[key]
              ? `<div style="color: #15803d; font-weight: bold; font-size: 16px; width: 16px; height: 16px; margin-top: 1px; display: flex; align-items: center; justify-content: center; line-height: 1; user-select: none;">✓</div>`
              : `<div style="color: #64748b; font-weight: bold; font-size: 16px; width: 16px; height: 16px; margin-top: 1px; display: flex; align-items: center; justify-content: center; line-height: 1; user-select: none;">—</div>`
            );
        return `
        <label class="review-check" ${editable ? "" : 'style="cursor: default;"'}>
          ${inputHtml}
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
      <textarea data-review-field="note" rows="4" placeholder="Review notes, risk acceptance, pending actions" ${disabledAttr}>${escapeHtml(review.note)}</textarea>
    </label>
    ${renderReviewAudit(release)}
    <div class="review-actions">
      ${editable ? `<button class="link-button" type="submit">Save decision</button>` : ""}
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
  state.tab = "security";
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
      <div style="margin-top: 24px;">
        ${renderSecurityOverviewPanel(issues, release)}
        ${renderCveControls(issues)}
        ${renderCveBreakdown(issues, release)}
      </div>
    `;
  } else if (cveAvailable && !issues.length) {
    detailsHtml = renderDataNotice("info", "CVE report is clean", "The CVE report is present and has no issues.");
  } else if (!cveAvailable) {
    detailsHtml = renderDataNotice("warn", "CVE report not available", "No CVE report was found for this build.");
  }

  const sourceLabel = release.channel === "release" ? "NorthFi Release" : `NorthFi ${release.channel.toUpperCase()}`;
  const manifestPath = (release.kas_manifest || release.id || "").replace(/\.yml$/, "");
  const versionString = release.tag || release.artifact_label || release.id || "";
  const packageId = `${manifestPath}-${versionString}`;
  const hashVal = release.commit || "";

  return `<div class="list-block" style="display: flex; flex-direction: column; gap: 24px;">
    <!-- Security Analysis Card -->
    <div class="torizon-card" style="border: 1px solid #ffd013; border-radius: 8px; overflow: hidden; background: #fff;">
      <div class="card-header" style="padding: 16px 20px; border-bottom: 1px solid #f1f5f9; display: flex; justify-content: space-between; align-items: center; background: #fff;">
        <div style="display: flex; align-items: center; gap: 10px;">
          <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#fd7e14" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-alert-triangle"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
          <span style="font-size: 16px; font-weight: 700; color: #1f2937;">Security Analysis</span>
          <span style="background-color: #ffeef0; color: #cf222e; border: 1px solid #ffccd1; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; text-transform: uppercase;">Attention Required</span>
        </div>
        <div>
          <span style="background-color: #2da44e; color: #fff; font-size: 10px; padding: 2px 6px; border-radius: 4px; font-weight: 700; text-transform: uppercase;">NEW</span>
        </div>
      </div>
      <div class="card-body" style="padding: 20px;">
        <!-- Alert message banner -->
        <div style="background-color: #fff8c5; border: 1px solid rgba(225,188,19,0.2); border-radius: 6px; padding: 14px 16px; margin-bottom: 24px; font-size: 14px; color: #24292f; font-weight: 500; display: flex; align-items: center; gap: 8px;">
          <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#9a6700" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-info"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>
          <span>This version has critical vulnerabilities. Review recommended.</span>
        </div>

        <!-- CVE Counts and Action button -->
        ${cveAvailable ? `
        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 20px;">
          <div style="display: flex; gap: 32px;">
            <!-- Total CVEs -->
            <div style="display: flex; align-items: center; gap: 12px; border-left: 3px solid #2da44e; padding-left: 14px; min-width: 140px;">
              <svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#2da44e" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-shield"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
              <div>
                <div style="font-size: 26px; font-weight: 700; color: #24292f; line-height: 1.1;">${totalCves}</div>
                <div style="font-size: 10px; color: #57606a; font-weight: 600; letter-spacing: 0.5px; text-transform: uppercase;">TOTAL CVES</div>
              </div>
            </div>
            <!-- Critical -->
            <div style="display: flex; align-items: center; gap: 12px; border-left: 3px solid #cf222e; padding-left: 14px; min-width: 140px;">
              <svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#cf222e" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-alert-triangle"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
              <div>
                <div style="font-size: 26px; font-weight: 700; color: #cf222e; line-height: 1.1;">${criticalCount}</div>
                <div style="font-size: 10px; color: #57606a; font-weight: 600; letter-spacing: 0.5px; text-transform: uppercase;">CRITICAL</div>
              </div>
            </div>
            <!-- High -->
            <div style="display: flex; align-items: center; gap: 12px; border-left: 3px solid #fd7e14; padding-left: 14px; min-width: 140px;">
              <svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#fd7e14" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-alert-circle"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
              <div>
                <div style="font-size: 26px; font-weight: 700; color: #fd7e14; line-height: 1.1;">${highCount}</div>
                <div style="font-size: 10px; color: #57606a; font-weight: 600; letter-spacing: 0.5px; text-transform: uppercase;">HIGH</div>
              </div>
            </div>
          </div>
          <div>
            <button class="link-button view-full-cve-btn" type="button" data-toggle-security-expand style="display: flex; align-items: center; gap: 8px; padding: 8px 16px; border: 1px solid #0969da; border-radius: 6px; background-color: transparent; color: #0969da; font-weight: 600; cursor: pointer; font-size: 13px;">
              <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-activity"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline></svg>
              <span>${expanded ? "Hide Full CVE Analysis" : "View Full CVE Analysis"}</span>
            </button>
          </div>
        </div>` : ""}
      </div>
    </div>

    <!-- Additional Information Card -->
    <div class="torizon-card" style="border: 1px solid #d0d7de; border-radius: 8px; overflow: hidden; background: #fff;">
      <div class="card-header" style="padding: 16px 20px; border-bottom: 1px solid #f1f5f9; background: #fff;">
        <h3 style="font-size: 16px; font-weight: 700; margin: 0; color: #1f2937;">Additional Information</h3>
      </div>
      <div class="card-body" style="padding: 20px; display: flex; flex-direction: column; gap: 16px;">
        <div style="display: flex; flex-direction: column; gap: 4px;">
          <span style="font-size: 12px; color: #57606a; font-weight: 600;">Supported Component</span>
          <span style="font-size: 14px; font-weight: 600; color: #24292f;">${escapeHtml(release.machine || "—")}</span>
        </div>
        
        <div style="display: flex; flex-direction: column; gap: 4px;">
          <span style="font-size: 12px; color: #57606a; font-weight: 600;">Source</span>
          <div>
            <span style="background-color: #ddf4ff; color: #0969da; font-size: 11px; font-weight: 600; padding: 3px 8px; border-radius: 4px; display: inline-block;">${escapeHtml(sourceLabel)}</span>
          </div>
        </div>

        <div style="border-top: 1px solid #f1f5f9; margin-top: 8px; padding-top: 16px;">
          <h4 style="font-size: 13px; font-weight: 700; color: #57606a; text-transform: uppercase; margin: 0 0 16px 0; letter-spacing: 0.5px;">Technical Details</h4>
          
          <table style="width: 100%; border-collapse: collapse; font-size: 14px;">
            <tbody>
              <tr style="border-bottom: 1px solid #f1f5f9;">
                <td style="padding: 10px 0; color: #57606a; width: 140px;">Package Type</td>
                <td style="padding: 10px 0; font-weight: 600; color: #24292f;">${escapeHtml(inferPackageType(release, detail))}</td>
              </tr>
              <tr style="border-bottom: 1px solid #f1f5f9;">
                <td style="padding: 10px 0; color: #57606a;">Hash (SHA256)</td>
                <td style="padding: 10px 0; font-family: monospace; font-size: 13px; color: #24292f; display: flex; align-items: center; gap: 8px;">
                  <span>${escapeHtml(hashVal || "—")}</span>
                  ${hashVal ? `
                  <button class="copy-btn" data-copy-text="${escapeHtml(hashVal)}" title="Copy Hash" style="background: none; border: none; padding: 2px; cursor: pointer; color: #0969da; display: inline-flex; align-items: center; justify-content: center; width: 20px; height: 20px; border-radius: 4px;">
                    <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-copy"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                  </button>` : ""}
                </td>
              </tr>
              <tr>
                <td style="padding: 10px 0; color: #57606a;">Package ID</td>
                <td style="padding: 10px 0; font-family: monospace; font-size: 13px; color: #24292f; display: flex; align-items: center; gap: 8px;">
                  <span>${escapeHtml(packageId)}</span>
                  <button class="copy-btn" data-copy-text="${escapeHtml(packageId)}" title="Copy Package ID" style="background: none; border: none; padding: 2px; cursor: pointer; color: #0969da; display: inline-flex; align-items: center; justify-content: center; width: 20px; height: 20px; border-radius: 4px;">
                    <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-copy"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
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

  return `<div class="cve-overview" style="background: #fff; border: 1px solid #d0d7de; border-radius: 8px; padding: 24px; display: flex; gap: 48px; align-items: flex-start; justify-content: space-between; font-family: Inter, sans-serif;">
    <!-- Left stacked details column -->
    <div style="display: flex; flex-direction: column; gap: 16px; min-width: 200px; text-align: left;">
      <h3 style="font-size: 18px; font-weight: 700; color: #24292f; margin: 0 0 8px 0;">CVEs Overview</h3>
      
      <div style="display: flex; flex-direction: column; gap: 12px; font-size: 14px;">
        <div style="display: flex; align-items: center; gap: 8px; color: #57606a;">
          <span style="font-weight: 700; color: #24292f; font-size: 15px; width: 45px; display: inline-block; text-align: left;">${total}</span>
          <span>Total</span>
        </div>
        <div style="display: flex; align-items: center; gap: 8px; color: #57606a;">
          <span style="font-weight: 700; color: #cf222e; font-size: 15px; width: 45px; display: inline-block; text-align: left;">${critical}</span>
          <span>Critical</span>
        </div>
        <div style="display: flex; align-items: center; gap: 8px; color: #57606a;">
          <span style="font-weight: 700; color: #fd7e14; font-size: 15px; width: 45px; display: inline-block; text-align: left;">${high}</span>
          <span>High</span>
        </div>
        <div style="display: flex; align-items: center; gap: 8px; color: #57606a;">
          <span style="font-weight: 700; color: #24292f; font-size: 15px; width: 45px; display: inline-block; text-align: left;">${unpatchedCount}</span>
          <span>Vulnerable</span>
        </div>
        <div style="display: flex; align-items: center; gap: 8px; color: #57606a;">
          <span style="font-weight: 700; color: #24292f; font-size: 15px; width: 45px; display: inline-block; text-align: left;">0</span>
          <span>Exploited</span>
        </div>
      </div>
      
      <div style="border-top: 1px dashed #d0d7de; margin-top: 12px; padding-top: 16px;">
        <span class="sbom-download-link" data-export-cve="csv" data-release-id="${escapeHtml(release.id)}" style="color: #0969da; cursor: pointer; font-weight: 600; font-size: 14px; text-decoration: none; line-height: 1.4; display: inline-block;">
          Download SBOM<br>(CycloneDX+VEX)
        </span>
      </div>
    </div>

    <!-- Right sunburst chart column -->
    <div style="flex: 1; display: flex; justify-content: center; align-items: center;">
      ${renderCveDonutChart(issues)}
    </div>
  </div>`;
}

function getIssueVex(issue) {
  const pkg = String(issue.package || "").toLowerCase();
  const type = (pkg.startsWith("linux-") || pkg === "linux") ? "kernel" : "other";

  const severity = String(issue.severity || "none").toLowerCase();

  // Status mapping to VEX Analysis and Justification
  const status = String(issue.status || "").toLowerCase();
  const detail = String(issue.detail || "").toLowerCase();

  let analysis = "Awaiting Triage";
  let justification = "";

  if (status === "patched") {
    analysis = "Fixed";
  } else if (status === "unpatched") {
    analysis = "Awaiting Triage";
  } else if (status === "ignored") {
    if (detail === "disputed") {
      analysis = "False Positive";
    } else if (detail === "not-applicable-config") {
      analysis = "Not Affected";
      justification = "Requires configuration";
    } else if (detail === "not-applicable-platform") {
      analysis = "Not Affected";
      justification = "Requires environment";
    } else if (detail === "cpe-incorrect") {
      analysis = "Not Affected";
      justification = "Code not present";
    } else if (detail === "upstream-wontfix") {
      analysis = "Needs Analysis";
    } else {
      analysis = "Not Affected";
    }
  }

  // Determine justification based on detail value for other values
  if (detail.includes("code-not-present") || detail.includes("code_not_present") || detail === "code not present") {
    justification = "Code not present";
  } else if (detail.includes("code-not-reachable") || detail.includes("code_not_reachable") || detail === "code not reachable") {
    justification = "Code not reachable";
  } else if (detail.includes("requires-configuration") || detail.includes("requires_configuration") || detail === "requires configuration") {
    justification = "Requires configuration";
  } else if (detail.includes("requires-dependency") || detail.includes("requires_dependency") || detail === "requires dependency") {
    justification = "Requires dependency";
  } else if (detail.includes("requires-environment") || detail.includes("requires_environment") || detail === "requires environment") {
    justification = "Requires environment";
  } else if (detail.includes("protected-by-compiler") || detail.includes("protected_by_compiler") || detail === "protected by compiler") {
    justification = "Protected by compiler";
  } else if (detail.includes("protected-by-runtime") || detail.includes("protected_by_runtime") || detail === "protected by runtime") {
    justification = "Protected by runtime";
  } else if (detail.includes("protected-at-perimeter") || detail.includes("protected_at_perimeter") || detail === "protected at perimeter") {
    justification = "Protected at perimeter";
  } else if (detail.includes("protected-by-mitigating-control") || detail.includes("protected_by_mitigating_control") || detail === "protected by mitigating control") {
    justification = "Protected by mitigating control";
  }

  // Allow explicit VEX fields if present
  if (issue.analysis) {
    analysis = issue.analysis;
  }
  if (issue.justification) {
    justification = issue.justification;
  }

  return { type, severity, analysis, justification };
}

const typeOptions = [
  { value: "all", label: "All" },
  { value: "kernel", label: "Kernel" },
  { value: "other", label: "Other" }
];

const severityOptions = [
  { value: "all", label: "All" },
  { value: "critical", label: "Critical" },
  { value: "high", label: "High" },
  { value: "medium", label: "Medium" },
  { value: "low", label: "Low" },
  { value: "none", label: "None" }
];

const analysisOptions = [
  { value: "all", label: "All" },
  { value: "Fixed", label: "Fixed" },
  { value: "Vulnerable", label: "Vulnerable" },
  { value: "Exploited", label: "Exploited" },
  { value: "Needs Analysis", label: "Needs Analysis" },
  { value: "Mitigation Available", label: "Mitigation Available" },
  { value: "False Positive", label: "False Positive" },
  { value: "Not Affected", label: "Not Affected" },
  { value: "Awaiting Triage", label: "Awaiting Triage" }
];

const justificationOptions = [
  { value: "all", label: "All" },
  { value: "Code not present", label: "Code not present" },
  { value: "Code not reachable", label: "Code not reachable" },
  { value: "Requires configuration", label: "Requires configuration" },
  { value: "Requires dependency", label: "Requires dependency" },
  { value: "Requires environment", label: "Requires environment" },
  { value: "Protected by compiler", label: "Protected by compiler" },
  { value: "Protected by runtime", label: "Protected by runtime" },
  { value: "Protected at perimeter", label: "Protected at perimeter" },
  { value: "Protected by mitigating control", label: "Protected by mitigating control" }
];

function renderCveBreakdown(issues, release) {
  const searchQuery = (state.cveRowQuery || "").trim().toLowerCase();

  const filtered = issues.filter((issue) => {
    const vex = getIssueVex(issue);
    if (state.cveRowType !== "all" && vex.type !== state.cveRowType) return false;
    if (state.cveRowSeverity !== "all" && vex.severity !== state.cveRowSeverity) return false;
    if (state.cveRowAnalysis !== "all" && vex.analysis !== state.cveRowAnalysis) return false;
    if (state.cveRowJustification !== "all" && vex.justification !== state.cveRowJustification) return false;
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
          <th>Layer</th>
        </tr>
      </thead>
      <tbody>
        ${visible.map((issue) => {
          const vex = getIssueVex(issue);
          const sev = escapeHtml(issue.severity || "Unknown");
          const score = escapeHtml(issue.scorev3 || "N/A");
          const component = `${escapeHtml(issue.package || "unknown")} (${escapeHtml(issue.version || "")})`;
          const analysisStr = escapeHtml(vex.analysis || "Awaiting Triage");
          const justificationStr = escapeHtml(vex.justification || "—");
          const layerStr = escapeHtml(issue.layer || "unknown");
          const issueStatus = String(issue.status || "").toLowerCase();
          
          // Fix/patch status derived from available data
          let fixInfo = "";
          if (issueStatus === "patched") {
            fixInfo = `<p><strong>Fix Status:</strong><br><span style="color: #1a7f37; font-weight: 600;">✓ Fixed in this build</span><br>Package version includes the fix: <code>${escapeHtml(issue.version || "unknown")}</code></p>`;
          } else if (issueStatus === "unpatched") {
            fixInfo = `<p><strong>Fix Status:</strong><br><span style="color: #cf222e; font-weight: 600;">✗ Not yet fixed</span><br>No fix version available in this build. Current vulnerable version: <code>${escapeHtml(issue.version || "unknown")}</code></p>`;
          } else if (issueStatus === "ignored") {
            fixInfo = `<p><strong>Fix Status:</strong><br><span style="color: #57606a; font-weight: 600;">— Ignored</span><br>This CVE has been marked as ignored for this package.</p>`;
          }
          
          return `
          <tr class="t-cve-row" data-cve-toggle-target="${escapeHtml(issue.id)}">
            <td class="t-cve-caret"><span class="caret-icon">›</span></td>
            <td class="t-cve-id">${escapeHtml(issue.id)}</td>
            <td class="t-cve-component-cell"><span class="t-cve-component">${component}</span></td>
            <td><span class="sev-badge ${sev.toLowerCase()}">${sev}</span></td>
            <td><span class="score-badge score-${Math.floor(Number(issue.scorev3 || 0))}">${score}</span></td>
            <td><span class="analysis-badge status-${analysisStr.toLowerCase().replace(/\s+/g, '-')}">${analysisStr}</span></td>
            <td><span class="t-cve-justification">${justificationStr}</span></td>
            <td><span class="t-cve-layer">${layerStr}</span></td>
          </tr>
          <tr class="t-cve-details-row hidden" id="cve-details-${escapeHtml(issue.id)}">
            <td colspan="8">
              <div class="t-cve-details-content">
                <div class="t-cve-section">
                  <h4 class="t-cve-section-title">CVE Analysis ℹ️</h4>
                  <div class="t-cve-analysis-box">
                    <strong>Current Status:</strong><br>
                    <span class="analysis-icon">⚠</span> ${analysisStr}
                    ${justificationStr !== "—" ? `<br><br><strong>Justification:</strong><br>${justificationStr}` : ""}
                  </div>
                </div>
                
                <div class="t-cve-section">
                  <h4 class="t-cve-section-title">CVE Information ℹ️</h4>
                  <div class="t-cve-info-content">
                    <p><strong>Description:</strong><br>${escapeHtml(issue.summary || issue.description || "")}</p>
                    <p><strong>Severity:</strong><br>${sev} (CVSS Score: ${score})</p>
                    <p><strong>Affected Components:</strong><br><span class="t-code-badge">${component}</span></p>
                    <p><strong>Layer:</strong><br><span class="t-code-badge">${layerStr}</span></p>
                    ${fixInfo}
                    ${issue.link ? `<a href="${escapeHtml(issue.link)}" target="_blank" rel="noreferrer" class="t-cve-link">View full details on National Vulnerability Database ↗</a>` : ""}
                  </div>
                </div>
              </div>
            </td>
          </tr>
          `;
        }).join("") || `<tr><td colspan="8" class="t-cve-empty">No CVE rows match the current filters.</td></tr>`}
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
  const query = (state.cveRowQuery || "").trim().toLowerCase();
  return issues.filter((issue) => {
    const vex = getIssueVex(issue);
    if (state.cveRowType !== "all" && vex.type !== state.cveRowType) return false;
    if (state.cveRowSeverity !== "all" && vex.severity !== state.cveRowSeverity) return false;
    if (state.cveRowAnalysis !== "all" && vex.analysis !== state.cveRowAnalysis) return false;
    if (state.cveRowJustification !== "all" && vex.justification !== state.cveRowJustification) return false;
    if (state.cveRowPackage !== "all" && issue.package !== state.cveRowPackage) return false;
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
  const queryInput = document.getElementById("cveRowQuery");
  if (queryInput) {
    queryInput.addEventListener("input", () => {
      state.cveRowQuery = queryInput.value || "";
      renderDetails();
    });
  }

  // Bind filter links
  el.detailsPanel.querySelectorAll(".cve-filter-link").forEach((link) => {
    link.addEventListener("click", (e) => {
      e.preventDefault();
      const key = link.dataset.filterKey;
      const value = link.dataset.filterValue;
      state[key] = value;
      renderDetails();
    });
  });

  // Bind package dropdown
  const packageSelect = document.getElementById("cveRowPackage");
  if (packageSelect) {
    packageSelect.addEventListener("change", () => {
      state.cveRowPackage = packageSelect.value || "all";
      renderDetails();
    });
  }

  document.querySelector("[data-cve-filter-reset]")?.addEventListener("click", () => {
    state.cveRowType = "all";
    state.cveRowSeverity = "all";
    state.cveRowAnalysis = "all";
    state.cveRowJustification = "all";
    state.cveRowPackage = "all";
    state.cveRowQuery = "";
    renderDetails();
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

function renderFilterRow(label, key, options, issues) {
  const counts = {};
  let totalCount = issues.length;

  if (key === "cveRowJustification") {
    totalCount = issues.filter(issue => getIssueVex(issue).justification !== "").length;
  }

  issues.forEach((issue) => {
    const vex = getIssueVex(issue);
    let val = "";
    if (key === "cveRowType") val = vex.type;
    else if (key === "cveRowSeverity") val = vex.severity;
    else if (key === "cveRowAnalysis") val = vex.analysis;
    else if (key === "cveRowJustification") val = vex.justification;

    if (val) {
      counts[val] = (counts[val] || 0) + 1;
    }
  });

  const activeValue = state[key] || "all";

  const linksHtml = options.map((opt) => {
    let count = 0;
    if (opt.value === "all") {
      count = totalCount;
    } else {
      count = counts[opt.value] || 0;
    }

    const isActive = activeValue === opt.value;
    if (isActive) {
      return `<span style="font-weight: 700; color: #1f2937; margin-right: 14px; cursor: default;">${escapeHtml(opt.label)} (${count})</span>`;
    } else {
      return `<a href="#" class="cve-filter-link" data-filter-key="${key}" data-filter-value="${escapeHtml(opt.value)}" style="color: #0969da; text-decoration: none; margin-right: 14px;">${escapeHtml(opt.label)} (${count})</a>`;
    }
  }).join("");

  return `<div style="display: flex; align-items: flex-start; gap: 8px; font-size: 13px; line-height: 1.5; margin-bottom: 8px;">
    <span style="font-weight: 600; color: #57606a; min-width: 90px; text-align: right; margin-right: 8px;">${escapeHtml(label)}:</span>
    <div style="display: flex; flex-wrap: wrap; gap: 4px;">
      ${linksHtml}
    </div>
  </div>`;
}

function renderCveControls(issues) {
  const packages = sortedPackages(issues);
  return `<div class="cve-breakdown-panel" style="margin-bottom: 24px;">
    <h3 style="font-size: 18px; font-weight: 700; color: #24292f; margin: 0 0 16px 0;">CVE Breakdown</h3>
    
    <div style="display: flex; gap: 16px; align-items: center; margin-bottom: 16px; flex-wrap: wrap;">
      <div style="position: relative; width: 260px;">
        <input id="cveRowQuery" type="text" value="${escapeHtml(state.cveRowQuery || "")}" placeholder="Search" style="width: 100%; padding: 8px 12px 8px 36px; border: 1px solid #d0d7de; border-radius: 6px; font-size: 14px; background: #fff;">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#57606a" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="position: absolute; left: 12px; top: 50%; transform: translateY(-50%); pointer-events: none;"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
      </div>
      
      <div style="display: flex; align-items: center; gap: 8px; font-size: 14px; color: #24292f;">
        <span style="font-weight: 600;">Package:</span>
        <select id="cveRowPackage" style="padding: 7px 12px; border: 1px solid #d0d7de; border-radius: 6px; font-size: 14px; background: #fff; min-width: 180px; max-width: 280px; cursor: pointer;">
          <option value="all">All packages</option>
          ${packages.map((pkg) => `<option value="${escapeHtml(pkg)}" ${pkg === state.cveRowPackage ? "selected" : ""}>${escapeHtml(pkg)}</option>`).join("")}
        </select>
      </div>
    </div>

    <div style="margin-bottom: 12px; font-size: 12px; color: #57606a; font-weight: 600;">Filter by:</div>
    <div style="display: flex; flex-direction: column; gap: 4px;">
      ${renderFilterRow("Type", "cveRowType", typeOptions, issues)}
      ${renderFilterRow("Severity", "cveRowSeverity", severityOptions, issues)}
      ${renderFilterRow("Analysis", "cveRowAnalysis", analysisOptions, issues)}
      ${renderFilterRow("Justification", "cveRowJustification", justificationOptions, issues)}
    </div>
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

function getArcPath(cx, cy, r1, r2, startAngle, endAngle) {
  // SVG arcs use degrees, convert to radians.
  // Subtract 90 degrees to start at 12 o'clock.
  const startRad1 = (startAngle - 90) * Math.PI / 180;
  const endRad1 = (endAngle - 90) * Math.PI / 180;
  
  const x1_inner = cx + r1 * Math.cos(startRad1);
  const y1_inner = cy + r1 * Math.sin(startRad1);
  const x2_inner = cx + r1 * Math.cos(endRad1);
  const y2_inner = cy + r1 * Math.sin(endRad1);
  
  const x1_outer = cx + r2 * Math.cos(startRad1);
  const y1_outer = cy + r2 * Math.sin(startRad1);
  const x2_outer = cx + r2 * Math.cos(endRad1);
  const y2_outer = cy + r2 * Math.sin(endRad1);
  
  const largeArcFlag = (endAngle - startAngle) > 180 ? 1 : 0;
  
  return `
    M ${x1_outer} ${y1_outer}
    A ${r2} ${r2} 0 ${largeArcFlag} 1 ${x2_outer} ${y2_outer}
    L ${x2_inner} ${y2_inner}
    A ${r1} ${r1} 0 ${largeArcFlag} 0 ${x1_inner} ${y1_inner}
    Z
  `;
}

function drawRing(cx, cy, innerR, outerR, segments, totalCount) {
  let currentAngle = 0;
  let pathsHtml = "";
  let textsHtml = "";
  
  for (const seg of segments) {
    if (seg.value === 0) continue;
    const angleSpan = (seg.value / totalCount) * 360;
    const startAngle = currentAngle;
    const endAngle = currentAngle + angleSpan;
    
    const pathD = getArcPath(cx, cy, innerR, outerR, startAngle, endAngle);
    pathsHtml += `<path d="${pathD}" fill="${seg.color}" stroke="#fff" stroke-width="1.5" />`;
    
    const midAngle = startAngle + angleSpan / 2;
    const rMid = (innerR + outerR) / 2;
    const midRad = (midAngle - 90) * Math.PI / 180;
    
    const tx = cx + rMid * Math.cos(midRad);
    const ty = cy + rMid * Math.sin(midRad);
    
    let textRot = midAngle;
    if (textRot > 90 && textRot < 270) {
      textRot += 180;
    }
    
    if (angleSpan > 6) {
      textsHtml += `<text x="${tx}" y="${ty}" transform="rotate(${textRot} ${tx} ${ty})" text-anchor="middle" dominant-baseline="middle" fill="#24292f" font-size="8" font-weight="600" font-family="Inter, sans-serif">${escapeHtml(seg.label)}</text>`;
    }
    
    currentAngle += angleSpan;
  }
  
  return { pathsHtml, textsHtml };
}

function cveConcentricDonut(issues) {
  if (!issues || !issues.length) return "";

  const total = issues.length;
  const size = 340;
  const cx = size / 2;
  const cy = size / 2;

  // Innermost ring: Type (Kernel vs Other)
  const kernelCount = issues.filter(i => (i.layer || "").toLowerCase().includes("kernel")).length;
  const otherCount = total - kernelCount;
  const ring1Segs = [
    { label: "Kernel", value: kernelCount, color: "#93c5fd" },
    { label: "Other", value: otherCount, color: "#a5f3fc" }
  ];

  // Middle ring: Severity (Critical, High, Medium, Low, None)
  const sevCounts = {};
  for (const issue of issues) {
    const sev = normalizedSeverity(issue);
    sevCounts[sev] = (sevCounts[sev] || 0) + 1;
  }
  const ring2Segs = [
    { label: "Critical", value: sevCounts.critical || 0, color: "#fca5a5" },
    { label: "High", value: sevCounts.high || 0, color: "#fed7aa" },
    { label: "Medium", value: sevCounts.medium || 0, color: "#fef08a" },
    { label: "Low", value: sevCounts.low || 0, color: "#bfdbfe" },
    { label: "None", value: (sevCounts.none || 0) + (sevCounts.unknown || 0), color: "#f3f4f6" }
  ];

  // Outermost ring: Status (Awaiting Triage, Mitigation Available, Not Affected, False Positive, etc.)
  const statusCounts = {};
  for (const issue of issues) {
    const statusStr = issue.status || "Awaiting Triage";
    statusCounts[statusStr] = (statusCounts[statusStr] || 0) + 1;
  }
  const ring3Segs = Object.keys(statusCounts).map(statusKey => {
    let color = "#e5e7eb";
    if (statusKey === "Awaiting Triage") color = "#9ca3af";
    else if (statusKey === "Mitigation Available") color = "#bfdbfe";
    else if (statusKey === "Not Affected") color = "#a7f3d0";
    else if (statusKey === "False Positive") color = "#fcd34d";
    else if (statusKey === "Fixed") color = "#86efac";
    else if (statusKey === "Needs Analysis") color = "#fed7aa";
    
    return {
      label: statusKey,
      value: statusCounts[statusKey],
      color: color
    };
  });

  const r1 = drawRing(cx, cy, 50, 90, ring1Segs, total);
  const r2 = drawRing(cx, cy, 92, 135, ring2Segs, total);
  const r3 = drawRing(cx, cy, 137, 152, ring3Segs, total);

  return `
    <div style="position: relative; width: ${size}px; height: ${size}px;">
      <svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">
        <!-- Inner ring paths & text -->
        ${r1.pathsHtml}
        ${r1.textsHtml}
        
        <!-- Middle ring paths & text -->
        ${r2.pathsHtml}
        ${r2.textsHtml}
        
        <!-- Outer ring paths & text -->
        ${r3.pathsHtml}
        ${r3.textsHtml}
        
        <!-- Center white mask for clean donut look -->
        <circle cx="${cx}" cy="${cy}" r="49" fill="#fff" />
      </svg>
    </div>
  `;
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
async function initializeProjects() {
  try {
    const data = await fetchJson("/api/projects");
    state.projects = Array.isArray(data.projects) ? data.projects : [];
  } catch (err) {
    console.error("Could not load projects", err);
    state.projects = [{ id: "default", name: "Default Project" }];
  }

  // Populate selector dropdown
  if (el.projectSelector) {
    el.projectSelector.innerHTML = state.projects.map(
      (proj) => `<option value="${escapeHtml(proj.id)}">${escapeHtml(proj.name)}</option>`
    ).join("");

    // Select active project
    if (state.projects.some(p => p.id === state.activeProjectId)) {
      el.projectSelector.value = state.activeProjectId;
    } else if (state.projects.length > 0) {
      state.activeProjectId = state.projects[0].id;
      window.localStorage.setItem("activeProjectId", state.activeProjectId);
      el.projectSelector.value = state.activeProjectId;
    } else {
      state.activeProjectId = "default";
      el.projectSelector.value = "default";
    }

    // Listen to changes
    el.projectSelector.addEventListener("change", (e) => {
      state.activeProjectId = e.target.value;
      window.localStorage.setItem("activeProjectId", state.activeProjectId);
      loadIndex();
    });
  }
}

syncViewTabs();
initializeAuth().then(initializeProjects).finally(loadIndex);
