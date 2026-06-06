import { create as createPlayer } from "asciinema-player";
import createElement from "lucide/dist/esm/createElement.mjs";
import Download from "lucide/dist/esm/icons/download.mjs";
import LayoutGrid from "lucide/dist/esm/icons/layout-grid.mjs";
import List from "lucide/dist/esm/icons/list.mjs";
import LogIn from "lucide/dist/esm/icons/log-in.mjs";
import LogOut from "lucide/dist/esm/icons/log-out.mjs";
import MonitorCog from "lucide/dist/esm/icons/monitor-cog.mjs";
import Moon from "lucide/dist/esm/icons/moon.mjs";
import Play from "lucide/dist/esm/icons/play.mjs";
import RefreshCw from "lucide/dist/esm/icons/refresh-cw.mjs";
import Sun from "lucide/dist/esm/icons/sun.mjs";
import Trash2 from "lucide/dist/esm/icons/trash-2.mjs";
import X from "lucide/dist/esm/icons/x.mjs";

const iconSet = {
  download: Download,
  "layout-grid": LayoutGrid,
  list: List,
  "log-in": LogIn,
  "log-out": LogOut,
  "monitor-cog": MonitorCog,
  moon: Moon,
  play: Play,
  "refresh-cw": RefreshCw,
  sun: Sun,
  "trash-2": Trash2,
  x: X,
};

const state = {
  user: null,
  recordings: [],
  filterDate: null,
  viewMode: "list",
  selected: new Set(),
  filtered: [],
};

const loginPanel = document.getElementById("loginPanel");
const appPanel = document.getElementById("appPanel");
const loginButton = document.getElementById("loginButton");
const loginError = document.getElementById("loginError");
const userLabel = document.getElementById("userLabel");
const recordingsBody = document.getElementById("recordingsBody");
const emptyState = document.getElementById("emptyState");
const selectAll = document.getElementById("selectAll");
const heatmapLabels = document.getElementById("heatmapLabels");
const heatmapFilter = document.getElementById("heatmapFilter");
const usernameInput = document.getElementById("username");
const passwordInput = document.getElementById("password");
const themeToggle = document.getElementById("themeToggle");
const listView = document.getElementById("listView");
const galleryView = document.getElementById("galleryView");
const viewListButton = document.getElementById("viewList");
const viewGalleryButton = document.getElementById("viewGallery");
const selectAllGallery = document.getElementById("selectAllGallery");
const selectAllGalleryWrap = document.getElementById("selectAllGalleryWrap");

const galleryPlayers = new Map();

function renderIcons(root = document) {
  root.querySelectorAll("[data-lucide]").forEach((element) => {
    const name = element.getAttribute("data-lucide");
    const iconNode = iconSet[name];
    if (!iconNode) {
      return;
    }
    const svg = createElement(iconNode, {
      "data-lucide": name,
      class: `lucide lucide-${name}`,
      "aria-hidden": "true",
      width: 18,
      height: 18,
      "stroke-width": 2,
    });
    element.replaceWith(svg);
  });
}

function iconMarkup(name) {
  return `<i data-lucide="${name}" aria-hidden="true"></i>`;
}

function iconButton(label, icon, dataAttr, id, extraClass = "") {
  return `
    <button
      ${dataAttr}="${id}"
      class="secondary icon-button ${extraClass}"
      type="button"
      aria-label="${label}"
      title="${label}"
    >
      ${iconMarkup(icon)}
      <span class="visually-hidden">${label}</span>
    </button>
  `;
}

async function api(path, options = {}) {
  const response = await fetch(path, Object.assign({
    headers: { "Content-Type": "application/json" },
    credentials: "include",
  }, options));
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || response.statusText);
  }
  const contentType = response.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    return await response.json();
  }
  return await response.text();
}

function showLogin(message) {
  loginPanel.classList.remove("hidden");
  appPanel.classList.add("hidden");
  if (message) {
    loginError.textContent = message;
  } else {
    loginError.textContent = "";
  }
}

function showApp() {
  loginPanel.classList.add("hidden");
  appPanel.classList.remove("hidden");
}

function formatBytes(bytes) {
  const units = ["B", "KB", "MB", "GB"];
  let idx = 0;
  let value = bytes;
  while (value > 1024 && idx < units.length - 1) {
    value /= 1024;
    idx += 1;
  }
  return `${value.toFixed(value < 10 && idx > 0 ? 1 : 0)} ${units[idx]}`;
}

function renderRecordings(recordings) {
  recordingsBody.innerHTML = "";
  if (!recordings.length) {
    emptyState.classList.remove("hidden");
    return;
  }
  emptyState.classList.add("hidden");
  for (const rec of recordings) {
    const row = document.createElement("tr");
    const checked = state.selected.has(rec.id) ? "checked" : "";
    row.innerHTML = `
      <td><input type="checkbox" data-id="${rec.id}" ${checked} /></td>
      <td>${rec.display}</td>
      <td>${rec.name} ${rec.compressed ? '<span class="badge">zst</span>' : ''}</td>
      <td>${formatBytes(rec.size)}</td>
      <td>
        <div class="table-actions">
          ${iconButton("View", "play", "data-view", rec.id)}
          ${iconButton("Download", "download", "data-download", rec.id)}
          ${iconButton("Delete", "trash-2", "data-delete", rec.id, "danger")}
        </div>
      </td>
    `;
    recordingsBody.appendChild(row);
  }
  renderIcons(recordingsBody);
}

function renderGallery(recordings) {
  disposeGalleryPlayers();
  galleryView.innerHTML = "";
  if (!recordings.length) {
    emptyState.classList.remove("hidden");
    return;
  }
  emptyState.classList.add("hidden");
  for (const rec of recordings) {
    const card = document.createElement("div");
    const checked = state.selected.has(rec.id) ? "checked" : "";
    card.className = `gallery-card${checked ? " selected" : ""}`;
    card.innerHTML = `
      <label class="gallery-select">
        <input type="checkbox" data-id="${rec.id}" ${checked} />
      </label>
      <div class="preview" data-id="${rec.id}" data-cast="/api/recordings/${rec.id}/cast"></div>
      <div class="gallery-meta">
        <div class="gallery-title">${rec.name} ${rec.compressed ? '<span class="badge">zst</span>' : ''}</div>
        <div class="gallery-sub">${rec.display} · ${formatBytes(rec.size)}</div>
      </div>
      <div class="table-actions">
        ${iconButton("View", "play", "data-view", rec.id)}
        ${iconButton("Download", "download", "data-download", rec.id)}
        ${iconButton("Delete", "trash-2", "data-delete", rec.id, "danger")}
      </div>
    `;
    galleryView.appendChild(card);
  }
  renderIcons(galleryView);
  initGalleryPlayers();
}

function initGalleryPlayers() {
  if (typeof createPlayer !== "function") {
    return;
  }
  const previews = galleryView.querySelectorAll(".preview");
  previews.forEach((preview) => {
    const castUrl = preview.dataset.cast;
    if (!castUrl) {
      return;
    }
    const player = createPlayer(castUrl, preview, {
      fit: "width",
      idleTimeLimit: 2,
    });
    if (player && player.seek) {
      player.seek("50%");
    }
    galleryPlayers.set(preview, player);
    let leaveTimer = null;
    preview.addEventListener("pointerenter", () => {
      if (leaveTimer) {
        clearTimeout(leaveTimer);
        leaveTimer = null;
      }
      if (player && player.seek) {
        player.seek(0);
      }
      if (player && player.play) {
        player.play();
      }
    });
    preview.addEventListener("pointerleave", () => {
      leaveTimer = window.setTimeout(() => {
        if (player && player.pause) {
          player.pause();
        }
        if (player && player.seek) {
          player.seek("50%");
        }
      }, 120);
    });
  });
}

function disposeGalleryPlayers() {
  for (const [node, player] of galleryPlayers.entries()) {
    if (player && player.dispose) {
      player.dispose();
    }
    if (node) {
      node.replaceChildren();
    }
  }
  galleryPlayers.clear();
}

function setViewMode(mode) {
  state.viewMode = mode;
  localStorage.setItem("ttyrecall-view", mode);
  updateViewMode();
  applyFilters();
}

function updateViewMode() {
  const mode = state.viewMode || "list";
  const listActive = mode === "list";
  listView.classList.toggle("hidden", !listActive);
  galleryView.classList.toggle("hidden", listActive);
  viewListButton.classList.toggle("active", listActive);
  viewGalleryButton.classList.toggle("active", !listActive);
  if (selectAllGalleryWrap) {
    selectAllGalleryWrap.classList.toggle("hidden", listActive);
  }
  if (listActive) {
    disposeGalleryPlayers();
  }
}

function applyFilters() {
  let records = state.recordings;
  if (state.filterDate) {
    records = records.filter((rec) => rec.date === state.filterDate);
  }
  state.filtered = records;
  if (!records.length) {
    emptyState.classList.remove("hidden");
    renderRecordings([]);
    renderGallery([]);
    return;
  }
  emptyState.classList.add("hidden");
  if (state.viewMode === "gallery") {
    renderGallery(records);
  } else {
    renderRecordings(records);
  }
  updateFilterLabel();
  updateSelectAllCheckbox();
}

function updateFilterLabel() {
  if (state.filterDate) {
    heatmapFilter.innerHTML = `
      Showing recordings for <strong>${state.filterDate}</strong>
      <button id="clearHeatmapFilter" class="secondary icon-button compact" type="button" aria-label="Clear filter" title="Clear filter">
        ${iconMarkup("x")}
        <span class="visually-hidden">Clear filter</span>
      </button>
    `;
    renderIcons(heatmapFilter);
  } else {
    heatmapFilter.textContent = "";
  }
}

function selectedIds() {
  return Array.from(state.selected);
}

function updateSelectAllCheckbox() {
  if (!state.filtered.length) {
    if (selectAll) {
      selectAll.checked = false;
      selectAll.indeterminate = false;
    }
    if (selectAllGallery) {
      selectAllGallery.checked = false;
      selectAllGallery.indeterminate = false;
    }
    return;
  }
  const selectedCount = state.filtered.filter((rec) => state.selected.has(rec.id)).length;
  if (selectAll) {
    selectAll.checked = selectedCount === state.filtered.length;
    selectAll.indeterminate = selectedCount > 0 && selectedCount < state.filtered.length;
  }
  if (selectAllGallery) {
    selectAllGallery.checked = selectedCount === state.filtered.length;
    selectAllGallery.indeterminate = selectedCount > 0 && selectedCount < state.filtered.length;
  }
}

async function loadRecordings() {
  const data = await api("/api/recordings");
  state.recordings = data.recordings || [];
  applyFilters();
}

function colorForCount(count) {
  if (count >= 10) return "var(--heat-4)";
  if (count >= 6) return "var(--heat-3)";
  if (count >= 3) return "var(--heat-2)";
  if (count >= 1) return "var(--heat-1)";
  return "var(--heat-0)";
}

async function loadHeatmap() {
  const data = await api("/api/heatmap");
  const counts = new Map(data.counts.map((item) => [item.date, item.count]));
  const today = new Date(data.today);
  const days = 53 * 7;
  const start = new Date(today);
  start.setDate(start.getDate() - (days - 1));

  const heatmap = document.getElementById("heatmap");
  const heatmapScroller = heatmap.parentElement;
  heatmap.innerHTML = "";
  heatmapLabels.innerHTML = "";
  const weeks = 53;
  let lastMonth = null;
  for (let week = 0; week < weeks; week++) {
    const date = new Date(start);
    date.setDate(start.getDate() + week * 7);
    const month = date.toLocaleString("en-US", { month: "short" });
    const label = document.createElement("div");
    label.className = "label";
    if (month !== lastMonth) {
      label.textContent = month;
      lastMonth = month;
    } else {
      label.textContent = "";
    }
    heatmapLabels.appendChild(label);
  }
  for (let i = 0; i < days; i++) {
    const date = new Date(start);
    date.setDate(start.getDate() + i);
    const key = date.toISOString().slice(0, 10);
    const count = counts.get(key) || 0;
    const cell = document.createElement("div");
    cell.className = "day";
    cell.style.background = colorForCount(count);
    cell.title = `${key}: ${count} recording${count === 1 ? "" : "s"}`;
    cell.dataset.date = key;
    if (state.filterDate === key) {
      cell.classList.add("selected");
    }
    heatmap.appendChild(cell);
  }
  if (heatmapScroller) {
    requestAnimationFrame(() => {
      heatmapScroller.scrollLeft = Math.max(
        0,
        heatmapScroller.scrollWidth - heatmapScroller.clientWidth,
      );
    });
  }
}

async function loadMe() {
  try {
    const me = await api("/api/me");
    state.user = me;
    userLabel.textContent = `Signed in as ${me.username}`;
    showApp();
    await loadHeatmap();
    await loadRecordings();
  } catch (err) {
    showLogin();
  }
}

loginButton.addEventListener("click", async () => {
  loginButton.disabled = true;
  try {
    const username = document.getElementById("username").value.trim();
    const password = document.getElementById("password").value;
    await api("/api/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    });
    await loadMe();
  } catch (err) {
    const message = err.message.includes("token")
      ? "Token login is required for this web UI."
      : "Login failed. Please check your credentials.";
    showLogin(message);
  } finally {
    loginButton.disabled = false;
  }
});

function handleLoginKey(event) {
  if (event.key === "Enter") {
    loginButton.click();
  }
}

usernameInput.addEventListener("keydown", handleLoginKey);
passwordInput.addEventListener("keydown", handleLoginKey);

document.getElementById("refreshButton").addEventListener("click", async () => {
  await loadHeatmap();
  await loadRecordings();
});

document.getElementById("downloadButton").addEventListener("click", () => {
  const ids = selectedIds();
  if (!ids.length) {
    return;
  }
  for (const id of ids) {
    const link = document.createElement("a");
    link.href = `/api/recordings/${id}/download`;
    link.download = "";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  }
});

document.getElementById("deleteButton").addEventListener("click", async () => {
  const ids = selectedIds();
  if (!ids.length) {
    return;
  }
  if (!confirm(`Delete ${ids.length} recording(s)?`)) {
    return;
  }
  await api("/api/recordings/delete", {
    method: "POST",
    body: JSON.stringify({ ids }),
  });
  await loadRecordings();
  await loadHeatmap();
});

document.getElementById("logoutButton").addEventListener("click", async () => {
  await api("/api/logout", { method: "POST" });
  state.user = null;
  showLogin();
});

selectAll.addEventListener("change", (event) => {
  const checked = event.target.checked;
  if (checked) {
    state.filtered.forEach((rec) => state.selected.add(rec.id));
  } else {
    state.filtered.forEach((rec) => state.selected.delete(rec.id));
  }
  applyFilters();
});

if (selectAllGallery) {
  selectAllGallery.addEventListener("change", (event) => {
    const checked = event.target.checked;
    if (checked) {
      state.filtered.forEach((rec) => state.selected.add(rec.id));
    } else {
      state.filtered.forEach((rec) => state.selected.delete(rec.id));
    }
    applyFilters();
  });
}

recordingsBody.addEventListener("click", async (event) => {
  const target = event.target.closest("button[data-view], button[data-download], button[data-delete]");
  if (!target) {
    return;
  }
  if (target.dataset.view) {
    window.open(`/view/${target.dataset.view}`, "_blank");
  }
  if (target.dataset.download) {
    window.open(`/api/recordings/${target.dataset.download}/download`, "_blank");
  }
  if (target.dataset.delete) {
    if (!confirm("Delete this recording?")) {
      return;
    }
    await api("/api/recordings/delete", {
      method: "POST",
      body: JSON.stringify({ ids: [target.dataset.delete] }),
    });
    await loadRecordings();
    await loadHeatmap();
  }
});

recordingsBody.addEventListener("change", (event) => {
  const target = event.target;
  if (target && target.matches("input[type=checkbox][data-id]")) {
    const id = target.dataset.id;
    if (target.checked) {
      state.selected.add(id);
    } else {
      state.selected.delete(id);
    }
    updateSelectAllCheckbox();
  }
});

galleryView.addEventListener("click", async (event) => {
  const target = event.target.closest("button[data-view], button[data-download], button[data-delete]");
  if (!target) {
    return;
  }
  if (target.dataset.view) {
    window.open(`/view/${target.dataset.view}`, "_blank");
  }
  if (target.dataset.download) {
    window.open(`/api/recordings/${target.dataset.download}/download`, "_blank");
  }
  if (target.dataset.delete) {
    if (!confirm("Delete this recording?")) {
      return;
    }
    await api("/api/recordings/delete", {
      method: "POST",
      body: JSON.stringify({ ids: [target.dataset.delete] }),
    });
    await loadRecordings();
    await loadHeatmap();
  }
});

galleryView.addEventListener("change", (event) => {
  const target = event.target;
  if (target && target.matches("input[type=checkbox][data-id]")) {
    const id = target.dataset.id;
    if (target.checked) {
      state.selected.add(id);
    } else {
      state.selected.delete(id);
    }
    const card = target.closest(".gallery-card");
    if (card) {
      card.classList.toggle("selected", target.checked);
    }
    updateSelectAllCheckbox();
  }
});

heatmapFilter.addEventListener("click", async (event) => {
  const target = event.target.closest("#clearHeatmapFilter");
  if (target && target.id === "clearHeatmapFilter") {
    state.filterDate = null;
    await loadHeatmap();
    applyFilters();
  }
});

document.getElementById("heatmap").addEventListener("click", async (event) => {
  const target = event.target;
  if (!target.classList.contains("day")) {
    return;
  }
  const date = target.dataset.date;
  if (!date) {
    return;
  }
  state.filterDate = state.filterDate === date ? null : date;
  await loadHeatmap();
  applyFilters();
});

async function tryTokenLogin() {
  const params = new URLSearchParams(window.location.search);
  const token = params.get("token");
  if (!token) {
    return false;
  }
  try {
    await api("/api/token-login", {
      method: "POST",
      body: JSON.stringify({ token }),
    });
    window.history.replaceState({}, "", window.location.pathname);
    return true;
  } catch (err) {
    showLogin("Token login failed. Check the token.");
    return false;
  }
}

async function bootstrap() {
  renderIcons();
  initThemeToggle();
  const storedView = localStorage.getItem("ttyrecall-view") || "list";
  state.viewMode = storedView === "gallery" ? "gallery" : "list";
  updateViewMode();
  viewListButton.addEventListener("click", () => setViewMode("list"));
  viewGalleryButton.addEventListener("click", () => setViewMode("gallery"));
  await tryTokenLogin();
  await loadMe();
}

bootstrap();

function applyTheme(theme) {
  if (theme === "light" || theme === "dark") {
    document.documentElement.setAttribute("data-theme", theme);
  } else {
    document.documentElement.removeAttribute("data-theme");
  }
  updateThemeLabel(theme);
}

function initThemeToggle() {
  const stored = localStorage.getItem("ttyrecall-theme") || "system";
  applyTheme(stored);
  if (!themeToggle) {
    return;
  }
  updateThemeLabel(stored);
  themeToggle.addEventListener("click", () => {
    const current = localStorage.getItem("ttyrecall-theme") || "system";
    let next = "system";
    if (current === "system") {
      next = "dark";
    } else if (current === "dark") {
      next = "light";
    } else {
      next = "system";
    }
    applyTheme(next);
    localStorage.setItem("ttyrecall-theme", next);
  });
}

function updateThemeLabel(theme) {
  if (!themeToggle) {
    return;
  }
  const label = theme === "dark" ? "Theme: Dark" : theme === "light" ? "Theme: Light" : "Theme: System";
  const icon = theme === "dark" ? "moon" : theme === "light" ? "sun" : "monitor-cog";
  themeToggle.innerHTML = `${iconMarkup(icon)}<span class="visually-hidden">${label}</span>`;
  renderIcons(themeToggle);
  themeToggle.setAttribute("aria-label", label);
  themeToggle.setAttribute("title", label);
  themeToggle.setAttribute("aria-pressed", theme === "dark");
}
