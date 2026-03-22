const state = {
  user: null,
  recordings: [],
  filterDate: null,
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
    row.innerHTML = `
      <td><input type="checkbox" data-id="${rec.id}" /></td>
      <td>${rec.display}</td>
      <td>${rec.name} ${rec.compressed ? '<span class="badge">zst</span>' : ''}</td>
      <td>${formatBytes(rec.size)}</td>
      <td>
        <div class="table-actions">
          <button data-view="${rec.id}" class="secondary">View</button>
          <button data-download="${rec.id}">Download</button>
          <button data-delete="${rec.id}" class="secondary">Delete</button>
        </div>
      </td>
    `;
    recordingsBody.appendChild(row);
  }
}

function applyFilters() {
  let records = state.recordings;
  if (state.filterDate) {
    records = records.filter((rec) => rec.date === state.filterDate);
  }
  renderRecordings(records);
  updateFilterLabel();
}

function updateFilterLabel() {
  if (state.filterDate) {
    heatmapFilter.innerHTML = `Showing recordings for <strong>${state.filterDate}</strong> · <button id="clearHeatmapFilter" class="secondary">Clear</button>`;
  } else {
    heatmapFilter.textContent = "";
  }
}

function selectedIds() {
  const checked = recordingsBody.querySelectorAll("input[type=checkbox]:checked");
  return Array.from(checked).map((el) => el.dataset.id);
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
  recordingsBody.querySelectorAll("input[type=checkbox]").forEach((box) => {
    box.checked = checked;
  });
});

recordingsBody.addEventListener("click", async (event) => {
  const target = event.target;
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

heatmapFilter.addEventListener("click", async (event) => {
  const target = event.target;
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
  initThemeToggle();
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
  themeToggle.textContent = label;
  themeToggle.setAttribute("aria-pressed", theme === "dark");
}
