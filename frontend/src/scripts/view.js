import { create as createPlayer } from "asciinema-player";
import createElement from "lucide/dist/esm/createElement.mjs";
import ArrowLeft from "lucide/dist/esm/icons/arrow-left.mjs";
import MonitorCog from "lucide/dist/esm/icons/monitor-cog.mjs";
import Moon from "lucide/dist/esm/icons/moon.mjs";
import Sun from "lucide/dist/esm/icons/sun.mjs";

const iconSet = {
  "arrow-left": ArrowLeft,
  "monitor-cog": MonitorCog,
  moon: Moon,
  sun: Sun,
};

const id = window.location.pathname.split("/").pop();
const params = new URLSearchParams(window.location.search);
const startAt = Math.max(0, Number(params.get("t") || "0"));
const castUrl = `/api/recordings/${id}/cast`;
const downloadUrl = `/api/recordings/${id}/download`;
const downloadLink = document.getElementById("downloadLink");
const fallback = document.getElementById("fallback");
const playerContainer = document.getElementById("player");
const header = document.querySelector("header");
const themeToggle = document.getElementById("themeToggle");

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

renderIcons();
initThemeToggle();

downloadLink.href = downloadUrl;

if (typeof createPlayer === "function") {
  const resizePlayer = () => {
    const viewport = window.innerHeight || 800;
    const headerHeight = header ? header.getBoundingClientRect().height : 0;
    const target = Math.max(240, viewport - headerHeight - 40);
    playerContainer.style.height = `${target}px`;
  };
  resizePlayer();
  window.addEventListener("resize", resizePlayer);

  createPlayer(castUrl, document.getElementById("player"), {
    theme: "monokai",
    loop: false,
    idleTimeLimit: 2,
    fit: "both",
    startAt,
  });
} else {
  fallback.classList.remove("hidden");
}

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
