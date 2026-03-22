const id = window.location.pathname.split("/").pop();
const castUrl = `/api/recordings/${id}/cast`;
const downloadUrl = `/api/recordings/${id}/download`;
const downloadLink = document.getElementById("downloadLink");
const fallback = document.getElementById("fallback");
const playerContainer = document.getElementById("player");
const header = document.querySelector("header");
const themeToggle = document.getElementById("themeToggle");

initThemeToggle();

downloadLink.href = downloadUrl;

if (window.AsciinemaPlayer) {
  const resizePlayer = () => {
    const viewport = window.innerHeight || 800;
    const headerHeight = header ? header.getBoundingClientRect().height : 0;
    const target = Math.max(240, viewport - headerHeight - 40);
    playerContainer.style.height = `${target}px`;
  };
  resizePlayer();
  window.addEventListener("resize", resizePlayer);

  window.AsciinemaPlayer.create(castUrl, document.getElementById("player"), {
    theme: "monokai",
    loop: false,
    idleTimeLimit: 2,
    fit: "both",
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
  themeToggle.textContent = label;
  themeToggle.setAttribute("aria-pressed", theme === "dark");
}
