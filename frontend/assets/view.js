const id = window.location.pathname.split("/").pop();
const castUrl = `/api/recordings/${id}/cast`;
const downloadUrl = `/api/recordings/${id}/download`;
const downloadLink = document.getElementById("downloadLink");
const fallback = document.getElementById("fallback");
const playerContainer = document.getElementById("player");
const header = document.querySelector("header");

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
