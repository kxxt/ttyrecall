const id = window.location.pathname.split("/").pop();
const castUrl = `/api/recordings/${id}/cast`;
const downloadUrl = `/api/recordings/${id}/download`;
const downloadLink = document.getElementById("downloadLink");
const fallback = document.getElementById("fallback");

downloadLink.href = downloadUrl;

if (window.AsciinemaPlayer) {
  window.AsciinemaPlayer.create(castUrl, document.getElementById("player"), {
    theme: "monokai",
    loop: false,
    idleTimeLimit: 2,
    fit: "width",
  });
} else {
  fallback.classList.remove("hidden");
}
