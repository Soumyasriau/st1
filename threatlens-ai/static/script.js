/**
 * ThreatLens AI — Client-side UX & Interactive Controller
 */

document.addEventListener("DOMContentLoaded", function () {
    // 1. URL Pre-validation on Client
    const scanForm = document.getElementById("scanForm");
    const urlInput = document.getElementById("urlInput");

    if (scanForm && urlInput) {
        urlInput.addEventListener("input", function () {
            let val = urlInput.value.trim().toLowerCase();
            // Block obvious localhost or private targets on client side immediately
            const blockedKeywords = [
                "localhost", "127.0.0.1", "::1", "169.254.169.254",
                "192.168.", "10.", "172.16.", "172.17.", "172.18.",
                "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
                "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
                "172.29.", "172.30.", "172.31."
            ];

            let isBlocked = blockedKeywords.some(keyword => val.includes(keyword));
            if (isBlocked) {
                urlInput.style.borderColor = "#ef4444";
                urlInput.title = "Internal / private target prohibited by SSRF policy.";
            } else {
                urlInput.style.borderColor = "";
                urlInput.title = "";
            }
        });
    }

    // 2. Escape key closes modals
    document.addEventListener("keydown", function (e) {
        if (e.key === "Escape") {
            const deleteModal = document.getElementById("deleteModal");
            if (deleteModal && deleteModal.style.display !== "none") {
                deleteModal.style.display = "none";
            }
        }
    });

    // 3. Auto-dismiss flash alerts after 8 seconds
    const flashAlerts = document.querySelectorAll(".flash-alert");
    flashAlerts.forEach(function (alert) {
        setTimeout(function () {
            alert.style.opacity = "0";
            alert.style.transition = "opacity 0.5s ease";
            setTimeout(function () { alert.remove(); }, 500);
        }, 8000);
    });
});
