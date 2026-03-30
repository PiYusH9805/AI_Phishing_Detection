document.addEventListener("DOMContentLoaded", () => {
    // Shared frontend controller for theme switching, scan interactions, and panel navigation.
    const root = document.documentElement;
    const body = document.body;
    const themeToggle = document.getElementById("theme-toggle");
    const themeLabel = themeToggle?.querySelector(".theme-toggle-label");
    const tabs = Array.from(document.querySelectorAll(".tab-button"));
    const panels = Array.from(document.querySelectorAll(".scan-mode"));
    const switchButtons = Array.from(document.querySelectorAll("[data-switch-target]"));
    const scanOverlay = document.getElementById("scan-overlay");
    const pasteUrlButton = document.getElementById("paste-url-button");
    const urlInput = document.getElementById("input_url");
    const resultSection = document.getElementById("result-section");
    const savedTheme = localStorage.getItem("theme");
    const SCAN_SCROLL_FLAG = "scroll-to-scan-result";
    const SCAN_PENDING_FLAG = "scan-pending";
    const hash = window.location.hash;
    const overlayTitle = scanOverlay?.querySelector("h2");
    const overlayMessage = scanOverlay?.querySelector("p");
    let scanProgressFrame = null;
    let scanProgressState = null;

    const ensureScanAnimationUi = () => {
        if (!scanOverlay) {
            return {};
        }

        let animationHost = scanOverlay.querySelector("[data-scan-animation]");
        let progressBar = scanOverlay.querySelector("[data-scan-progress-bar]");
        let progressText = scanOverlay.querySelector("[data-scan-progress-text]");

        if (animationHost && progressBar && progressText) {
            return { animationHost, progressBar, progressText };
        }

        animationHost = document.createElement("div");
        animationHost.dataset.scanAnimation = "true";
        animationHost.setAttribute("aria-hidden", "true");
        animationHost.style.display = "grid";
        animationHost.style.gap = "12px";
        animationHost.style.marginTop = "18px";

        const progressTrack = document.createElement("div");
        progressTrack.style.width = "100%";
        progressTrack.style.height = "12px";
        progressTrack.style.borderRadius = "999px";
        progressTrack.style.overflow = "hidden";
        progressTrack.style.border = "1px solid rgba(47, 220, 255, 0.2)";
        progressTrack.style.background = "rgba(255, 255, 255, 0.08)";
        progressTrack.style.boxShadow = "inset 0 0 18px rgba(47, 220, 255, 0.05)";

        progressBar = document.createElement("div");
        progressBar.dataset.scanProgressBar = "true";
        progressBar.style.width = "0%";
        progressBar.style.height = "100%";
        progressBar.style.borderRadius = "inherit";
        progressBar.style.background = "linear-gradient(90deg, #17d5ff, #42f3a3)";
        progressBar.style.boxShadow = "0 0 18px rgba(23, 213, 255, 0.28)";
        progressBar.style.transition = "width 160ms ease";

        progressText = document.createElement("div");
        progressText.dataset.scanProgressText = "true";
        progressText.style.color = "rgba(237, 246, 255, 0.86)";
        progressText.style.fontSize = "0.95rem";
        progressText.style.letterSpacing = "0.08em";
        progressText.style.textTransform = "uppercase";
        progressText.style.fontWeight = "700";
        progressText.style.textAlign = "center";
        progressText.textContent = "0% complete";

        progressTrack.appendChild(progressBar);
        animationHost.append(progressTrack, progressText);
        scanOverlay.querySelector(".scan-overlay-card")?.appendChild(animationHost);

        return { animationHost, progressBar, progressText };
    };

    const applyTheme = (theme) => {
        root.setAttribute("data-theme", theme);

        if (themeLabel) {
            themeLabel.textContent = theme === "dark" ? "Light Mode" : "Dark Mode";
        }

        if (themeToggle) {
            themeToggle.setAttribute("aria-pressed", String(theme === "light"));
            themeToggle.setAttribute("aria-label", `Switch to ${theme === "dark" ? "light" : "dark"} mode`);
        }
    };

    const showScanOverlay = () => {
        scanOverlay?.classList.add("is-visible");
        scanOverlay?.setAttribute("aria-hidden", "false");
    };

    const hideScanOverlay = () => {
        scanOverlay?.classList.remove("is-visible");
        scanOverlay?.setAttribute("aria-hidden", "true");
    };

    const stopScanAnimation = () => {
        if (scanProgressFrame !== null) {
            window.cancelAnimationFrame(scanProgressFrame);
            scanProgressFrame = null;
        }
        scanProgressState = null;
    };

    const startScanAnimation = () => {
        const { progressBar, progressText } = ensureScanAnimationUi();
        if (!progressBar || !progressText) {
            return;
        }

        stopScanAnimation();

        if (overlayTitle) {
            overlayTitle.textContent = "Analyzing threat...";
        }
        if (overlayMessage) {
            overlayMessage.textContent = "Extracting signals, checking indicators, and computing the final phishing risk score.";
        }

        progressBar.style.width = "0%";
        progressText.textContent = "0% complete";
        scanProgressState = { startedAt: performance.now() };

        const tick = (now) => {
            if (!scanProgressState) {
                return;
            }

            const elapsed = now - scanProgressState.startedAt;
            const normalized = Math.min(elapsed / 2200, 1);
            const eased = 1 - Math.pow(1 - normalized, 3);
            const visualProgress = Math.min(92, Math.round(eased * 92));

            progressBar.style.width = `${visualProgress}%`;
            progressText.textContent = `${visualProgress}% complete`;

            if (visualProgress < 92) {
                scanProgressFrame = window.requestAnimationFrame(tick);
            } else {
                scanProgressFrame = null;
            }
        };

        scanProgressFrame = window.requestAnimationFrame(tick);
    };

    const scrollResultIntoView = () => {
        if (resultSection?.dataset.hasResult === "true") {
            resultSection.scrollIntoView({ behavior: "smooth", block: "start" });
        }
    };

    applyTheme(savedTheme === "light" ? "light" : "dark");

    const activatePanel = (panelId) => {
        tabs.forEach((tab) => {
            tab.classList.toggle("active", tab.dataset.panel === panelId);
        });

        panels.forEach((panel) => {
            panel.classList.toggle("active", panel.id === panelId);
        });
    };

    const handleHashNavigation = () => {
        // Frontend-only deep links keep the requested navbar sections working without new Flask routes.
        if (hash === "#url-scanner") {
            activatePanel("url-panel");
            document.getElementById("scanner")?.scrollIntoView({ behavior: "smooth", block: "start" });
        } else if (hash === "#email-scanner") {
            activatePanel("email-panel");
            document.getElementById("scanner")?.scrollIntoView({ behavior: "smooth", block: "start" });
        } else if (hash === "#file-scanner") {
            activatePanel("file-panel");
            document.getElementById("scanner")?.scrollIntoView({ behavior: "smooth", block: "start" });
        } else if (hash === "#simulation-lab") {
            document.getElementById("simulation-lab")?.scrollIntoView({ behavior: "smooth", block: "start" });
        }
    };

    tabs.forEach((tab) => {
        tab.addEventListener("click", () => activatePanel(tab.dataset.panel));
    });

    switchButtons.forEach((button) => {
        button.addEventListener("click", () => {
            activatePanel(button.dataset.switchTarget);
            document.getElementById("scanner")?.scrollIntoView({ behavior: "smooth", block: "start" });
        });
    });

    activatePanel(body.dataset.activePanel || "email-panel");
    window.setTimeout(handleHashNavigation, 120);

    document.querySelectorAll(".js-scan-form").forEach((form) => {
        form.addEventListener("submit", async (event) => {
            if (form.dataset.submitting === "true") {
                return;
            }

            event.preventDefault();

            const button = form.querySelector(".primary-button");
            if (!button) {
                sessionStorage.setItem(SCAN_PENDING_FLAG, "true");
                form.dataset.submitting = "true";
                form.submit();
                return;
            }

            button.classList.add("is-loading");
            button.disabled = true;
            const buttonText = button.querySelector(".button-text");
            if (buttonText) {
                buttonText.dataset.originalText = buttonText.dataset.originalText || buttonText.textContent || "";
                buttonText.textContent = "Analyzing threat...";
            }

            showScanOverlay();
            startScanAnimation();

            // Keep the cybersecurity scan animation visible for at least one second.
            await new Promise((resolve) => window.setTimeout(resolve, 1000));

            sessionStorage.setItem(SCAN_SCROLL_FLAG, "true");
            sessionStorage.setItem(SCAN_PENDING_FLAG, "true");
            form.dataset.submitting = "true";
            form.submit();
        });
    });

    document.querySelectorAll(".js-auth-form").forEach((form) => {
        form.addEventListener("submit", () => {
            const button = form.querySelector(".primary-button");
            if (!button) {
                return;
            }

            button.classList.add("is-loading");
            button.disabled = true;
        });
    });

    themeToggle?.addEventListener("click", () => {
        const nextTheme = root.getAttribute("data-theme") === "light" ? "dark" : "light";
        localStorage.setItem("theme", nextTheme);
        applyTheme(nextTheme);
    });

    pasteUrlButton?.addEventListener("click", async () => {
        if (!navigator.clipboard || !urlInput) {
            return;
        }

        try {
            const text = await navigator.clipboard.readText();
            if (text) {
                urlInput.value = text.trim();
                activatePanel("url-panel");
                urlInput.focus();
            }
        } catch (error) {
            console.error("Clipboard read failed", error);
        }
    });

    if (sessionStorage.getItem(SCAN_PENDING_FLAG) === "true") {
        sessionStorage.removeItem(SCAN_PENDING_FLAG);
        stopScanAnimation();
        hideScanOverlay();
    }

    if (sessionStorage.getItem(SCAN_SCROLL_FLAG) === "true") {
        sessionStorage.removeItem(SCAN_SCROLL_FLAG);
        window.setTimeout(scrollResultIntoView, 160);
    }
});
