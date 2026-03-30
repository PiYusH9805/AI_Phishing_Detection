document.addEventListener("DOMContentLoaded", () => {
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
    const savedTheme = localStorage.getItem("theme");

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

    applyTheme(savedTheme === "light" ? "light" : "dark");

    const activatePanel = (panelId) => {
        tabs.forEach((tab) => {
            tab.classList.toggle("active", tab.dataset.panel === panelId);
        });

        panels.forEach((panel) => {
            panel.classList.toggle("active", panel.id === panelId);
        });
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

    document.querySelectorAll(".js-scan-form").forEach((form) => {
        form.addEventListener("submit", () => {
            const button = form.querySelector(".primary-button");
            if (!button) {
                return;
            }

            button.classList.add("is-loading");
            button.disabled = true;
            scanOverlay?.classList.add("is-visible");
            scanOverlay?.setAttribute("aria-hidden", "false");
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
});
