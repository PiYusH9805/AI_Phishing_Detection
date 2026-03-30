document.addEventListener("DOMContentLoaded", () => {
    // Frontend-only controller for homepage-only interactions:
    // 1. recent threat modal
    // 2. animated risk gauge readout
    const trigger = document.getElementById("recent-threats-trigger");
    const modal = document.getElementById("recent-threats-modal");
    const closeButton = document.getElementById("recent-threats-close");
    const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const gauges = Array.from(document.querySelectorAll("[data-gauge-value]"));

    const setGaugeValue = (gauge, value) => {
        const clamped = Math.max(0, Math.min(100, value));
        const angle = -90 + (clamped * 1.8);
        const readout = gauge.querySelector("[data-gauge-readout]");

        gauge.style.setProperty("--gauge-angle", `${angle}deg`);

        if (readout) {
            readout.textContent = `${Math.round(clamped)}%`;
        }
    };

    gauges.forEach((gauge) => {
        const target = Number(gauge.dataset.gaugeValue);
        if (!Number.isFinite(target)) {
            return;
        }

        if (prefersReducedMotion) {
            setGaugeValue(gauge, target);
            return;
        }

        const duration = 900;
        const start = performance.now();

        const tick = (now) => {
            const progress = Math.min((now - start) / duration, 1);
            const eased = 1 - Math.pow(1 - progress, 3);
            setGaugeValue(gauge, target * eased);

            if (progress < 1) {
                window.requestAnimationFrame(tick);
            } else {
                setGaugeValue(gauge, target);
            }
        };

        setGaugeValue(gauge, 0);
        window.requestAnimationFrame(tick);
    });

    if (!trigger || !modal) {
        return;
    }

    const closeTargets = modal.querySelectorAll("[data-close-threats-modal]");

    const openModal = () => {
        modal.classList.add("is-open");
        modal.setAttribute("aria-hidden", "false");
        document.body.classList.add("modal-open");
    };

    const closeModal = () => {
        modal.classList.remove("is-open");
        modal.setAttribute("aria-hidden", "true");
        document.body.classList.remove("modal-open");
    };

    trigger.addEventListener("click", openModal);
    closeButton?.addEventListener("click", closeModal);
    closeTargets.forEach((element) => element.addEventListener("click", closeModal));

    document.addEventListener("keydown", (event) => {
        if (event.key === "Escape" && modal.classList.contains("is-open")) {
            closeModal();
        }
    });
});
