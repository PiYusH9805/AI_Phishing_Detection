document.addEventListener("DOMContentLoaded", () => {
    // Lightweight animation controller for counters, reveal-on-scroll, and interaction polish.
    document.body.classList.add("js-animate");
    const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const animatedCounters = new WeakSet();

    const revealTargets = Array.from(
        document.querySelectorAll(
            ".glass-panel, .metric-chip, .progress-card, .history-row, .simulation-card, .stat-box, .flash-card"
        )
    );

    const counterTargets = Array.from(document.querySelectorAll("[data-counter-target]"));

    const animateCounter = (element) => {
        if (animatedCounters.has(element)) {
            return;
        }

        const target = Number(element.dataset.counterTarget);
        if (!Number.isFinite(target)) {
            return;
        }

        animatedCounters.add(element);

        if (prefersReducedMotion) {
            element.textContent = String(target);
            return;
        }

        const duration = 1200;
        const start = performance.now();

        const tick = (now) => {
            const progress = Math.min((now - start) / duration, 1);
            const eased = 1 - Math.pow(1 - progress, 3);
            element.textContent = String(Math.round(target * eased));

            if (progress < 1) {
                window.requestAnimationFrame(tick);
            } else {
                element.textContent = String(target);
            }
        };

        element.textContent = "0";
        window.requestAnimationFrame(tick);
    };

    const addInteractivePress = (element) => {
        element.addEventListener("pointerdown", () => {
            element.classList.add("is-pressed");
        });

        const clearPressed = () => element.classList.remove("is-pressed");
        element.addEventListener("pointerup", clearPressed);
        element.addEventListener("pointerleave", clearPressed);
        element.addEventListener("pointercancel", clearPressed);
    };

    document
        .querySelectorAll(".ghost-button, .primary-button, .tab-button, .table-action, .theme-toggle")
        .forEach(addInteractivePress);

    if (prefersReducedMotion) {
        revealTargets.forEach((target) => target.classList.add("in-view"));
        counterTargets.forEach(animateCounter);
        return;
    }

    const revealObserver = new IntersectionObserver(
        (entries, observer) => {
            entries.forEach((entry) => {
                if (!entry.isIntersecting) {
                    return;
                }

                entry.target.classList.add("in-view");
                observer.unobserve(entry.target);
            });
        },
        { threshold: 0.12, rootMargin: "0px 0px -8% 0px" }
    );

    revealTargets.forEach((target, index) => {
        target.style.setProperty("--reveal-delay", `${Math.min(index * 45, 260)}ms`);
        revealObserver.observe(target);
    });

    const counterObserver = new IntersectionObserver(
        (entries, observer) => {
            entries.forEach((entry) => {
                if (!entry.isIntersecting) {
                    return;
                }

                animateCounter(entry.target);
                observer.unobserve(entry.target);
            });
        },
        { threshold: 0.4 }
    );

    counterTargets.forEach((counter) => counterObserver.observe(counter));
});
