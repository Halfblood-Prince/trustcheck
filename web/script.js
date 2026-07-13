const header = document.querySelector("[data-header]");
const nav = document.querySelector("[data-nav]");
const navToggle = document.querySelector("[data-nav-toggle]");
const themeToggle = document.querySelector("[data-theme-toggle]");
const year = document.querySelector("[data-year]");
const root = document.documentElement;
const themeStorageKey = "trustcheck-theme";
const preferredDark = window.matchMedia("(prefers-color-scheme: dark)");

const storedTheme = () => {
  try {
    const value = window.localStorage.getItem(themeStorageKey);
    return value === "dark" || value === "light" ? value : null;
  } catch {
    return null;
  }
};

const saveTheme = (theme) => {
  try {
    window.localStorage.setItem(themeStorageKey, theme);
  } catch {
    return;
  }
};

const systemTheme = () => (preferredDark.matches ? "dark" : "light");

const applyTheme = (theme) => {
  root.dataset.theme = theme;
  root.style.colorScheme = theme;

  if (themeToggle instanceof HTMLButtonElement) {
    const isDark = theme === "dark";
    const nextMode = isDark ? "light" : "dark";
    themeToggle.setAttribute("aria-checked", isDark.toString());
    themeToggle.setAttribute("aria-label", `Switch to ${nextMode} mode`);
    themeToggle.title = `Switch to ${nextMode} mode`;
  }
};

applyTheme(storedTheme() || systemTheme());

if (year) {
  year.textContent = new Date().getFullYear().toString();
}

if (header) {
  const updateHeader = () => {
    header.classList.toggle("is-scrolled", window.scrollY > 8);
  };

  updateHeader();
  window.addEventListener("scroll", updateHeader, { passive: true });
}

if (nav && navToggle) {
  navToggle.setAttribute("aria-expanded", "false");

  navToggle.addEventListener("click", () => {
    const expanded = nav.classList.toggle("is-open");
    navToggle.setAttribute("aria-expanded", expanded.toString());
  });

  nav.addEventListener("click", (event) => {
    if (event.target instanceof HTMLAnchorElement) {
      nav.classList.remove("is-open");
      navToggle.setAttribute("aria-expanded", "false");
    }
  });
}

if (themeToggle instanceof HTMLButtonElement) {
  themeToggle.addEventListener("click", () => {
    const nextTheme = root.dataset.theme === "dark" ? "light" : "dark";
    applyTheme(nextTheme);
    saveTheme(nextTheme);
  });
}

preferredDark.addEventListener("change", () => {
  if (!storedTheme()) {
    applyTheme(systemTheme());
  }
});

document.querySelectorAll("[data-copy]").forEach((button) => {
  button.addEventListener("click", async () => {
    if (!(button instanceof HTMLButtonElement)) {
      return;
    }

    const command = button.dataset.copy;
    if (!command || !navigator.clipboard) {
      return;
    }

    const original = button.textContent;
    try {
      await navigator.clipboard.writeText(command);
      button.textContent = "Copied";
    } catch {
      button.textContent = "Copy failed";
    } finally {
      window.setTimeout(() => {
        button.textContent = original;
      }, 1600);
    }
  });
});
