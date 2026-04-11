(() => {
  document.addEventListener(
    "keydown",
    (event) => {
      if (event.key.toLowerCase() !== "s") {
        return;
      }

      if (event.altKey || event.ctrlKey || event.metaKey) {
        return;
      }

      if (event.shiftKey) {
        return;
      }

      // Material for MkDocs uses plain "s" as a global shortcut that can steal
      // focus from embedded widgets. We disable that hotkey entirely while
      // still allowing the "s" character to be typed normally.
      event.stopImmediatePropagation();
    },
    true,
  );

  window.addEventListener("load", () => {
    const search = document.querySelector("[data-md-component='search-query']");
    if (search instanceof HTMLElement) {
      search.removeAttribute("accesskey");
    }
  });
})();
