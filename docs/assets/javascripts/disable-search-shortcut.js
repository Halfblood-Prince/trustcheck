(() => {
  document.addEventListener(
    "keydown",
    (event) => {
      const key = event.key.toLowerCase();
      if (key !== "s" && key !== "n") {
        return;
      }

      if (event.altKey || event.ctrlKey || event.metaKey) {
        return;
      }

      if (event.shiftKey) {
        return;
      }

      // Material for MkDocs uses plain letter hotkeys like "s" and "n" that can
      // steal focus from embedded widgets. We disable those hotkeys entirely
      // while still allowing the characters to be typed normally.
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
