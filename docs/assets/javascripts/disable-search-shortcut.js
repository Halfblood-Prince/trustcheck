(() => {
  function isEditableTarget(target) {
    if (!(target instanceof Element)) {
      return false;
    }

    return Boolean(
      target.closest(
        [
          "input",
          "textarea",
          "select",
          "[contenteditable='']",
          "[contenteditable='true']",
          "[role='textbox']",
        ].join(","),
      ),
    );
  }

  document.addEventListener(
    "keydown",
    (event) => {
      if (event.defaultPrevented) {
        return;
      }

      if (event.key.toLowerCase() !== "s") {
        return;
      }

      if (event.altKey || event.ctrlKey || event.metaKey) {
        return;
      }

      if (!isEditableTarget(event.target)) {
        return;
      }

      // Stop Material for MkDocs from treating "s" as a global search shortcut
      // while the user is actively typing in an editable control.
      event.stopPropagation();
    },
    true,
  );
})();
