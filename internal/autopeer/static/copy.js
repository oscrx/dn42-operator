// Copy buttons for everything marked data-copy (config blocks and values).
// Without JavaScript the pages work as before; this only adds the buttons.
(function () {
  // execCopy copies with the older API, which some browsers still allow
  // when the Clipboard API is denied.
  function execCopy(text) {
    var t = document.createElement("textarea");
    t.value = text;
    t.setAttribute("readonly", "");
    t.style.position = "fixed";
    t.style.opacity = "0";
    document.body.appendChild(t);
    t.select();
    var ok = false;
    try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
    document.body.removeChild(t);
    return ok;
  }
  function copy(text) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text).catch(function () {
        if (!execCopy(text)) { throw new Error("copy failed"); }
      });
    }
    return execCopy(text) ? Promise.resolve() : Promise.reject(new Error("copy failed"));
  }
  // selectText selects the element's text, so the user can copy it by hand.
  function selectText(el) {
    var r = document.createRange();
    r.selectNodeContents(el);
    var s = window.getSelection();
    s.removeAllRanges();
    s.addRange(r);
  }
  document.querySelectorAll("[data-copy]").forEach(function (el) {
    var b = document.createElement("button");
    b.type = "button";
    b.className = "copy";
    b.textContent = "Copy";
    b.setAttribute("aria-label", "Copy " + (el.getAttribute("data-copy") || "to the clipboard"));
    b.addEventListener("click", function () {
      copy(el.textContent.trim()).then(function () {
        b.textContent = "Copied";
      }, function () {
        selectText(el);
        b.textContent = "Selected: press Ctrl+C";
      });
      setTimeout(function () { b.textContent = "Copy"; }, 2000);
    });
    if (el.tagName === "PRE") {
      var wrap = document.createElement("div");
      wrap.className = "copywrap";
      el.parentNode.insertBefore(wrap, el);
      wrap.appendChild(el);
      wrap.appendChild(b);
    } else {
      el.insertAdjacentElement("afterend", b);
    }
  });
})();
