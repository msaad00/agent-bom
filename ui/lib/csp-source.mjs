// Single source of truth for the inline scripts the dashboard ships with.
//
// `THEME_BOOTSTRAP_SCRIPT` is rendered inline via next/script in
// app/layout.tsx and its sha256 hash is added to script-src by
// lib/security-headers.mjs. If you edit the body of this script, you do not
// need to recompute the hash by hand — security-headers.mjs derives it from
// this same string. The vitest suite in tests/security-headers.test.ts pins
// the rendered CSP and the vercel.json sync test catches drift.
//
// Keep the script self-contained, ASCII, and short. Anything large should
// move into an external chunk under public/ so the CSP stays hash-only.

export const THEME_BOOTSTRAP_SCRIPT = `
(function () {
  try {
    var stored = localStorage.getItem("agent-bom-theme");
    var theme = stored === "light" || stored === "dark" ? stored : "dark";
    var root = document.documentElement;
    root.dataset.theme = theme;
    root.style.colorScheme = theme;
  } catch (error) {
    document.documentElement.dataset.theme = "dark";
    document.documentElement.style.colorScheme = "dark";
  }
})();
`;
