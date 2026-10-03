import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { createRequire } from "node:module";
import { test } from "node:test";

const require = createRequire(import.meta.url);
const pluginEntry = require.resolve("@next/eslint-plugin-next");
const pluginRequire = createRequire(pluginEntry);
const { getRootDirs } = pluginRequire("./utils/get-root-dirs.js");

// The override is intentionally limited to Next's globSync(directory pattern)
// use. Do not assume tinyglobby implements the complete fast-glob API.
test("Next root-dir discovery uses the maintained replacement without braces", () => {
  const installed = pluginRequire("fast-glob/package.json");
  assert.equal(installed.name, "tinyglobby");
  assert.equal(installed.version, "0.2.17");
  const lock = JSON.parse(readFileSync(new URL("../package-lock.json", import.meta.url), "utf8"));
  for (const [name, record] of Object.entries(lock.packages)) {
    assert.ok(!name.endsWith("/braces") && record.name !== "braces", "braces must not re-enter the UI dependency tree");
  }
});

test("Next root-dir discovery preserves directory, array, brace and separator semantics", () => {
  const root = mkdtempSync(path.join(tmpdir(), "agent-bom-next-glob-"));
  try {
    for (const name of ["apps/web", "apps/admin", "apps/.hidden", "packages/ui"]) mkdirSync(path.join(root, name), { recursive: true });
    writeFileSync(path.join(root, "apps", "readme.txt"), "fixture");
    // tinyglobby returns relative paths with trailing slashes for directories.
    // Next joins these with pages/app and reads the same filesystem locations.
    const normalized = value => path.resolve(value).replaceAll("\\", "/");
    const expected = ["apps/admin", "apps/web"].map(value => normalized(path.join(root, value))).sort();
    const discover = rootDir => getRootDirs({ cwd: root, settings: { next: { rootDir } } }).map(normalized).sort();
    assert.deepEqual(getRootDirs({ cwd: root, settings: {} }), [root]);
    assert.deepEqual(discover(path.join(root, "apps/*")), expected);
    assert.deepEqual(discover(path.join(root, "apps/{web,admin}")), expected);
    assert.deepEqual(discover([path.join(root, "apps/web"), path.join(root, "apps/admin"), null]), expected);
    assert.deepEqual(discover(path.join(root, "apps/*").replaceAll("/", "\\")), expected);
    assert.deepEqual(discover(path.join(root, "missing/*")), []);
    assert.deepEqual(discover(path.join(root, "apps/readme.txt")), []);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("Next still rejects an HTML link to a page discovered through a root glob", () => {
  const root = mkdtempSync(path.join(tmpdir(), "agent-bom-next-rule-"));
  try {
    const pages = path.join(root, "apps/web/pages");
    mkdirSync(pages, { recursive: true });
    writeFileSync(path.join(pages, "about.jsx"), "export default function About() { return null; }");
    const { Linter } = require("eslint");
    const linter = new Linter();
    const messages = linter.verify('const link = <a href="/about">About</a>;', [{
      files: ["**/*.jsx"],
      languageOptions: { ecmaVersion: "latest", sourceType: "module", parserOptions: { ecmaFeatures: { jsx: true } } },
      plugins: { "@next/next": require("@next/eslint-plugin-next") },
      settings: { next: { rootDir: path.join(root, "apps/*") } },
      rules: { "@next/next/no-html-link-for-pages": "error" },
    }], { filename: "fixture.jsx" });
    assert.equal(messages.length, 1);
    assert.equal(messages[0].ruleId, "@next/next/no-html-link-for-pages");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
