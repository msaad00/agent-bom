import fs from "node:fs";
import path from "node:path";

const root = process.cwd();
const packageJson = JSON.parse(
  fs.readFileSync(path.join(root, "package.json"), "utf8"),
);
const packageLock = JSON.parse(
  fs.readFileSync(path.join(root, "package-lock.json"), "utf8"),
);

function normalizeVersionRange(value) {
  return String(value ?? "").trim().replace(/^[~^]/, "");
}

function majorOf(value) {
  return Number.parseInt(normalizeVersionRange(value).split(".")[0] ?? "", 10);
}

function fail(message) {
  console.error(`::error::${message}`);
  process.exit(1);
}

const nextDeclared = packageJson.dependencies?.next;
const eslintConfigNextDeclared = packageJson.devDependencies?.["eslint-config-next"];
const eslintDeclared = packageJson.devDependencies?.eslint;
const reactDeclared = packageJson.dependencies?.react;
const reactDomDeclared = packageJson.dependencies?.["react-dom"];

if (!nextDeclared || !eslintConfigNextDeclared || !eslintDeclared) {
  fail("UI toolchain contract is incomplete: next, eslint-config-next, and eslint must all be declared.");
}

if (normalizeVersionRange(nextDeclared) !== normalizeVersionRange(eslintConfigNextDeclared)) {
  fail(
    `next (${nextDeclared}) and eslint-config-next (${eslintConfigNextDeclared}) must stay on the same tested version.`,
  );
}

if (reactDeclared !== reactDomDeclared) {
  fail(`react (${reactDeclared}) and react-dom (${reactDomDeclared}) must remain version-aligned.`);
}

const nextInstalled = packageLock.packages?.["node_modules/next"]?.version;
const eslintConfigNextInstalled =
  packageLock.packages?.["node_modules/eslint-config-next"]?.version;
const eslintInstalled = packageLock.packages?.["node_modules/eslint"]?.version;

if (!nextInstalled || !eslintConfigNextInstalled || !eslintInstalled) {
  fail("package-lock.json is missing installed versions for next, eslint-config-next, or eslint.");
}

if (nextInstalled !== eslintConfigNextInstalled) {
  fail(
    `Installed next (${nextInstalled}) and eslint-config-next (${eslintConfigNextInstalled}) are out of sync.`,
  );
}

const nextMajor = majorOf(nextInstalled);
const eslintMajor = majorOf(eslintInstalled);

// Next.js 16.2.x is the currently validated lint toolchain for this repo.
// The repo broke when eslint was allowed to float to 10.x, so keep this
// explicit until the UI has been validated against a newer major.
if (nextMajor === 16 && eslintMajor !== 9) {
  fail(
    `Next.js ${nextInstalled} is only validated in this repo with ESLint 9.x; found eslint ${eslintInstalled}.`,
  );
}

console.log(
  `UI toolchain contract verified: next ${nextInstalled}, eslint-config-next ${eslintConfigNextInstalled}, eslint ${eslintInstalled}.`,
);
