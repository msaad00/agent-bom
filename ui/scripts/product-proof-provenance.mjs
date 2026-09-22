// Shared "what counts as a release product-proof input" definition and
// hashing logic, used by:
//   - capture-product-proof.mjs (the real capture run — bundles this digest
//     with source_commit/source_tree from that run)
//   - refresh-capture-inputs-digest.mjs (recomputes ONLY the digest, for when
//     the counted input set changes but no screenshot needs re-capturing)
//   - scripts/check_release_consistency.py (a byte-for-byte Python mirror of
//     this same algorithm — keep both in sync on any change here)
//
// Scope is deliberately narrow: only paths that can affect a rendered/
// screenshotted pixel belong here. Lockfiles, tests, and tooling config
// cannot change what a screenshot shows and must stay OUT, or every
// dependency bump and config tweak re-trips release CI for no reason.
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export const PRODUCT_SCREENSHOT_INPUTS = [
  "ui/app",
  "ui/components",
  "ui/hooks",
  "ui/lib",
  "ui/public",
  "ui/server",
  "ui/fixtures",
  "ui/next.config.ts",
  "ui/postcss.config.mjs",
  "ui/scripts/capture-product-proof.mjs",
  "ui/scripts/product-proof-scope.mjs",
  "ui/scripts/product-proof-server.mjs",
  "ui/scripts/product-proof-provenance.mjs",
  "examples/reference-evidence-lab",
  "scripts/generate_reference_evidence_lab.py",
];

// Defensive: none of the directories above currently contain colocated
// tests, but if one is ever added it must not silently start counting.
const TEST_FILE_PATTERN = /(?:^|\/)(?:tests|e2e)\/|\.(?:test|spec)\.[jt]sx?$/;

/**
 * Hash the "dependencies" object of ui/package.json as a single virtual
 * input. devDependencies, scripts, and every other field are excluded on
 * purpose: they cannot affect what a browser renders. package-lock.json is
 * excluded too — see the PR description for the accepted trade-off.
 */
async function dependenciesDigestEntry(repoRoot) {
  const packageJsonPath = path.join(repoRoot, "ui", "package.json");
  const packageJson = JSON.parse(await fs.readFile(packageJsonPath, "utf8"));
  const dependencies = packageJson.dependencies ?? {};
  const lines = Object.keys(dependencies)
    .sort()
    .map((name) => `${name}=${dependencies[name]}`)
    .join("\n");
  return { label: "ui/package.json#dependencies", content: Buffer.from(lines, "utf8") };
}

/** Recompute the capture-inputs digest for the current working tree. */
export async function computeCaptureInputsDigest(repoRoot) {
  const { stdout: trackedOutput } = await execFileAsync(
    "git",
    ["ls-files", "-z", "--", ...PRODUCT_SCREENSHOT_INPUTS],
    { cwd: repoRoot, encoding: "buffer" },
  );
  const digest = createHash("sha256");
  const trackedPaths = trackedOutput
    .toString("utf8")
    .split("\0")
    .filter(Boolean)
    .filter((relativePath) => !TEST_FILE_PATTERN.test(relativePath))
    .sort();
  for (const relativePath of trackedPaths) {
    digest.update(relativePath);
    digest.update("\0");
    digest.update(await fs.readFile(path.join(repoRoot, relativePath)));
    digest.update("\0");
  }
  const dependenciesEntry = await dependenciesDigestEntry(repoRoot);
  digest.update(dependenciesEntry.label);
  digest.update("\0");
  digest.update(dependenciesEntry.content);
  digest.update("\0");
  return `sha256:${digest.digest("hex")}`;
}

/** Full provenance for a real capture run: commit + tree state + inputs digest. */
export async function captureSourceProvenance(repoRoot) {
  const [{ stdout: commit }, { stdout: status }] = await Promise.all([
    execFileAsync("git", ["rev-parse", "HEAD"], { cwd: repoRoot }),
    execFileAsync("git", ["status", "--porcelain"], { cwd: repoRoot }),
  ]);
  if (status.trim()) {
    throw new Error("Release product proof requires a clean committed source tree, including no untracked inputs");
  }
  return {
    source_commit: commit.trim(),
    source_tree: "clean",
    capture_inputs_sha256: await computeCaptureInputsDigest(repoRoot),
  };
}
