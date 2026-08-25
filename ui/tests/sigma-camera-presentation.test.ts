import { describe, expect, it } from "vitest";

import {
  readSigmaCameraPresentation,
  sanitizeSigmaCameraState,
  sigmaCameraStorageKey,
  writeSigmaCameraPresentation,
} from "@/lib/sigma-camera-presentation";

const scope = {
  tenantId: "tenant-private",
  subject: "viewer@example.test",
  snapshotId: "snapshot-private",
  lens: "estate",
  scope: "provider:aws",
};

function storageAdapter() {
  const values = new Map<string, string>();
  return {
    values,
    adapter: {
      getItem: (key: string) => values.get(key) ?? null,
      setItem: (key: string, value: string) => { values.set(key, value); },
    },
  };
}

describe("Sigma camera presentation", () => {
  it("uses an opaque renderer-specific key scoped by owner, snapshot, lens, and scope", () => {
    const key = sigmaCameraStorageKey(scope);
    expect(key).toMatch(/^agent-bom:graph-presentation:v1:[a-f0-9]{16}:sigma-camera$/);
    expect(key).not.toContain(scope.tenantId);
    expect(key).not.toContain(scope.subject);
    expect(key).not.toContain(scope.snapshotId);
    expect(key).not.toContain(scope.scope);
    expect(sigmaCameraStorageKey({ ...scope, lens: "identity" })).not.toBe(key);
  });

  it("round-trips a finite camera without storing graph identifiers", () => {
    const { values, adapter } = storageAdapter();
    const key = sigmaCameraStorageKey(scope);
    const camera = { x: 0.42, y: 0.61, angle: 0.25, ratio: 1.7 };

    expect(writeSigmaCameraPresentation(adapter, key, camera)).toBe(true);
    expect(readSigmaCameraPresentation(adapter, key)).toEqual(camera);
    expect(values.get(key)).not.toContain(scope.tenantId);
    expect(values.get(key)).not.toContain(scope.snapshotId);
  });

  it.each([
    null,
    {},
    { x: 0.5, y: 0.5, angle: 0, ratio: 0.01 },
    { x: 0.5, y: 0.5, angle: 0, ratio: 5 },
    { x: "0.5", y: 0.5, angle: 0, ratio: 1 },
    { x: 0.5, y: 0.5, angle: Number.POSITIVE_INFINITY, ratio: 1 },
  ])("rejects invalid camera state %#", (camera) => {
    expect(sanitizeSigmaCameraState(camera)).toBeNull();
  });

  it("treats malformed and unsupported persisted envelopes as absent", () => {
    const { values, adapter } = storageAdapter();
    const key = sigmaCameraStorageKey(scope);
    values.set(key, "not-json");
    expect(readSigmaCameraPresentation(adapter, key)).toBeNull();
    values.set(key, JSON.stringify({ version: 2, camera: { x: 0.5, y: 0.5, angle: 0, ratio: 1 } }));
    expect(readSigmaCameraPresentation(adapter, key)).toBeNull();
    values.set(key, JSON.stringify({ version: 1, camera: { x: 0.5, y: 0.5, angle: 0, ratio: 99 } }));
    expect(readSigmaCameraPresentation(adapter, key)).toBeNull();
  });
});
