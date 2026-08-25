import type { CameraState } from "sigma/types";

import {
  graphPresentationStorageKey,
  type GraphPresentationScope,
} from "@/lib/graph-presentation";

export type SigmaCameraState = Pick<CameraState, "x" | "y" | "angle" | "ratio">;

type SigmaCameraPresentationState = {
  version: 1;
  camera: SigmaCameraState;
};

type StorageAdapter = Pick<Storage, "getItem" | "setItem">;

const MAX_COORDINATE = 10_000_000;
const MIN_RATIO = 0.04;
const MAX_RATIO = 4;

function finiteCoordinate(value: unknown): number | null {
  return typeof value === "number" &&
    Number.isFinite(value) &&
    Math.abs(value) <= MAX_COORDINATE
    ? value
    : null;
}

/**
 * Camera state uses the same opaque, owner/snapshot/lens/scope key material as
 * React Flow presentation state, but a distinct suffix prevents the two
 * renderer schemas from overwriting one another.
 */
export function sigmaCameraStorageKey(scope: GraphPresentationScope): string {
  return `${graphPresentationStorageKey(scope)}:sigma-camera`;
}

export function sanitizeSigmaCameraState(value: unknown): SigmaCameraState | null {
  if (!value || typeof value !== "object") return null;
  const candidate = value as Partial<SigmaCameraState>;
  const x = finiteCoordinate(candidate.x);
  const y = finiteCoordinate(candidate.y);
  const angle = finiteCoordinate(candidate.angle);
  const ratio = candidate.ratio;
  if (
    x === null ||
    y === null ||
    angle === null ||
    typeof ratio !== "number" ||
    !Number.isFinite(ratio) ||
    ratio < MIN_RATIO ||
    ratio > MAX_RATIO
  ) {
    return null;
  }
  return { x, y, angle, ratio };
}

export function readSigmaCameraPresentation(
  storage: StorageAdapter | null | undefined,
  key: string,
): SigmaCameraState | null {
  if (!storage) return null;
  try {
    const raw = storage.getItem(key);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<SigmaCameraPresentationState>;
    if (parsed.version !== 1) return null;
    return sanitizeSigmaCameraState(parsed.camera);
  } catch {
    return null;
  }
}

export function writeSigmaCameraPresentation(
  storage: StorageAdapter | null | undefined,
  key: string,
  camera: SigmaCameraState,
): boolean {
  if (!storage) return false;
  const sanitized = sanitizeSigmaCameraState(camera);
  if (!sanitized) return false;
  try {
    storage.setItem(
      key,
      JSON.stringify({ version: 1, camera: sanitized } satisfies SigmaCameraPresentationState),
    );
    return true;
  } catch {
    return false;
  }
}
