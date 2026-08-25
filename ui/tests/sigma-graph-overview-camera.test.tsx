import { render, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { SigmaGraphOverview } from "@/components/sigma-graph-overview";
import {
  readSigmaCameraPresentation,
  sigmaCameraStorageKey,
  writeSigmaCameraPresentation,
} from "@/lib/sigma-camera-presentation";

const harness = vi.hoisted(() => ({ instances: [] as Array<{
  camera: {
    state: { x: number; y: number; angle: number; ratio: number };
    setCalls: Array<Record<string, number>>;
    emit: (state: { x: number; y: number; angle: number; ratio: number }) => void;
  };
  killed: boolean;
}> }));

vi.mock("@/lib/use-capture-mode", () => ({ useCaptureMode: () => false }));
vi.mock("@/lib/graph-canvas-theme", () => ({
  useGraphCanvasPalette: () => ({
    defaultEdge: "#999999",
    defaultNode: "#777777",
    label: "#111111",
    selected: "#00ff00",
    dimmed: "#444444",
  }),
}));

vi.mock("sigma", () => {
  class CameraMock {
    state = { x: 0.5, y: 0.5, angle: 0, ratio: 1 };
    setCalls: Array<Record<string, number>> = [];
    listeners = new Set<(state: typeof this.state) => void>();

    setState(next: Partial<typeof this.state>) {
      this.setCalls.push({ ...next } as Record<string, number>);
      this.state = { ...this.state, ...next };
      return this;
    }

    on(event: string, listener: (state: typeof this.state) => void) {
      if (event === "updated") this.listeners.add(listener);
      return this;
    }

    emit(state: typeof this.state) {
      this.state = state;
      for (const listener of this.listeners) listener(state);
    }
  }

  return {
    default: class SigmaMock {
      camera = new CameraMock();
      killed = false;

      constructor() {
        harness.instances.push(this);
      }

      getCamera() { return this.camera; }
      on() { return this; }
      refresh() { return this; }
      kill() { this.killed = true; }
    },
  };
});

const scope = {
  tenantId: "tenant-a",
  subject: "viewer-a",
  snapshotId: "scan-a",
  lens: "estate",
  scope: "provider:aws",
};

const nodes = [
  { id: "agent:a", position: { x: 0, y: 0 }, data: { label: "Agent A", nodeType: "agent" as const } },
  { id: "package:a", position: { x: 100, y: 0 }, data: { label: "Package A", nodeType: "package" as const } },
];
const edges = [
  { id: "uses:a", source: "agent:a", target: "package:a", data: { relationship: "uses" } },
];

describe("SigmaGraphOverview camera persistence", () => {
  beforeEach(() => {
    harness.instances.length = 0;
    const values = new Map<string, string>();
    Object.defineProperty(window, "localStorage", {
      configurable: true,
      value: {
        get length() { return values.size; },
        clear: () => values.clear(),
        getItem: (key: string) => values.get(key) ?? null,
        key: (index: number) => [...values.keys()][index] ?? null,
        removeItem: (key: string) => { values.delete(key); },
        setItem: (key: string, value: string) => { values.set(key, value); },
      } satisfies Storage,
    });
  });

  it("restores a valid camera instead of applying the default framing", async () => {
    const saved = { x: 0.31, y: 0.67, angle: 0.2, ratio: 1.8 };
    writeSigmaCameraPresentation(
      window.localStorage,
      sigmaCameraStorageKey(scope),
      saved,
    );

    render(
      <SigmaGraphOverview
        nodes={nodes}
        edges={edges}
        legendItems={[]}
        presentationScope={scope}
      />,
    );

    await waitFor(() => expect(harness.instances).toHaveLength(1));
    expect(harness.instances[0]!.camera.setCalls).toEqual([saved]);
  });

  it("uses default framing for invalid state and persists the latest valid camera update", async () => {
    const key = sigmaCameraStorageKey(scope);
    window.localStorage.setItem(
      key,
      JSON.stringify({ version: 1, camera: { x: 0.5, y: 0.5, angle: 0, ratio: 99 } }),
    );

    render(
      <SigmaGraphOverview
        nodes={nodes}
        edges={edges}
        legendItems={[]}
        presentationScope={scope}
      />,
    );

    await waitFor(() => expect(harness.instances).toHaveLength(1));
    const instance = harness.instances[0]!;
    expect(instance.camera.setCalls).toEqual([{ ratio: 1.05 }]);

    const moved = { x: 0.22, y: 0.73, angle: 0.1, ratio: 1.45 };
    instance.camera.emit(moved);
    await waitFor(() => {
      expect(readSigmaCameraPresentation(window.localStorage, key)).toEqual(moved);
    });
  });

  it("does not read or write camera state when persistence is disabled", async () => {
    const key = sigmaCameraStorageKey(scope);
    const saved = { x: 0.31, y: 0.67, angle: 0.2, ratio: 1.8 };
    writeSigmaCameraPresentation(window.localStorage, key, saved);

    render(
      <SigmaGraphOverview
        nodes={nodes}
        edges={edges}
        legendItems={[]}
        presentationScope={scope}
        presentationEnabled={false}
      />,
    );

    await waitFor(() => expect(harness.instances).toHaveLength(1));
    const instance = harness.instances[0]!;
    expect(instance.camera.setCalls).toEqual([{ ratio: 1.05 }]);
    instance.camera.emit({ x: 0.9, y: 0.9, angle: 0, ratio: 2 });
    await new Promise((resolve) => window.setTimeout(resolve, 100));
    expect(readSigmaCameraPresentation(window.localStorage, key)).toEqual(saved);
  });
});
