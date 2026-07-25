"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  applyNodeChanges,
  type Node,
  type NodeChange,
  type OnNodeDrag,
  type OnMoveEnd,
} from "@xyflow/react";

import {
  applyGraphPresentation,
  graphPositions,
  graphPresentationStorageKey,
  readGraphPresentation,
  removeGraphPresentation,
  writeGraphPresentation,
  type GraphPresentationScope,
  type GraphPresentationState,
} from "@/lib/graph-presentation";

const DEFAULT_VIEWPORT = { x: 0, y: 0, zoom: 1 };

function browserStorage(): Storage | null {
  if (typeof window === "undefined") return null;
  try {
    return window.localStorage;
  } catch {
    return null;
  }
}

export function useGraphPresentation<T extends Node>({
  nodes,
  scope,
  layout,
  enabled = true,
}: {
  nodes: T[];
  scope: GraphPresentationScope;
  layout: string;
  enabled?: boolean;
}) {
  const storageKey = useMemo(() => graphPresentationStorageKey(scope), [scope]);
  const initialState = useMemo(
    () => (enabled ? readGraphPresentation(browserStorage(), storageKey) : null),
    [enabled, storageKey],
  );
  const [editing, setEditing] = useState(() => enabled && initialState?.locked === false);
  const [hasSavedState, setHasSavedState] = useState(() => Boolean(enabled && initialState));
  const accessibleNodes = useMemo(
    () =>
      nodes.map((node) => {
        const data = node.data as { label?: unknown; nodeType?: unknown };
        const label = typeof data.label === "string" ? data.label : node.id;
        const kind = typeof data.nodeType === "string" ? `, ${data.nodeType}` : "";
        return { ...node, ariaLabel: node.ariaLabel ?? `${label}${kind}` } as T;
      }),
    [nodes],
  );
  const [presentedNodes, setPresentedNodes] = useState<T[]>(() =>
    applyGraphPresentation(accessibleNodes, initialState?.layout === layout ? initialState : null),
  );
  const [viewport, setViewport] = useState(initialState?.viewport ?? DEFAULT_VIEWPORT);
  const nodesRef = useRef(presentedNodes);
  const viewportRef = useRef(viewport);

  useEffect(() => {
    nodesRef.current = presentedNodes;
  }, [presentedNodes]);
  useEffect(() => {
    viewportRef.current = viewport;
  }, [viewport]);

  useEffect(() => {
    const stored = enabled ? readGraphPresentation(browserStorage(), storageKey) : null;
    const compatible = stored?.layout === layout ? stored : null;
    const nextNodes = applyGraphPresentation(accessibleNodes, compatible);
    nodesRef.current = nextNodes;
    setPresentedNodes(nextNodes);
    const nextViewport = compatible?.viewport ?? DEFAULT_VIEWPORT;
    viewportRef.current = nextViewport;
    setViewport(nextViewport);
    setEditing(enabled && compatible?.locked === false);
    setHasSavedState(Boolean(enabled && compatible));
  }, [accessibleNodes, enabled, layout, storageKey]);

  const persist = useCallback(
    (overrides: Partial<GraphPresentationState> = {}) => {
      if (!enabled) return;
      writeGraphPresentation(browserStorage(), storageKey, {
        version: 1,
        positions: graphPositions(nodesRef.current),
        viewport: viewportRef.current,
        layout,
        locked: !editing,
        ...overrides,
      });
      setHasSavedState(true);
    },
    [editing, enabled, layout, storageKey],
  );

  const onNodesChange = useCallback(
    (changes: NodeChange<T>[]) => {
      const allowed = editing
        ? changes.filter((change) => change.type !== "remove")
        : changes.filter(
            (change) => change.type !== "position" && change.type !== "remove",
          );
      if (allowed.length === 0) return;
      setPresentedNodes((current) => {
        const next = applyNodeChanges(allowed, current) as T[];
        nodesRef.current = next;
        return next;
      });
    },
    [editing],
  );

  const onNodeDragStop = useCallback<OnNodeDrag<T>>(
    (_event, node) => {
      if (!editing) return;
      const next = nodesRef.current.map((current) =>
        current.id === node.id ? ({ ...current, position: node.position } as T) : current,
      );
      nodesRef.current = next;
      setPresentedNodes(next);
      persist({ positions: graphPositions(next), locked: false });
    },
    [editing, persist],
  );

  const onMoveEnd = useCallback<OnMoveEnd>(
    (_event, nextViewport) => {
      viewportRef.current = nextViewport;
      setViewport(nextViewport);
      persist({ viewport: nextViewport });
    },
    [persist],
  );

  const toggleEditing = useCallback(() => {
    setEditing((current) => {
      const next = !current;
      writeGraphPresentation(browserStorage(), storageKey, {
        version: 1,
        positions: graphPositions(nodesRef.current),
        viewport: viewportRef.current,
        layout,
        locked: !next,
      });
      setHasSavedState(true);
      return next;
    });
  }, [layout, storageKey]);

  const reset = useCallback(() => {
    removeGraphPresentation(browserStorage(), storageKey);
    nodesRef.current = accessibleNodes;
    setPresentedNodes(accessibleNodes);
    viewportRef.current = DEFAULT_VIEWPORT;
    setViewport(DEFAULT_VIEWPORT);
    setEditing(false);
    setHasSavedState(false);
  }, [accessibleNodes, storageKey]);

  const autoLayout = useCallback(() => {
    nodesRef.current = accessibleNodes;
    setPresentedNodes(accessibleNodes);
    if (enabled) {
      writeGraphPresentation(browserStorage(), storageKey, {
        version: 1,
        positions: {},
        viewport: viewportRef.current,
        layout,
        locked: !editing,
      });
      setHasSavedState(true);
    }
  }, [accessibleNodes, editing, enabled, layout, storageKey]);

  return {
    storageKey,
    nodes: presentedNodes,
    editing,
    hasSavedState,
    viewport,
    onNodesChange,
    onNodeDragStop,
    onMoveEnd,
    toggleEditing,
    reset,
    autoLayout,
  };
}
