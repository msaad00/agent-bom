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
  purgeGraphPresentationsForOwner,
  readGraphPresentation,
  registerGraphPresentationKey,
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
  ownerActive = true,
  localMode = false,
}: {
  nodes: T[];
  scope: GraphPresentationScope;
  layout: string;
  enabled?: boolean;
  ownerActive?: boolean;
  localMode?: boolean;
}) {
  const persistenceEnabled = enabled && ownerActive && (
    localMode || (scope.tenantId !== "local" && scope.subject !== "local-viewer")
  );
  const storageKey = useMemo(() => graphPresentationStorageKey(scope), [scope]);
  const initialState = useMemo(
    () => (persistenceEnabled ? readGraphPresentation(browserStorage(), storageKey) : null),
    [persistenceEnabled, storageKey],
  );
  const [editing, setEditing] = useState(() => persistenceEnabled && initialState?.locked === false);
  const [hasSavedState, setHasSavedState] = useState(() => Boolean(persistenceEnabled && initialState));
  const accessibleNodes = useMemo(
    () =>
      nodes.map((node) => {
        const data = node.data as { label?: unknown; nodeType?: unknown };
        const label = typeof data.label === "string" ? data.label : "Graph node";
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
  const ownerRef = useRef(`${scope.tenantId}\u0000${scope.subject}`);
  const wasOwnerActiveRef = useRef(ownerActive);

  useEffect(() => {
    const owner = `${scope.tenantId}\u0000${scope.subject}`;
    const ownerChanged = ownerRef.current !== owner;
    if ((ownerChanged || (!ownerActive && wasOwnerActiveRef.current)) && wasOwnerActiveRef.current) {
      const [previousTenant, previousSubject] = ownerRef.current.split("\u0000");
      purgeGraphPresentationsForOwner(browserStorage(), previousTenant ?? "", previousSubject ?? "");
    }
    ownerRef.current = owner;
    wasOwnerActiveRef.current = ownerActive;
  }, [ownerActive, scope.subject, scope.tenantId, storageKey]);

  useEffect(() => {
    nodesRef.current = presentedNodes;
  }, [presentedNodes]);
  useEffect(() => {
    viewportRef.current = viewport;
  }, [viewport]);

  useEffect(() => {
    const stored = persistenceEnabled ? readGraphPresentation(browserStorage(), storageKey) : null;
    const compatible = stored?.layout === layout ? stored : null;
    const nextNodes = applyGraphPresentation(accessibleNodes, compatible);
    nodesRef.current = nextNodes;
    setPresentedNodes(nextNodes);
    const nextViewport = compatible?.viewport ?? DEFAULT_VIEWPORT;
    viewportRef.current = nextViewport;
    setViewport(nextViewport);
    setEditing(persistenceEnabled && compatible?.locked === false);
    setHasSavedState(Boolean(persistenceEnabled && compatible));
  }, [accessibleNodes, layout, persistenceEnabled, storageKey]);

  const persist = useCallback(
    (overrides: Partial<GraphPresentationState> = {}) => {
      if (!persistenceEnabled) return;
      registerGraphPresentationKey(browserStorage(), scope, storageKey);
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
    [editing, layout, persistenceEnabled, scope, storageKey],
  );

  const onNodesChange = useCallback(
    (changes: NodeChange<T>[]) => {
      if (!persistenceEnabled) return;
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
    [editing, persistenceEnabled],
  );

  const onNodeDragStop = useCallback<OnNodeDrag<T>>(
    (_event, node) => {
      if (!persistenceEnabled || !editing) return;
      const next = nodesRef.current.map((current) =>
        current.id === node.id ? ({ ...current, position: node.position } as T) : current,
      );
      nodesRef.current = next;
      setPresentedNodes(next);
      persist({ positions: graphPositions(next), locked: false });
    },
    [editing, persist, persistenceEnabled],
  );

  const onMoveEnd = useCallback<OnMoveEnd>(
    (_event, nextViewport) => {
      if (!persistenceEnabled) return;
      viewportRef.current = nextViewport;
      setViewport(nextViewport);
      persist({ viewport: nextViewport });
    },
    [persist, persistenceEnabled],
  );

  const toggleEditing = useCallback(() => {
    if (!persistenceEnabled) return;
    setEditing((current) => {
      const next = !current;
      registerGraphPresentationKey(browserStorage(), scope, storageKey);
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
  }, [layout, persistenceEnabled, scope, storageKey]);

  const reset = useCallback(() => {
    if (!persistenceEnabled) return;
    removeGraphPresentation(browserStorage(), storageKey);
    nodesRef.current = accessibleNodes;
    setPresentedNodes(accessibleNodes);
    viewportRef.current = DEFAULT_VIEWPORT;
    setViewport(DEFAULT_VIEWPORT);
    setEditing(false);
    setHasSavedState(false);
  }, [accessibleNodes, persistenceEnabled, storageKey]);

  const autoLayout = useCallback(() => {
    if (!persistenceEnabled) return;
    nodesRef.current = accessibleNodes;
    setPresentedNodes(accessibleNodes);
    registerGraphPresentationKey(browserStorage(), scope, storageKey);
    writeGraphPresentation(browserStorage(), storageKey, {
      version: 1,
      positions: {},
      viewport: viewportRef.current,
      layout,
      locked: !editing,
    });
    setHasSavedState(true);
  }, [accessibleNodes, editing, layout, persistenceEnabled, scope, storageKey]);

  return {
    storageKey,
    enabled: persistenceEnabled,
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
