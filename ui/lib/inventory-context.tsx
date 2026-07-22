"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

import { api } from "@/lib/api";
import type { UnifiedGraphResponse } from "@/lib/api-types";
import { ApiAuthError, ApiError, ApiForbiddenError } from "@/lib/api-errors";
import { buildInventory, mergeGraphPages, type InventoryModel } from "@/lib/inventory";

// First page for the Inventory section. The graph is the canonical correlation
// fabric — one read gives every asset kind plus finding neighbors. Follow
// pagination.has_more / next_cursor instead of a silent hard cap.
const GRAPH_NODE_PAGE = 500;

export type InventoryErrorKind = "network" | "auth" | "forbidden" | "empty";

export interface InventoryState {
  model: InventoryModel | null;
  loading: boolean;
  loadingMore: boolean;
  hasMore: boolean;
  error: string;
  errorKind: InventoryErrorKind;
  reload: () => void;
  loadMore: () => Promise<void>;
}

const InventoryContext = createContext<InventoryState | null>(null);

function classifyError(err: unknown): { message: string; kind: InventoryErrorKind } {
  if (err instanceof ApiAuthError) {
    return { message: "Sign in to view the asset inventory.", kind: "auth" };
  }
  if (err instanceof ApiForbiddenError) {
    return { message: "Your role cannot read the asset inventory.", kind: "forbidden" };
  }
  if (err instanceof ApiError && (err.status === 404 || err.status === 503)) {
    return {
      message:
        "No graph snapshot yet. Run a scan or connect an account to populate the asset inventory.",
      kind: "empty",
    };
  }
  return {
    message: err instanceof Error ? err.message : "Unable to load the asset inventory.",
    kind: "network",
  };
}

export function InventoryProvider({ children }: { children: ReactNode }) {
  const [graph, setGraph] = useState<UnifiedGraphResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState("");
  const [errorKind, setErrorKind] = useState<InventoryErrorKind>("network");
  const [nonce, setNonce] = useState(0);

  const reload = useCallback(() => setNonce((value) => value + 1), []);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setLoadingMore(false);
    setError("");
    setGraph(null);
    api
      .getGraph({ limit: GRAPH_NODE_PAGE, offset: 0 })
      .then((page) => {
        if (cancelled) return;
        setGraph(page);
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        const classified = classifyError(err);
        setGraph(null);
        setError(classified.message);
        setErrorKind(classified.kind);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [nonce]);

  const hasMore = Boolean(graph?.pagination?.has_more);
  const model = useMemo(() => (graph ? buildInventory(graph) : null), [graph]);

  const loadMore = useCallback(async () => {
    if (!graph || !graph.pagination?.has_more || loadingMore) return;
    setLoadingMore(true);
    try {
      const nextCursor = graph.pagination.next_cursor?.trim();
      const nextPage = nextCursor
        ? await api.getGraph({ limit: GRAPH_NODE_PAGE, cursor: nextCursor })
        : await api.getGraph({
            limit: GRAPH_NODE_PAGE,
            offset: (graph.pagination.offset ?? 0) + (graph.pagination.limit ?? GRAPH_NODE_PAGE),
          });
      setGraph((current) => (current ? mergeGraphPages(current, nextPage) : nextPage));
    } catch (err: unknown) {
      const classified = classifyError(err);
      setError(classified.message);
      setErrorKind(classified.kind);
    } finally {
      setLoadingMore(false);
    }
  }, [graph, loadingMore]);

  const value = useMemo<InventoryState>(
    () => ({
      model,
      loading,
      loadingMore,
      hasMore,
      error,
      errorKind,
      reload,
      loadMore,
    }),
    [model, loading, loadingMore, hasMore, error, errorKind, reload, loadMore],
  );

  return <InventoryContext.Provider value={value}>{children}</InventoryContext.Provider>;
}

export function useInventory(): InventoryState {
  const ctx = useContext(InventoryContext);
  if (!ctx) {
    throw new Error("useInventory must be used within an InventoryProvider");
  }
  return ctx;
}
