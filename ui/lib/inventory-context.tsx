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

export function InventoryProvider({
  children,
  entityTypes,
  minSeverity,
}: {
  children: ReactNode;
  /** Scope the read to one asset kind's graph entity types.
   *
   * Omitted on the index page, which needs every kind at once and takes its
   * card counts from `stats.node_types` rather than from the rows.
   *
   * Supplied on an asset-type page, because a ranked page of the estate is not
   * a page of THAT type: agents, MCP servers and container images all rank
   * below a misconfiguration-dominated cut, so those pages rendered "nothing
   * discovered yet" while their own card advertised hundreds. */
  entityTypes?: readonly string[] | undefined;
  /** Server-owned minimum severity from the inventory URL. */
  minSeverity?: string | undefined;
}) {
  const [graph, setGraph] = useState<UnifiedGraphResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState("");
  const [errorKind, setErrorKind] = useState<InventoryErrorKind>("network");
  const [nonce, setNonce] = useState(0);

  const reload = useCallback(() => setNonce((value) => value + 1), []);
  // Stable dependency: the array identity changes on every render, the
  // membership does not.
  const entityTypesKey = (entityTypes ?? []).join(",");
  const scopedEntityTypes = useMemo(
    () => (entityTypesKey ? entityTypesKey.split(",") : []),
    [entityTypesKey],
  );

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setLoadingMore(false);
    setError("");
    setGraph(null);
    api
      .getGraph({
        limit: GRAPH_NODE_PAGE,
        offset: 0,
        ...(scopedEntityTypes.length > 0 ? { entityTypes: scopedEntityTypes } : {}),
        ...(minSeverity ? { minSeverity } : {}),
      })
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
  }, [nonce, scopedEntityTypes, minSeverity]);

  const hasMore = Boolean(graph?.pagination?.has_more);
  const model = useMemo(() => (graph ? buildInventory(graph) : null), [graph]);

  const loadMore = useCallback(async () => {
    if (!graph || !graph.pagination?.has_more || loadingMore) return;
    setLoadingMore(true);
    try {
      const nextCursor = graph.pagination.next_cursor?.trim();
      // The scope has to travel with the page. Without it the second page
      // widens back to a ranked read of the whole estate, so a kind page would
      // start correct and then fill with other people's rows.
      const scope = {
        ...(scopedEntityTypes.length > 0 ? { entityTypes: scopedEntityTypes } : {}),
        ...(minSeverity ? { minSeverity } : {}),
      };
      const nextPage = nextCursor
        ? await api.getGraph({ limit: GRAPH_NODE_PAGE, cursor: nextCursor, ...scope })
        : await api.getGraph({
            limit: GRAPH_NODE_PAGE,
            offset: (graph.pagination.offset ?? 0) + (graph.pagination.limit ?? GRAPH_NODE_PAGE),
            ...scope,
          });
      setGraph((current) => (current ? mergeGraphPages(current, nextPage) : nextPage));
    } catch (err: unknown) {
      const classified = classifyError(err);
      setError(classified.message);
      setErrorKind(classified.kind);
    } finally {
      setLoadingMore(false);
    }
  }, [graph, loadingMore, scopedEntityTypes, minSeverity]);

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
