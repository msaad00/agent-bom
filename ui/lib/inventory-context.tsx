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
import type {
  InventoryAssetDetailResponse,
  InventoryAssetsResponse,
  InventorySummaryResponse,
} from "@/lib/api";
import { ApiAuthError, ApiError, ApiForbiddenError } from "@/lib/api-errors";
import {
  buildInventoryFromApi,
  mergeInventoryAssetPages,
  type InventoryModel,
} from "@/lib/inventory";

const INVENTORY_PAGE_SIZE = 100;

export type InventoryErrorKind = "network" | "auth" | "forbidden" | "empty";
export type InventoryFilterKey = "search" | "type" | "source" | "provider" | "environment" | "severity";

export interface InventoryFilters {
  search: string;
  type: string;
  source: string;
  provider: string;
  environment: string;
  severity: string;
}

const EMPTY_FILTERS: InventoryFilters = {
  search: "",
  type: "",
  source: "",
  provider: "",
  environment: "",
  severity: "",
};

export interface InventoryState {
  model: InventoryModel | null;
  summary: InventorySummaryResponse | null;
  page: InventoryAssetsResponse | null;
  filters: InventoryFilters;
  fixedEntityTypes: readonly string[];
  loading: boolean;
  loadingMore: boolean;
  hasMore: boolean;
  error: string;
  errorKind: InventoryErrorKind;
  details: Record<string, InventoryAssetDetailResponse>;
  detailLoadingId: string;
  detailError: string;
  setFilter: (key: InventoryFilterKey, value: string) => void;
  clearFilters: () => void;
  reload: () => void;
  loadMore: () => Promise<void>;
  loadAssetDetail: (assetId: string) => Promise<void>;
}

const InventoryContext = createContext<InventoryState | null>(null);

function classifyError(err: unknown): { message: string; kind: InventoryErrorKind } {
  if (err instanceof ApiAuthError) return { message: "Sign in to view the asset inventory.", kind: "auth" };
  if (err instanceof ApiForbiddenError) return { message: "Your role cannot read the asset inventory.", kind: "forbidden" };
  if (err instanceof ApiError && (err.status === 404 || err.status === 503)) {
    return {
      message: "No graph snapshot yet. Run a scan or connect an account to populate the asset inventory.",
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
  /** Route-owned asset taxonomy scope; every page and cursor keeps it. */
  entityTypes?: readonly string[] | undefined;
  /** Backward-compatible initial severity restored from the inventory URL. */
  minSeverity?: string | undefined;
}) {
  const [summary, setSummary] = useState<InventorySummaryResponse | null>(null);
  const [page, setPage] = useState<InventoryAssetsResponse | null>(null);
  const [filters, setFilters] = useState<InventoryFilters>({ ...EMPTY_FILTERS, severity: minSeverity ?? "" });
  const [loadingSummary, setLoadingSummary] = useState(true);
  const [loadingPage, setLoadingPage] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState("");
  const [errorKind, setErrorKind] = useState<InventoryErrorKind>("network");
  const [nonce, setNonce] = useState(0);
  const [details, setDetails] = useState<Record<string, InventoryAssetDetailResponse>>({});
  const [detailLoadingId, setDetailLoadingId] = useState("");
  const [detailError, setDetailError] = useState("");

  const reload = useCallback(() => setNonce((value) => value + 1), []);
  const entityTypesKey = (entityTypes ?? []).join(",");
  const fixedEntityTypes = useMemo(() => (entityTypesKey ? entityTypesKey.split(",") : []), [entityTypesKey]);

  useEffect(() => {
    setFilters((current) => ({ ...current, severity: minSeverity ?? "" }));
  }, [minSeverity]);

  useEffect(() => {
    let cancelled = false;
    setLoadingSummary(true);
    setLoadingPage(false);
    setSummary(null);
    setPage(null);
    setDetails({});
    setError("");
    api.getInventorySummary()
      .then((response) => {
        if (!cancelled) setSummary(response);
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        const classified = classifyError(err);
        setError(classified.message);
        setErrorKind(classified.kind);
      })
      .finally(() => {
        if (!cancelled) setLoadingSummary(false);
      });
    return () => {
      cancelled = true;
    };
  }, [nonce]);

  const requestedTypes = useMemo(() => {
    if (!filters.type) return fixedEntityTypes;
    if (fixedEntityTypes.length === 0 || fixedEntityTypes.includes(filters.type)) return [filters.type];
    return fixedEntityTypes;
  }, [filters.type, fixedEntityTypes]);

  const requestScope = useMemo(() => ({
    ...(requestedTypes.length > 0 ? { type: requestedTypes } : {}),
    ...(filters.search.trim() ? { search: filters.search.trim() } : {}),
    ...(filters.environment ? { environment: filters.environment } : {}),
    ...(filters.provider ? { provider: filters.provider } : {}),
    ...(filters.source ? { source: filters.source } : {}),
    ...(filters.severity ? { severity: filters.severity } : {}),
  }), [requestedTypes, filters]);

  useEffect(() => {
    if (!summary) return;
    let cancelled = false;
    setLoadingPage(true);
    setError("");
    api.getInventoryAssets({
      ...requestScope,
      scanId: summary.scan_id,
      limit: INVENTORY_PAGE_SIZE,
      offset: 0,
    })
      .then((response) => {
        if (!cancelled) setPage(response);
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        const classified = classifyError(err);
        setError(classified.message);
        setErrorKind(classified.kind);
      })
      .finally(() => {
        if (!cancelled) setLoadingPage(false);
      });
    return () => {
      cancelled = true;
    };
  }, [summary, requestScope]);

  const model = useMemo(() => (summary && page ? buildInventoryFromApi(summary, page) : null), [summary, page]);
  const hasMore = !loadingPage && Boolean(page?.pagination.has_more);
  const setFilter = useCallback((key: InventoryFilterKey, value: string) => {
    setFilters((current) => ({ ...current, [key]: value }));
  }, []);
  const clearFilters = useCallback(() => setFilters({ ...EMPTY_FILTERS, severity: minSeverity ?? "" }), [minSeverity]);

  const loadMore = useCallback(async () => {
    if (!summary || !page || !page.pagination.has_more || loadingPage || loadingMore) return;
    setLoadingMore(true);
    try {
      const next = await api.getInventoryAssets({
        ...requestScope,
        scanId: summary.scan_id,
        limit: INVENTORY_PAGE_SIZE,
        cursor: page.pagination.next_cursor,
      });
      setPage((current) => (current ? mergeInventoryAssetPages(current, next) : next));
    } catch (err: unknown) {
      const classified = classifyError(err);
      setError(classified.message);
      setErrorKind(classified.kind);
    } finally {
      setLoadingMore(false);
    }
  }, [summary, page, loadingPage, loadingMore, requestScope]);

  const loadAssetDetail = useCallback(async (assetId: string) => {
    if (!summary || details[assetId] || detailLoadingId === assetId) return;
    setDetailLoadingId(assetId);
    setDetailError("");
    try {
      const detail = await api.getInventoryAsset(assetId, summary.scan_id);
      setDetails((current) => ({ ...current, [assetId]: detail }));
    } catch (err: unknown) {
      setDetailError(classifyError(err).message);
    } finally {
      setDetailLoadingId("");
    }
  }, [summary, details, detailLoadingId]);

  const value = useMemo<InventoryState>(() => ({
    model,
    summary,
    page,
    filters,
    fixedEntityTypes,
    loading: loadingSummary || loadingPage,
    loadingMore,
    hasMore,
    error,
    errorKind,
    details,
    detailLoadingId,
    detailError,
    setFilter,
    clearFilters,
    reload,
    loadMore,
    loadAssetDetail,
  }), [model, summary, page, filters, fixedEntityTypes, loadingSummary, loadingPage, loadingMore, hasMore, error, errorKind, details, detailLoadingId, detailError, setFilter, clearFilters, reload, loadMore, loadAssetDetail]);

  return <InventoryContext.Provider value={value}>{children}</InventoryContext.Provider>;
}

export function useInventory(): InventoryState {
  const ctx = useContext(InventoryContext);
  if (!ctx) throw new Error("useInventory must be used within an InventoryProvider");
  return ctx;
}
