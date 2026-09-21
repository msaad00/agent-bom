"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
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
  type InventoryModel,
} from "@/lib/inventory";

const INVENTORY_PAGE_SIZE = 100;

export type InventoryErrorKind = "network" | "auth" | "forbidden" | "empty";
export type InventoryFilterKey = "search" | "type" | "source" | "provider" | "environment" | "severity" | "minSeverity";

export interface InventoryFilters {
  search: string;
  type: string;
  source: string;
  provider: string;
  environment: string;
  severity: string;
  minSeverity?: string;
}

const EMPTY_FILTERS: InventoryFilters = {
  search: "",
  type: "",
  source: "",
  provider: "",
  environment: "",
  severity: "",
  minSeverity: "",
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
  previousPage: () => Promise<void>;
  pageSize: number;
  setPageSize: (size: number) => void;
  loadAssetDetail: (assetId: string) => Promise<void>;
}

const InventoryContext = createContext<InventoryState | null>(null);

function classifyError(err: unknown): { message: string; kind: InventoryErrorKind } {
  if (err instanceof ApiAuthError) return { message: "Sign in to view the asset inventory.", kind: "auth" };
  if (err instanceof ApiForbiddenError) return { message: "Your role cannot read the asset inventory.", kind: "forbidden" };
  if (err instanceof ApiError && err.status === 404) {
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
  scanId,
  initialFilters,
  onFiltersChange,
  onSnapshotResolved,
}: {
  children: ReactNode;
  /** Route-owned asset taxonomy scope; every page and cursor keeps it. */
  entityTypes?: readonly string[] | undefined;
  /** Backward-compatible initial severity restored from the inventory URL. */
  minSeverity?: string | undefined;
  scanId?: string | undefined;
  initialFilters?: Partial<InventoryFilters> | undefined;
  onFiltersChange?: ((filters: InventoryFilters) => void) | undefined;
  onSnapshotResolved?: ((scanId: string) => void) | undefined;
}) {
  const [summary, setSummary] = useState<InventorySummaryResponse | null>(null);
  const [page, setPage] = useState<InventoryAssetsResponse | null>(null);
  const [pageSize, setPageSizeState] = useState(INVENTORY_PAGE_SIZE);
  const setPageSize = useCallback((size: number) => { if ([25, 50, 100].includes(size)) setPageSizeState(size); }, []);
  const [filters, setFilters] = useState<InventoryFilters>({ ...EMPTY_FILTERS, ...initialFilters, severity: minSeverity ?? initialFilters?.severity ?? "" });
  const filtersRef = useRef(filters);
  filtersRef.current = filters;
  const resolvedSnapshot = useRef(scanId);
  const [loadingSummary, setLoadingSummary] = useState(true);
  const [loadingPage, setLoadingPage] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState("");
  const [errorKind, setErrorKind] = useState<InventoryErrorKind>("network");
  const [nonce, setNonce] = useState(0);
  const [details, setDetails] = useState<Record<string, InventoryAssetDetailResponse>>({});
  const [detailLoadingId, setDetailLoadingId] = useState("");
  const [detailError, setDetailError] = useState("");
  // Continuations are query-scoped; details remain valid across filters but not refreshes.
  const pageGeneration = useRef(0);
  const snapshotGeneration = useRef(0);
  // Cursor responses report the request offset (normally zero), not a row
  // ordinal. Keep position and prior cursors locally for bounded navigation.
  const pageCursors = useRef(new Map<number, string>());

  const reload = useCallback(() => setNonce((value) => value + 1), []);
  const entityTypesKey = (entityTypes ?? []).join(",");
  const fixedEntityTypes = useMemo(() => (entityTypesKey ? entityTypesKey.split(",") : []), [entityTypesKey]);

  const initialFiltersKey = JSON.stringify(initialFilters ?? {});
  useEffect(() => {
    const restored = JSON.parse(initialFiltersKey) as Partial<InventoryFilters>;
    const next = { ...EMPTY_FILTERS, ...restored, severity: minSeverity ?? restored.severity ?? "" };
    filtersRef.current = next;
    setFilters(next);
  }, [minSeverity, initialFiltersKey]);
  const snapshotCallback = useRef(onSnapshotResolved);
  snapshotCallback.current = onSnapshotResolved;

  useEffect(() => {
    resolvedSnapshot.current = scanId;
    snapshotGeneration.current += 1;
    setDetails({});
    setDetailLoadingId("");
    setDetailError("");
    setSummary(null);
    setPage(null);
    return () => { snapshotGeneration.current += 1; };
  }, [scanId, nonce]);
  const queryFiltersKey = JSON.stringify(filters);

  useEffect(() => {
    let cancelled = false;
    setLoadingSummary(true);
    setError("");
    const restored = JSON.parse(queryFiltersKey) as InventoryFilters;
    const selectedTypes = restored.type ? restored.type.split(",") : [];
    const scopedTypes = fixedEntityTypes.length ? selectedTypes.filter((type) => fixedEntityTypes.includes(type)) : selectedTypes;
    api.getInventorySummary(scanId ?? resolvedSnapshot.current, {
      environment: restored.environment, provider: restored.provider, source: restored.source,
      search: restored.search, type: scopedTypes.length ? scopedTypes : fixedEntityTypes.length ? fixedEntityTypes : undefined,
      severity: minSeverity ?? restored.severity, minSeverity: restored.minSeverity,
    })
      .then((response) => {
        if (!cancelled) {
          resolvedSnapshot.current = response.scan_id;
          setSummary(response);
          snapshotCallback.current?.(response.scan_id);
        }
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
  }, [nonce, scanId, queryFiltersKey, minSeverity, fixedEntityTypes]);

  const requestedTypes = useMemo(() => {
    if (!filters.type) return fixedEntityTypes;
    const selected = filters.type.split(",").map((type) => type.trim()).filter(Boolean);
    if (fixedEntityTypes.length === 0) return selected;
    const allowed = selected.filter((type) => fixedEntityTypes.includes(type));
    return allowed.length ? allowed : fixedEntityTypes;
  }, [filters.type, fixedEntityTypes]);

  const requestScope = useMemo(() => ({
    ...(requestedTypes.length > 0 ? { type: requestedTypes } : {}),
    ...(filters.search.trim() ? { search: filters.search.trim() } : {}),
    ...(filters.environment ? { environment: filters.environment } : {}),
    ...(filters.provider ? { provider: filters.provider } : {}),
    ...(filters.source ? { source: filters.source } : {}),
    ...(filters.severity ? { severity: filters.severity } : {}),
    ...(filters.minSeverity ? { minSeverity: filters.minSeverity } : {}),
  }), [requestedTypes, filters]);

  const snapshotId = summary?.scan_id;
  useEffect(() => {
    if (!snapshotId) return;
    pageCursors.current.clear();
    pageGeneration.current += 1;
    setLoadingMore(false);
    let cancelled = false;
    setLoadingPage(true);
    setError("");
    api.getInventoryAssets({
      ...requestScope,
      scanId: snapshotId,
      limit: pageSize,
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
      pageGeneration.current += 1;
    };
  }, [snapshotId, requestScope, pageSize, nonce]);

  const model = useMemo(() => (summary && page ? buildInventoryFromApi(summary, page) : null), [summary, page]);
  const hasMore = !loadingPage && Boolean(page?.pagination.has_more);
  const setFilter = useCallback((key: InventoryFilterKey, value: string) => {
    const next = { ...filtersRef.current, [key]: value };
    filtersRef.current = next;
    setFilters(next);
    onFiltersChange?.(next);
  }, [onFiltersChange]);
  const clearFilters = useCallback(() => {
    const next = { ...EMPTY_FILTERS, severity: minSeverity ?? "" };
    filtersRef.current = next;
    setFilters(next);
    onFiltersChange?.(next);
  }, [minSeverity, onFiltersChange]);

  const navigatePage = useCallback(async (previous: boolean) => {
    if (!summary || !page || loadingPage || loadingMore || (previous ? page.pagination.offset === 0 : !page.pagination.has_more)) return;
    const generation = pageGeneration.current;
    const targetOffset = previous ? Math.max(0, page.pagination.offset - pageSize) : page.pagination.offset + pageSize;
    const cursor = previous ? pageCursors.current.get(targetOffset) : page.pagination.next_cursor;
    setLoadingMore(true);
    try {
      const next = await api.getInventoryAssets({
        ...requestScope,
        scanId: summary.scan_id,
        limit: pageSize,
        ...(cursor ? { cursor } : { offset: targetOffset }),
      });
      if (generation !== pageGeneration.current) return;
      if (cursor) pageCursors.current.set(targetOffset, cursor);
      setPage({ ...next, pagination: { ...next.pagination, offset: targetOffset } });
    } catch (err: unknown) {
      if (generation !== pageGeneration.current) return;
      const classified = classifyError(err);
      setError(classified.message);
      setErrorKind(classified.kind);
    } finally {
      if (generation === pageGeneration.current) setLoadingMore(false);
    }
  }, [summary, page, loadingPage, loadingMore, requestScope, pageSize]);
  const loadMore = useCallback(() => navigatePage(false), [navigatePage]);
  const previousPage = useCallback(() => navigatePage(true), [navigatePage]);

  const loadAssetDetail = useCallback(async (assetId: string) => {
    if (!summary || details[assetId] || detailLoadingId === assetId) return;
    const generation = snapshotGeneration.current;
    setDetailLoadingId(assetId);
    setDetailError("");
    try {
      const detail = await api.getInventoryAsset(assetId, summary.scan_id);
      if (generation !== snapshotGeneration.current) return;
      setDetails((current) => ({ ...current, [assetId]: detail }));
    } catch (err: unknown) {
      if (generation !== snapshotGeneration.current) return;
      setDetailError(classifyError(err).message);
    } finally {
      if (generation === snapshotGeneration.current) {
        setDetailLoadingId((current) => current === assetId ? "" : current);
      }
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
    previousPage, pageSize, setPageSize,
    loadAssetDetail,
  }), [model, summary, page, filters, fixedEntityTypes, loadingSummary, loadingPage, loadingMore, hasMore, error, errorKind, details, detailLoadingId, detailError, setFilter, clearFilters, reload, loadMore, previousPage, pageSize, setPageSize, loadAssetDetail]);

  return <InventoryContext.Provider value={value}>{children}</InventoryContext.Provider>;
}

export function useInventory(): InventoryState {
  const ctx = useContext(InventoryContext);
  if (!ctx) throw new Error("useInventory must be used within an InventoryProvider");
  return ctx;
}
