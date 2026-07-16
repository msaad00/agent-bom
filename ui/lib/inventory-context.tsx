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
import { ApiAuthError, ApiError, ApiForbiddenError } from "@/lib/api-errors";
import { buildInventory, type InventoryModel } from "@/lib/inventory";

// Single graph fetch for the whole Inventory section. The graph is the
// canonical correlation fabric — one read gives every asset kind plus the
// finding neighbors used for correlation. Loading it once at the section root
// keeps navigation between asset-type pages instant.
const GRAPH_NODE_LIMIT = 4000;

export type InventoryErrorKind = "network" | "auth" | "forbidden" | "empty";

export interface InventoryState {
  model: InventoryModel | null;
  loading: boolean;
  error: string;
  errorKind: InventoryErrorKind;
  reload: () => void;
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
  const [model, setModel] = useState<InventoryModel | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [errorKind, setErrorKind] = useState<InventoryErrorKind>("network");
  const [nonce, setNonce] = useState(0);

  const reload = useCallback(() => setNonce((value) => value + 1), []);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError("");
    api
      .getGraph({ limit: GRAPH_NODE_LIMIT })
      .then((graph) => {
        if (cancelled) return;
        setModel(buildInventory(graph));
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        const classified = classifyError(err);
        setModel(null);
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

  const value = useMemo<InventoryState>(
    () => ({ model, loading, error, errorKind, reload }),
    [model, loading, error, errorKind, reload],
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
