"use client";

import { ApiOfflineState } from "@/components/api-offline-state";
import { PageErrorState } from "@/components/states/page-state";
import type { InventoryErrorKind } from "@/lib/inventory-context";

export function InventoryErrorState({
  error,
  errorKind,
  onRetry,
}: {
  error: string;
  errorKind: Exclude<InventoryErrorKind, "empty">;
  onRetry: () => void;
}) {
  if (errorKind === "request") {
    return (
      <PageErrorState
        data-testid="inventory-error"
        title="Asset inventory could not be loaded"
        detail={error}
        action={{ label: "Retry", onClick: onRetry }}
      />
    );
  }
  return (
    <div className="space-y-3">
      <ApiOfflineState detail={error} kind={errorKind} />
      {errorKind === "network" ? (
        <div className="flex justify-center">
          <button
            type="button"
            onClick={onRetry}
            className="rounded-lg border border-outline px-3 py-2 text-sm text-ink-secondary hover:bg-surface-muted"
          >
            Retry
          </button>
        </div>
      ) : null}
    </div>
  );
}
