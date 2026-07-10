"use client";

import { useEffect, useState } from "react";

import {
  FINDINGS_LENSES,
  findingsLensHint,
  findingsLensLabel,
  normalizeFindingsLens,
  readStoredFindingsLens,
  storeFindingsLens,
  type FindingsLens,
} from "@/lib/findings-lens";

export function useFindingsLens(paramLens: string | null) {
  const [lens, setLens] = useState<FindingsLens>("ops");
  const [ready, setReady] = useState(false);

  useEffect(() => {
    const fromParam = normalizeFindingsLens(paramLens);
    const stored = readStoredFindingsLens();
    setLens(fromParam ?? stored ?? "ops");
    setReady(true);
  }, [paramLens]);

  const selectLens = (next: FindingsLens) => {
    setLens(next);
    storeFindingsLens(next);
  };

  return {
    lens,
    selectLens,
    ready,
    lenses: FINDINGS_LENSES,
    label: findingsLensLabel,
    hint: findingsLensHint(lens),
  };
}
