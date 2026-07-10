"use client";

import { useEffect, useState } from "react";

import type { AuthMeResponse } from "@/lib/api";
import {
  defaultOverviewPersona,
  readStoredOverviewPersona,
  storeOverviewPersona,
  type OverviewPersona,
} from "@/lib/overview-persona";

export function useOverviewPersona(session: AuthMeResponse | null) {
  const [persona, setPersona] = useState<OverviewPersona>("executive");
  const [ready, setReady] = useState(false);

  useEffect(() => {
    const stored = readStoredOverviewPersona();
    setPersona(stored ?? defaultOverviewPersona(session));
    setReady(true);
  }, [session]);

  const selectPersona = (next: OverviewPersona) => {
    setPersona(next);
    storeOverviewPersona(next);
  };

  return { persona, selectPersona, ready };
}
