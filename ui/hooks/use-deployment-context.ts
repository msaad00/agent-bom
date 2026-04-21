"use client";

import { useEffect, useState } from "react";

import { api, type PostureCountsResponse } from "@/lib/api";

export function useDeploymentContext() {
  const [counts, setCounts] = useState<PostureCountsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let mounted = true;

    const load = () => {
      api
        .getPostureCounts()
        .then((nextCounts) => {
          if (!mounted) return;
          setCounts(nextCounts);
          setError(null);
          setLoading(false);
        })
        .catch((nextError: Error) => {
          if (!mounted) return;
          setError(nextError.message);
          setLoading(false);
        });
    };

    load();
    const interval = window.setInterval(load, 60_000);
    return () => {
      mounted = false;
      window.clearInterval(interval);
    };
  }, []);

  return { counts, loading, error };
}
