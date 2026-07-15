"use client";

import { useCallback, useEffect, useState } from "react";
import { CheckCircle2, Loader2, Plug, RefreshCw, XCircle } from "lucide-react";

import { api, type SiemTestResponse } from "@/lib/api";
import { useAuthState } from "@/components/auth-provider";
import { PageErrorState } from "@/components/states/page-state";
import { StatStrip } from "@/components/stat-strip";
import {
  Field,
  INPUT_CLASS,
  InlineNotice,
  PanelButton,
  PanelIntro,
  Pill,
  errorMessage,
} from "@/components/integrations/panel-kit";

export function SiemPanel() {
  const { session, hasCapability } = useAuthState();
  const canTest = !session?.auth_required || hasCapability("policy.manage");

  const [connectors, setConnectors] = useState<string[]>([]);
  const [formats, setFormats] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  const [siemType, setSiemType] = useState("");
  const [url, setUrl] = useState("");
  const [token, setToken] = useState("");
  const [testing, setTesting] = useState(false);
  const [result, setResult] = useState<SiemTestResponse | null>(null);
  const [testError, setTestError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setLoadError(null);
    try {
      const [c, f] = await Promise.all([api.listSiemConnectors(), api.listSiemFormats()]);
      const list = c.connectors ?? [];
      setConnectors(list);
      setFormats(f.formats ?? []);
      setSiemType((prev) => prev || list[0] || "");
    } catch (err) {
      setLoadError(errorMessage(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const runTest = async () => {
    setTesting(true);
    setResult(null);
    setTestError(null);
    try {
      const res = await api.testSiemConnection(siemType, url.trim(), token.trim() || undefined);
      // Do not retain the token beyond the request.
      setToken("");
      setResult(res);
    } catch (err) {
      setTestError(errorMessage(err));
    } finally {
      setTesting(false);
    }
  };

  if (loadError) {
    return (
      <PageErrorState
        title="Could not load SIEM connectors"
        detail={loadError}
        action={{ label: "Retry", onClick: () => void load() }}
      />
    );
  }

  return (
    <div className="space-y-5">
      <PanelIntro
        title="SIEM connectors"
        description="Available SIEM connector types and event formats for streaming detections downstream. Run a connectivity test before wiring a destination. Tokens are sent per-test and never stored or displayed."
      >
        <PanelButton tone="secondary" onClick={() => void load()} title="Refresh">
          <RefreshCw className="h-4 w-4" />
          Refresh
        </PanelButton>
      </PanelIntro>

      <StatStrip
        items={[
          { label: "Connector types", value: connectors.length, icon: Plug },
          { label: "Event formats", value: formats.length },
        ]}
      />

      <div className="grid gap-3 md:grid-cols-2">
        <div className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4">
          <div className="text-[11px] font-semibold uppercase tracking-[0.12em] text-[color:var(--text-tertiary)]">
            Connector types
          </div>
          <div className="mt-3 flex flex-wrap gap-2" data-testid="siem-connectors">
            {loading ? (
              <span className="text-sm text-[color:var(--text-tertiary)]">Loading…</span>
            ) : connectors.length === 0 ? (
              <span className="text-sm text-[color:var(--text-tertiary)]">No connectors registered.</span>
            ) : (
              connectors.map((c) => (
                <Pill key={c} tone="accent">
                  {c}
                </Pill>
              ))
            )}
          </div>
        </div>
        <div className="rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-4">
          <div className="text-[11px] font-semibold uppercase tracking-[0.12em] text-[color:var(--text-tertiary)]">
            Event formats
          </div>
          <div className="mt-3 flex flex-wrap gap-2" data-testid="siem-formats">
            {loading ? (
              <span className="text-sm text-[color:var(--text-tertiary)]">Loading…</span>
            ) : (
              formats.map((f) => (
                <Pill key={f} tone="neutral">
                  {f}
                </Pill>
              ))
            )}
          </div>
        </div>
      </div>

      <form
        className="space-y-4 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-5"
        onSubmit={(e) => {
          e.preventDefault();
          void runTest();
        }}
      >
        <div className="text-sm font-medium text-[color:var(--foreground)]">Test connectivity</div>
        <div className="grid gap-4 md:grid-cols-3">
          <Field label="Connector type">
            <select
              className={INPUT_CLASS}
              value={siemType}
              onChange={(e) => setSiemType(e.target.value)}
              data-testid="siem-type-select"
            >
              {connectors.map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Endpoint URL">
            <input
              className={INPUT_CLASS}
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://siem.example.com/services/collector"
              data-testid="siem-url-input"
            />
          </Field>
          <Field label="Auth token (optional, not stored)">
            <input
              className={INPUT_CLASS}
              type="password"
              autoComplete="off"
              value={token}
              onChange={(e) => setToken(e.target.value)}
              placeholder="Sent via header for this test only"
            />
          </Field>
        </div>

        {!canTest ? (
          <InlineNotice tone="info">Testing a SIEM connector requires an admin (policy management) role.</InlineNotice>
        ) : null}
        {testError ? <InlineNotice tone="error">{testError}</InlineNotice> : null}
        {result ? (
          <InlineNotice tone={result.healthy ? "success" : "error"} data-testid="siem-test-result">
            <div className="flex items-center gap-2 font-medium">
              {result.healthy ? (
                <CheckCircle2 className="h-4 w-4" />
              ) : (
                <XCircle className="h-4 w-4" />
              )}
              {result.siem_type || siemType}: {result.healthy ? "healthy" : "unhealthy"}
            </div>
            {result.error ? <p className="mt-1 text-xs">{result.error}</p> : null}
          </InlineNotice>
        ) : null}

        <PanelButton tone="primary" type="submit" disabled={!canTest || testing || !siemType} data-testid="siem-test-submit">
          {testing ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plug className="h-4 w-4" />}
          Run test
        </PanelButton>
      </form>
    </div>
  );
}
