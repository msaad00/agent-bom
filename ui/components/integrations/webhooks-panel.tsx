"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { Copy, Loader2, Plus, RefreshCw, Send, Trash2, Power, Webhook } from "lucide-react";

import {
  api,
  type WebhookSubscription,
  type WebhookOutboxResponse,
} from "@/lib/api";
import { useAuthState } from "@/components/auth-provider";
import { DataTable, type DataTableColumn } from "@/components/data-table";
import { StatStrip } from "@/components/stat-strip";
import { PageErrorState } from "@/components/states/page-state";
import {
  Field,
  INPUT_CLASS,
  InlineNotice,
  PanelButton,
  PanelIntro,
  Pill,
  errorMessage,
} from "@/components/integrations/panel-kit";

/**
 * A webhook URL can itself be a secret (Slack-style incoming webhooks embed the
 * token in the path), which is why the backend redacts it in the audit log. We
 * mirror that here: the management table shows only origin + a masked path and
 * the non-reversible `secret_fingerprint` handle — never a full URL or secret.
 */
function redactWebhookUrl(raw: string): string {
  try {
    const u = new URL(raw);
    const hasPath = u.pathname && u.pathname !== "/";
    return `${u.protocol}//${u.host}${hasPath ? "/•••" : ""}`;
  } catch {
    return "•••";
  }
}

export function WebhooksPanel() {
  const { session, hasCapability } = useAuthState();
  const canManage = !session?.auth_required || hasCapability("policy.manage");

  const [subs, setSubs] = useState<WebhookSubscription[]>([]);
  const [catalog, setCatalog] = useState<string[]>([]);
  const [outbox, setOutbox] = useState<WebhookOutboxResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [notice, setNotice] = useState<{ tone: "success" | "error"; text: string } | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  const [showCreate, setShowCreate] = useState(false);
  const [oneTimeSecret, setOneTimeSecret] = useState<string | null>(null);
  const [secretCopied, setSecretCopied] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setLoadError(null);
    try {
      const res = await api.listWebhookSubscriptions(true, 200);
      setSubs(res.subscriptions ?? []);
      setCatalog(res.event_catalog ?? []);
      // Outbox is best-effort observability; a failure here must not blank the panel.
      const box = await api.listWebhookOutbox(undefined, 50).catch(() => null);
      setOutbox(box);
    } catch (err) {
      setLoadError(errorMessage(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const runAction = useCallback(
    async (id: string, verb: string, fn: () => Promise<unknown>) => {
      setBusyId(id);
      setNotice(null);
      try {
        await fn();
        setNotice({ tone: "success", text: `Webhook ${verb}.` });
        await load();
      } catch (err) {
        setNotice({ tone: "error", text: errorMessage(err) });
      } finally {
        setBusyId(null);
      }
    },
    [load],
  );

  const activeCount = subs.filter((s) => s.status === "active").length;
  const stats = outbox?.stats ?? {};

  const columns = useMemo<DataTableColumn<WebhookSubscription>[]>(
    () => [
      {
        key: "url",
        header: "Destination",
        cell: (s) => (
          <div className="min-w-0">
            <div className="truncate font-mono text-xs text-[color:var(--foreground)]" title="URL redacted — it may embed a secret token">
              {redactWebhookUrl(s.url)}
            </div>
            {s.description ? (
              <div className="truncate text-xs text-[color:var(--text-tertiary)]">{s.description}</div>
            ) : null}
          </div>
        ),
      },
      {
        key: "events",
        header: "Events",
        cell: (s) =>
          s.event_types.length === 0 ? (
            <Pill tone="neutral">all governance events</Pill>
          ) : (
            <div className="flex flex-wrap gap-1">
              {s.event_types.map((e) => (
                <Pill key={e} tone="neutral">
                  {e}
                </Pill>
              ))}
            </div>
          ),
      },
      {
        key: "secret",
        header: "Secret",
        cell: (s) => (
          <span className="font-mono text-xs text-[color:var(--text-tertiary)]">
            {s.secret_fingerprint ? `${s.secret_fingerprint}…` : "—"}
          </span>
        ),
      },
      {
        key: "status",
        header: "Status",
        cell: (s) =>
          s.status === "active" ? <Pill tone="success">active</Pill> : <Pill tone="warn">disabled</Pill>,
      },
      {
        key: "actions",
        header: "",
        align: "right",
        cell: (s) => {
          const busy = busyId === s.subscription_id;
          return (
            <div className="flex justify-end gap-1.5">
              <PanelButton
                tone="secondary"
                disabled={!canManage || busy}
                title="Send a synthetic test delivery"
                onClick={() =>
                  runAction(s.subscription_id, "test enqueued", () =>
                    api.testWebhookSubscription(s.subscription_id),
                  )
                }
              >
                {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Send className="h-3.5 w-3.5" />}
                Test
              </PanelButton>
              <PanelButton
                tone="secondary"
                disabled={!canManage || busy}
                onClick={() =>
                  runAction(
                    s.subscription_id,
                    s.status === "active" ? "disabled" : "enabled",
                    () =>
                      s.status === "active"
                        ? api.disableWebhookSubscription(s.subscription_id)
                        : api.enableWebhookSubscription(s.subscription_id),
                  )
                }
              >
                <Power className="h-3.5 w-3.5" />
                {s.status === "active" ? "Disable" : "Enable"}
              </PanelButton>
              <PanelButton
                tone="danger"
                disabled={!canManage || busy}
                onClick={() => {
                  if (!window.confirm("Delete this webhook subscription?")) return;
                  void runAction(s.subscription_id, "deleted", () =>
                    api.deleteWebhookSubscription(s.subscription_id),
                  );
                }}
              >
                <Trash2 className="h-3.5 w-3.5" />
                Delete
              </PanelButton>
            </div>
          );
        },
      },
    ],
    [busyId, canManage, runAction],
  );

  if (loadError) {
    return (
      <PageErrorState
        title="Could not load webhook subscriptions"
        detail={loadError}
        action={{ label: "Retry", onClick: () => void load() }}
      />
    );
  }

  return (
    <div className="space-y-5">
      <PanelIntro
        title="Webhook subscriptions"
        description="Outbound governance webhooks (budget enforcement, identity lifecycle, JIT grants, conditional-access denials, drift). Deliveries flow through the durable, HMAC-signed outbox."
      >
        <PanelButton tone="secondary" onClick={() => void load()} title="Refresh">
          <RefreshCw className="h-4 w-4" />
          Refresh
        </PanelButton>
        <PanelButton
          tone="primary"
          disabled={!canManage}
          onClick={() => {
            setOneTimeSecret(null);
            setShowCreate((v) => !v);
          }}
        >
          <Plus className="h-4 w-4" />
          New subscription
        </PanelButton>
      </PanelIntro>

      <StatStrip
        items={[
          { label: "Subscriptions", value: subs.length, icon: Webhook },
          { label: "Active", value: activeCount, accent: "success" },
          { label: "Disabled", value: subs.length - activeCount, accent: activeCount === subs.length ? "neutral" : "warn" },
          { label: "Outbox pending", value: Number(stats.pending ?? 0), accent: "warn" },
          { label: "Delivered", value: Number(stats.delivered ?? 0), accent: "success" },
          { label: "Dead-letter", value: Number(stats.dead_letter ?? 0), accent: "critical" },
        ]}
      />

      {notice ? <InlineNotice tone={notice.tone} data-testid="webhook-notice">{notice.text}</InlineNotice> : null}
      {!canManage ? (
        <InlineNotice tone="info">
          Viewing only. Registering, testing, enabling, disabling, or deleting webhooks requires an
          admin (policy management) role.
        </InlineNotice>
      ) : null}

      {oneTimeSecret ? (
        <InlineNotice tone="success" data-testid="webhook-secret-reveal">
          <div className="font-medium">Signing secret — shown once</div>
          <p className="mt-1 text-xs">
            Store this HMAC signing secret now. It is not retrievable later; the table only ever shows a
            non-reversible fingerprint.
          </p>
          <div className="mt-2 flex items-center gap-2">
            <code className="min-w-0 flex-1 truncate rounded border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-2 py-1 font-mono text-xs text-[color:var(--foreground)]">
              {oneTimeSecret}
            </code>
            <PanelButton
              tone="secondary"
              onClick={() => {
                void navigator.clipboard?.writeText(oneTimeSecret);
                setSecretCopied(true);
              }}
            >
              {secretCopied ? "Copied" : <><Copy className="h-3.5 w-3.5" /> Copy</>}
            </PanelButton>
          </div>
        </InlineNotice>
      ) : null}

      {showCreate && canManage ? (
        <CreateWebhookForm
          catalog={catalog}
          onCancel={() => setShowCreate(false)}
          onCreated={(secret) => {
            setShowCreate(false);
            setOneTimeSecret(secret);
            setSecretCopied(false);
            setNotice({ tone: "success", text: "Webhook subscription created." });
            void load();
          }}
        />
      ) : null}

      <DataTable
        rows={subs}
        rowKey={(s) => s.subscription_id}
        columns={columns}
        loading={loading}
        maxHeight="32rem"
        caption="Governance webhook subscriptions"
        empty="No webhook subscriptions yet. Register a destination to receive governance events."
        data-testid="webhooks-table"
      />
    </div>
  );
}

function CreateWebhookForm({
  catalog,
  onCancel,
  onCreated,
}: {
  catalog: string[];
  onCancel: () => void;
  onCreated: (secret: string) => void;
}) {
  const [url, setUrl] = useState("");
  const [description, setDescription] = useState("");
  const [signingSecret, setSigningSecret] = useState("");
  const [allowPrivate, setAllowPrivate] = useState(false);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const toggleEvent = (e: string) =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(e)) next.delete(e);
      else next.add(e);
      return next;
    });

  const submit = async () => {
    setError(null);
    if (!url.trim()) {
      setError("A destination URL is required.");
      return;
    }
    setSubmitting(true);
    try {
      const res = await api.createWebhookSubscription({
        url: url.trim(),
        event_types: [...selected],
        description: description.trim(),
        signing_secret: signingSecret.trim() || undefined,
        allow_private_networks: allowPrivate,
      });
      // Clear the operator-provided secret from memory immediately.
      setSigningSecret("");
      onCreated(res.signing_secret);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <form
      className="space-y-4 rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] p-5"
      onSubmit={(e) => {
        e.preventDefault();
        void submit();
      }}
    >
      <div className="grid gap-4 md:grid-cols-2">
        <Field label="Destination URL">
          <input
            className={INPUT_CLASS}
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://hooks.example.com/agent-bom"
            data-testid="webhook-url-input"
          />
        </Field>
        <Field label="Description (optional)">
          <input
            className={INPUT_CLASS}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Team channel / purpose"
          />
        </Field>
      </div>

      <Field label="Signing secret (optional — leave blank to auto-generate)">
        <input
          className={INPUT_CLASS}
          type="password"
          autoComplete="off"
          value={signingSecret}
          onChange={(e) => setSigningSecret(e.target.value)}
          placeholder="Provide your own HMAC secret, or leave blank"
        />
      </Field>

      <div>
        <span className="text-[11px] font-semibold uppercase tracking-[0.12em] text-[color:var(--text-tertiary)]">
          Event types ({selected.size === 0 ? "all governance events" : `${selected.size} selected`})
        </span>
        <div className="mt-2 flex flex-wrap gap-2">
          {catalog.map((e) => {
            const on = selected.has(e);
            return (
              <button
                key={e}
                type="button"
                onClick={() => toggleEvent(e)}
                className={`rounded-full border px-2.5 py-1 text-xs font-medium transition ${
                  on
                    ? "border-[color:var(--accent-border)] bg-[color:var(--accent-soft)] text-[color:var(--accent)]"
                    : "border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] text-[color:var(--text-secondary)] hover:border-[color:var(--border-strong)]"
                }`}
              >
                {e}
              </button>
            );
          })}
        </div>
      </div>

      <label className="flex items-center gap-2 text-sm text-[color:var(--text-secondary)]">
        <input type="checkbox" checked={allowPrivate} onChange={(e) => setAllowPrivate(e.target.checked)} />
        Allow private-network destinations (advanced)
      </label>

      {error ? <InlineNotice tone="error">{error}</InlineNotice> : null}

      <div className="flex gap-2">
        <PanelButton tone="primary" type="submit" disabled={submitting} data-testid="webhook-create-submit">
          {submitting ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />}
          Create subscription
        </PanelButton>
        <PanelButton tone="secondary" onClick={onCancel} disabled={submitting}>
          Cancel
        </PanelButton>
      </div>
    </form>
  );
}
