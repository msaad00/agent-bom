"use client";

import {
  type EndpointConnection,
  type EndpointSync,
} from "@/lib/endpoint-connectors";
import { field, button } from "./styles";

export function EndpointConnectionCard({
  connection,
  state,
  canManage,
  busy,
  inspect,
  sync,
  update,
}: {
  connection: EndpointConnection;
  state: EndpointSync | null;
  canManage: boolean;
  busy: boolean;
  inspect: (id: string) => Promise<void>;
  sync: (id: string, restart: boolean) => Promise<void>;
  update: (
    id: string,
    body: { enabled?: boolean; client_secret?: string },
  ) => Promise<void>;
}) {
  return (
    <div
      key={connection.id}
      className="rounded-xl border border-[var(--border-subtle)] p-4 space-y-2"
    >
      <h3 className="font-medium">
        {connection.name}{" "}
        <span className="text-xs text-[var(--text-secondary)]">
          {connection.provider}
        </span>
      </h3>
      <p className="text-sm">
        {!connection.enabled ? "Disabled · " : ""}
        {state
          ? `${state.status} · ${state.device_count} / ${state.expected_count ?? "unknown"} devices`
          : "Not collected"}
      </p>
      {state && (
        <p className="text-xs text-[var(--text-secondary)]">
          Collected {new Date(state.updated_at).toLocaleString()}
          {state.gap ? ` · ${state.gap.replaceAll("_", " ")}` : ""}
        </p>
      )}
      <div className="flex flex-wrap gap-2">
        <button className={button} onClick={() => void inspect(connection.id)}>
          Inspect evidence
        </button>
        {canManage && (
          <>
            <button
              className={button}
              disabled={busy || !connection.enabled}
              onClick={() => void sync(connection.id, false)}
            >
              {state && state.status !== "complete"
                ? "Resume sync"
                : "Sync inventory"}
            </button>
            <button
              className={button}
              disabled={busy || !connection.enabled}
              onClick={() => void sync(connection.id, true)}
            >
              Start fresh collection
            </button>
            <button
              className={button}
              disabled={busy}
              onClick={() =>
                void update(connection.id, { enabled: !connection.enabled })
              }
            >
              {connection.enabled ? "Disable" : "Enable"}
            </button>
          </>
        )}
      </div>
      {canManage && (
        <details>
          <summary className="text-xs cursor-pointer">
            Rotate credential
          </summary>
          <form
            className="flex gap-2 mt-2"
            onSubmit={(event) => {
              event.preventDefault();
              const form = event.currentTarget;
              const input = form.elements.namedItem(
                "replacement",
              ) as HTMLInputElement;
              const secret = input.value;
              input.value = "";
              void update(connection.id, { client_secret: secret });
            }}
          >
            <input
              name="replacement"
              type="password"
              required
              aria-label={`New client secret for ${connection.name}`}
              autoComplete="new-password"
              className={field}
            />
            <button disabled={busy} className={button}>
              Rotate secret
            </button>
          </form>
        </details>
      )}
    </div>
  );
}
