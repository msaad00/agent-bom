"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "@/lib/api";
import {
  type EndpointConnections,
  type EndpointInventory,
} from "@/lib/endpoint-connectors";
import { Card } from "@/components/card";

import { button } from "./endpoint-connections/styles";
import { EndpointConnectionForm } from "./endpoint-connections/connection-form";
import { EndpointConnectionCard } from "./endpoint-connections/connection-card";
import { EndpointDeviceEvidence } from "./endpoint-connections/device-evidence";

export function EndpointConnectionsPanel({
  canManage,
  demo = false,
}: {
  canManage: boolean;
  demo?: boolean;
}) {
  const [rows, setRows] = useState<EndpointConnections["connections"]>([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [selected, setSelected] = useState("");
  const [inventory, setInventory] = useState<EndpointInventory | null>(null);
  const [showForm, setShowForm] = useState(false);
  const generation = useRef(0);
  const refresh = useCallback(async () => {
    if (demo) return;
    try {
      setRows((await api.endpointConnections()).connections);
    } catch {
      setError(
        "Endpoint connections could not be loaded. Check API access and retry.",
      );
    }
  }, [demo]);
  useEffect(() => {
    void refresh();
    return () => {
      generation.current++;
    };
  }, [refresh]);

  async function inspect(id: string, offset = 0) {
    const request = ++generation.current;
    setSelected(id);
    setInventory(null);
    setError("");
    try {
      const result = await api.endpointDevices(id, offset);
      if (request === generation.current) setInventory(result);
    } catch {
      if (request === generation.current)
        setError("Device evidence could not be loaded.");
    }
  }
  async function sync(id: string, restart: boolean) {
    setBusy(true);
    setError("");
    try {
      await api.syncEndpointConnection(id, restart);
      await refresh();
      await inspect(id);
    } catch {
      setError(
        "Sync could not finish. Check permissions and retry; previously collected evidence is retained.",
      );
    } finally {
      setBusy(false);
    }
  }
  async function update(
    id: string,
    body: { enabled?: boolean; client_secret?: string },
  ) {
    setBusy(true);
    setError("");
    try {
      await api.updateEndpointConnection(id, body);
      await refresh();
    } catch {
      setError("Connection update failed. Wait for any active sync and retry.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card className="space-y-4" aria-label="Endpoint inventory connections">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="font-semibold">Endpoint inventory</h2>
          <p className="text-sm text-[var(--text-secondary)]">
            Jamf management and Falcon sensor evidence. Sensor health is
            separate from policy compliance.
          </p>
        </div>
        {canManage && !demo && (
          <button className={button} onClick={() => setShowForm(!showForm)}>
            Connect endpoint provider
          </button>
        )}
      </div>
      {demo && (
        <p className="text-sm text-[var(--text-secondary)]">
          Connect a provider in your authenticated control plane to collect
          endpoint evidence.
        </p>
      )}
      {error && (
        <div role="alert" className="text-sm text-red-500">
          {error}{" "}
          <button className={button} onClick={() => void refresh()}>
            Retry
          </button>
        </div>
      )}
      {showForm && (
        <EndpointConnectionForm
          setError={setError}
          onCreated={async (id) => {
            setShowForm(false);
            await refresh();
            await inspect(id);
          }}
        />
      )}
      {!demo && rows.length === 0 && !error && (
        <p className="text-sm text-[var(--text-secondary)]">
          No endpoint connections configured.
        </p>
      )}
      <div className="grid gap-3 lg:grid-cols-2">
        {rows.map(({ connection, sync: state }) => (
          <EndpointConnectionCard
            key={connection.id}
            connection={connection}
            state={state}
            canManage={canManage}
            busy={busy}
            inspect={inspect}
            sync={sync}
            update={update}
          />
        ))}
      </div>
      {selected && (
        <EndpointDeviceEvidence
          selected={selected}
          inventory={inventory}
          canManage={canManage}
          busy={busy}
          inspect={inspect}
          setBusy={setBusy}
          setError={setError}
        />
      )}
    </Card>
  );
}
