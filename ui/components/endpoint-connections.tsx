"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "@/lib/api";
import {
  type EndpointConnections,
  type EndpointInventory,
} from "@/lib/endpoint-connectors";
import { Drawer } from "@/components/drawer";

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
  const [page, setPage] = useState(0);
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
    <section className="space-y-4" aria-label="Endpoint inventory connections">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="font-semibold">Endpoint inventory</h2>
          <p className="text-sm text-[var(--text-secondary)]">
            Jamf management and Falcon sensor evidence. Sensor health is
            separate from policy compliance.
          </p>
        </div>
        <div className="flex gap-2">
          {!demo && (
            <button className={button} onClick={() => void refresh()}>
              Refresh endpoints
            </button>
          )}
          {canManage && !demo && (
            <button
              className={button}
              onClick={() => {
                setSelected("");
                setError("");
                setShowForm(true);
              }}
            >
              Connect endpoint provider
            </button>
          )}
        </div>
      </div>
      {demo && (
        <p className="text-sm text-[var(--text-secondary)]">
          Connect a provider in your authenticated control plane to collect
          endpoint evidence.
        </p>
      )}
      {error && !showForm && !selected && (
        <div role="alert" className="text-sm text-red-500">
          {error}{" "}
          <button className={button} onClick={() => void refresh()}>
            Retry
          </button>
        </div>
      )}
      <Drawer
        open={showForm}
        onClose={() => setShowForm(false)}
        title="Connect endpoint provider"
        size="2xl"
        ariaLabel="Connect endpoint provider"
      >
        {error && (
          <p role="alert" className="text-sm text-red-500 mb-3">
            {error}
          </p>
        )}
        <EndpointConnectionForm
          setError={setError}
          onCreated={async (id) => {
            setShowForm(false);
            await refresh();
            await inspect(id);
          }}
        />
      </Drawer>
      {!demo && rows.length === 0 && !error && (
        <p className="text-sm text-[var(--text-secondary)]">
          No endpoint connections configured.
        </p>
      )}
      <div className="grid max-h-[55vh] overflow-y-auto gap-3 lg:grid-cols-2">
        {rows
          .slice(page * 4, page * 4 + 4)
          .map(({ connection, sync: state }) => (
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
      {rows.length > 4 && (
        <div className="flex items-center gap-3 text-sm">
          <button
            className={button}
            disabled={page === 0}
            onClick={() => setPage(page - 1)}
          >
            Previous connections
          </button>
          <span>
            {page + 1} / {Math.ceil(rows.length / 4)}
          </span>
          <button
            className={button}
            disabled={(page + 1) * 4 >= rows.length}
            onClick={() => setPage(page + 1)}
          >
            Next connections
          </button>
        </div>
      )}
      <Drawer
        open={Boolean(selected)}
        onClose={() => {
          generation.current++;
          setSelected("");
          setInventory(null);
        }}
        title="Device evidence"
        subtitle={
          rows.find((row) => row.connection.id === selected)?.connection.name
        }
        size="5xl"
        ariaLabel="Endpoint device evidence"
      >
        {error && (
          <p role="alert" className="text-sm text-red-500 mb-3">
            {error}
          </p>
        )}
        <EndpointDeviceEvidence
          selected={selected}
          inventory={inventory}
          canManage={canManage}
          busy={busy}
          inspect={inspect}
          setBusy={setBusy}
          setError={setError}
        />
      </Drawer>
    </section>
  );
}
