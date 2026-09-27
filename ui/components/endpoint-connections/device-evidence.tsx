"use client";

import Link from "next/link";
import { api } from "@/lib/api";
import {
  type EndpointInventory,
  postureLabel,
} from "@/lib/endpoint-connectors";
import { field, button } from "./styles";

export function EndpointDeviceEvidence({
  selected,
  inventory,
  canManage,
  busy,
  inspect,
  setBusy,
  setError,
}: {
  selected: string;
  inventory: EndpointInventory | null;
  canManage: boolean;
  busy: boolean;
  inspect: (id: string, offset?: number) => Promise<void>;
  setBusy: (busy: boolean) => void;
  setError: (message: string) => void;
}) {
  return (
    <div className="space-y-3">
      <h3 className="font-medium">Device evidence</h3>
      {!inventory ? (
        <p className="text-sm">Loading evidence…</p>
      ) : (
        <>
          <p className="text-xs text-[var(--text-secondary)]">
            {inventory.sync?.status ?? "Not collected"} collection · device IDs
            are scoped to tenant and vendor account. Unknown posture does not
            satisfy access policy.
          </p>
          <details>
            <summary className="text-sm cursor-pointer">
              Recent collection receipts
            </summary>
            <ul className="mt-2 text-xs space-y-1">
              {inventory.recent_receipts?.map((receipt, index) => (
                <li key={`${receipt.run_id}-${index}`}>
                  {new Date(receipt.updated_at).toLocaleString()} ·{" "}
                  {receipt.status} · {receipt.device_count} devices
                  {receipt.gap ? ` · ${receipt.gap.replaceAll("_", " ")}` : ""}
                </li>
              ))}
            </ul>
          </details>
          <div className="grid gap-3 lg:grid-cols-2">
            {inventory.devices.map((device) => (
              <details
                key={device.device_id}
                className="rounded-lg border border-[var(--border-subtle)] p-3"
              >
                <summary className="text-sm cursor-pointer">
                  Agent associations · {device.hostname || "Unnamed device"}
                </summary>
                <p className="text-xs text-[var(--text-secondary)] my-2">
                  Exact, tenant-scoped IDs. Operator-recorded associations do
                  not prove installed software ran.
                </p>
                {Array.isArray(device.attributes.agent_bindings) &&
                  device.attributes.agent_bindings.map(
                    (binding: {
                      agent_id: string;
                      canonical_id: string;
                      active: boolean;
                      assurance: string;
                    }) => (
                      <div
                        className="text-sm flex gap-2"
                        key={binding.agent_id}
                      >
                        <Link
                          className="text-emerald-500 underline break-all"
                          href={`/agents?name=${encodeURIComponent(binding.canonical_id)}`}
                        >
                          {binding.agent_id}
                        </Link>
                        <span>
                          {binding.active ? "Associated" : "Retired"} · operator
                          recorded
                        </span>
                        {canManage && binding.active && (
                          <button
                            className={button}
                            disabled={busy}
                            onClick={async () => {
                              setBusy(true);
                              try {
                                await api.bindEndpointAgent(
                                  device.device_id,
                                  binding.agent_id,
                                  false,
                                );
                                await inspect(selected, inventory.offset);
                              } catch {
                                setError("Association could not be retired.");
                              } finally {
                                setBusy(false);
                              }
                            }}
                          >
                            Retire
                          </button>
                        )}
                      </div>
                    ),
                  )}
                {canManage && (
                  <form
                    className="flex gap-2 mt-2"
                    onSubmit={async (event) => {
                      event.preventDefault();
                      const form = event.currentTarget;
                      const data = new FormData(form);
                      setBusy(true);
                      setError("");
                      try {
                        await api.bindEndpointAgent(
                          device.device_id,
                          String(data.get("agent_id")),
                        );
                        await inspect(selected, inventory.offset);
                      } catch {
                        setError(
                          "Association rejected. Use an existing fleet agent ID in this tenant.",
                        );
                      } finally {
                        setBusy(false);
                      }
                    }}
                  >
                    <input
                      className={field}
                      name="agent_id"
                      required
                      aria-label={`Fleet agent ID for ${device.hostname || device.device_id}`}
                      placeholder="Exact fleet agent ID"
                    />
                    <button className={button} disabled={busy}>
                      Associate agent
                    </button>
                  </form>
                )}
              </details>
            ))}
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr>
                  {[
                    "Device",
                    "Freshness",
                    "Managed",
                    "Sensor healthy",
                    "Encrypted",
                    "Compliant",
                  ].map((x) => (
                    <th key={x} className="p-2">
                      {x}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {inventory.devices.map((device) => (
                  <tr
                    key={device.device_id}
                    className="border-t border-[var(--border-subtle)]"
                  >
                    <td className="p-2">
                      <span>
                        {device.hostname ||
                          (device.attributes.vendor_device_id as string)}
                      </span>
                      <details className="text-xs text-[var(--text-secondary)]">
                        <summary>Provenance</summary>
                        <p className="break-all">{device.device_id}</p>
                        <p>
                          Provider observed: {device.last_seen || "Unknown"}
                        </p>
                        <p>Collected: {device.observed_at}</p>
                      </details>
                    </td>
                    <td className="p-2">
                      {String(device.attributes.freshness ?? "unknown")}
                    </td>
                    <td className="p-2">{postureLabel(device.managed)}</td>
                    <td className="p-2">
                      {postureLabel(
                        typeof device.attributes.sensor_healthy === "boolean"
                          ? device.attributes.sensor_healthy
                          : null,
                      )}
                    </td>
                    <td className="p-2">
                      {postureLabel(device.disk_encrypted)}
                    </td>
                    <td className="p-2">{postureLabel(device.compliant)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {inventory.devices.length === 0 && (
            <p className="text-sm">No device evidence in this collection.</p>
          )}
          <div className="flex gap-2">
            <button
              className={button}
              disabled={inventory.offset === 0}
              onClick={() =>
                void inspect(
                  selected,
                  Math.max(0, inventory.offset - inventory.limit),
                )
              }
            >
              Previous devices
            </button>
            <button
              className={button}
              disabled={
                inventory.offset + inventory.devices.length >=
                (inventory.sync?.device_count ?? 0)
              }
              onClick={() =>
                void inspect(selected, inventory.offset + inventory.limit)
              }
            >
              Next devices
            </button>
          </div>
        </>
      )}
    </div>
  );
}
