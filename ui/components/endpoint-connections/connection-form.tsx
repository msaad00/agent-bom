"use client";

import { useState } from "react";
import { api } from "@/lib/api";
import { field, button } from "./styles";

export function EndpointConnectionForm({
  onCreated,
  setError,
}: {
  onCreated: (id: string) => Promise<void>;
  setError: (message: string) => void;
}) {
  const [provider, setProvider] = useState<"jamf" | "crowdstrike">("jamf");
  const [busy, setBusy] = useState(false);
  async function create(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const value = (key: string) => String(data.get(key) ?? "").trim();
    setBusy(true);
    setError("");
    try {
      const origin =
        provider === "jamf" ? new URL(value("jamf_url")).origin : "";
      const connection = await api.createEndpointConnection({
        name: value("name"),
        provider,
        account_id:
          provider === "jamf" ? new URL(origin).hostname : value("account_id"),
        jamf_url: origin,
        region: value("region") || "us1",
        client_id: value("client_id"),
        client_secret: String(data.get("client_secret") ?? ""),
      });
      form.reset();
      await onCreated(connection.id);
    } catch {
      setError(
        "Connection was not saved. Check fields, admin access, and server encryption configuration.",
      );
    } finally {
      const secret = form.elements.namedItem("client_secret");
      if (secret instanceof HTMLInputElement) secret.value = "";
      setBusy(false);
    }
  }

  return (
    <form onSubmit={create} className="grid gap-3 sm:grid-cols-2">
      <label className="text-sm">
        Provider
        <select
          className={field}
          value={provider}
          onChange={(e) =>
            setProvider(e.target.value as "jamf" | "crowdstrike")
          }
        >
          <option value="jamf">Jamf Pro</option>
          <option value="crowdstrike">CrowdStrike Falcon</option>
        </select>
      </label>
      <label className="text-sm">
        Connection name
        <input className={field} name="name" required maxLength={120} />
      </label>
      {provider === "jamf" ? (
        <label className="text-sm">
          Jamf instance URL
          <input
            className={field}
            name="jamf_url"
            type="url"
            required
            placeholder="https://your-instance.jamfcloud.com"
          />
        </label>
      ) : (
        <>
          <label className="text-sm">
            Customer CID (without checksum)
            <input
              className={field}
              name="account_id"
              required
              pattern="[a-fA-F0-9]{32}"
            />
          </label>
          <label className="text-sm">
            Falcon region
            <select className={field} name="region">
              {["us1", "us2", "eu1", "usgov1", "usgov2"].map((region) => (
                <option key={region}>{region}</option>
              ))}
            </select>
          </label>
        </>
      )}
      <label className="text-sm">
        Client ID
        <input className={field} name="client_id" required autoComplete="off" />
      </label>
      <label className="text-sm">
        Client secret
        <input
          className={field}
          name="client_secret"
          type="password"
          required
          autoComplete="new-password"
        />
      </label>
      <p className="text-xs text-[var(--text-secondary)] sm:col-span-2">
        Read-only grant:{" "}
        {provider === "jamf"
          ? "Read Computers (Jamf Pro inventory v4)."
          : "Hosts: Read."}{" "}
        Credentials are encrypted by the control plane. Saving does not collect
        inventory.
      </p>
      <button className={button} disabled={busy}>
        Save connection
      </button>
    </form>
  );
}
