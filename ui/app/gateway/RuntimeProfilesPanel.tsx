"use client";

import { useCallback, useEffect, useState } from "react";
import { api } from "@/lib/api";
import { ApiError } from "@/lib/api-errors";
import type { AgentIdentitySummary, McpClientConfigAssignment } from "@/lib/api-types";
import { useAuthState } from "@/components/auth-provider";

const inputClass = "mt-1 w-full min-w-0 rounded border border-[var(--border-subtle)] bg-[var(--surface)] px-3 py-2 text-sm text-[var(--foreground)]";
const split = (value: string) => [...new Set(value.split(",").map(item => item.trim()).filter(Boolean))];
const safeError = (error: unknown) => error instanceof ApiError && error.status === 409
  ? "This profile changed or its binding conflicts. Reload profiles before editing again."
  : error instanceof ApiError && [401, 403].includes(error.status) ? "Sign in with the required profile permission."
    : "The profile request failed. Check identity, blueprint, connector and tenant bindings, then retry.";

type Profile = McpClientConfigAssignment;
type Target = { upstream: string; tool: string };

export function RuntimeProfilesPanel() {
  const { session } = useAuthState();
  return <Profiles key={`${session?.tenant_id ?? ""}:${session?.subject ?? ""}`} />;
}

function Profiles() {
  const { hasCapability, session } = useAuthState();
  const canWrite = hasCapability("policy.manage");
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [identities, setIdentities] = useState<AgentIdentitySummary[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [editing, setEditing] = useState<Profile | "new" | null>(null);
  const [revoking, setRevoking] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [preview, setPreview] = useState<{ id: string; result: Awaited<ReturnType<typeof api.evaluateRuntimeProfile>> } | null>(null);
  const load = useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const response = await api.listRuntimeProfiles();
      if (!Array.isArray(response.assignments) || response.assignments.some(profile => !profile || (session?.tenant_id && profile.tenant_id !== session.tenant_id) ||
        ["config_id", "name", "identity_id", "profile_id", "environment", "issuer", "status"].some(key => typeof (profile as unknown as Record<string, unknown>)[key] !== "string") ||
        !Number.isSafeInteger(profile.revision) ||
        [profile.connector_ids, profile.allowed_tools, profile.required_scopes, profile.policy_ids, profile.connection_ids].some(values => !Array.isArray(values) || values.some(value => typeof value !== "string")))) throw new Error("Invalid profiles");
      setProfiles(response.assignments);
    } catch (caught) { setError(safeError(caught)); }
    finally { setLoading(false); }
  }, [session?.tenant_id]);
  useEffect(() => { const timer = setTimeout(() => void load(), 0); return () => clearTimeout(timer); }, [load]);
  const create = async () => {
    setBusy(true); setError(null);
    try { const response = await api.listIdentities(); setIdentities(response.identities.filter(item => item.status === "active")); setEditing("new"); setPreview(null); }
    catch (caught) { setError(safeError(caught)); }
    finally { setBusy(false); }
  };
  const validate = async (profile: Profile, target?: Target) => {
    setBusy(true); setPreview(null); setError(null);
    try {
      const result = await api.evaluateRuntimeProfile({ config_id: profile.config_id, issuer: profile.issuer, environment: profile.environment, granted_scopes: profile.required_scopes, ...target });
      if (result.scope !== "profile_contract_only" || result.executed !== false) throw new Error("Invalid preview");
      setPreview({ id: profile.config_id, result });
    } catch (caught) { setError(safeError(caught)); }
    finally { setBusy(false); }
  };
  const revoke = async (id: string) => {
    setBusy(true); setError(null);
    try { await api.revokeRuntimeProfile(id); setRevoking(null); setEditing(null); setPreview(null); await load(); }
    catch (caught) { setError(safeError(caught)); }
    finally { setBusy(false); }
  };
  return <section className="rounded-xl border border-[var(--border-subtle)] bg-[var(--surface)] p-4 sm:p-5" aria-label="Runtime profiles">
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div><h3 className="text-sm font-semibold">Managed runtime profiles</h3><p className="mt-1 max-w-2xl text-xs text-[var(--text-secondary)]">Bind an agent identity to its blueprint, environment, upstreams and tool constraints. Profile previews do not execute tools.</p></div>
      <div className="flex gap-2"><button onClick={() => { setEditing(null); setPreview(null); void load(); }} disabled={loading || busy} className="graph-page-action">Reload profiles</button>
        {canWrite && <button onClick={() => void create()} disabled={busy} className="graph-page-action">Create profile</button>}</div>
    </div>
    {!canWrite && <p className="mt-3 text-xs text-[var(--text-secondary)]">Read-only access. Profile creation, updates and revocation require config permission.</p>}
    {error && <p role="alert" className="mt-3 text-sm text-red-700 dark:text-red-300">{error}</p>}
    {preview && <div role="status" className="my-3 border-l-2 border-[var(--border-subtle)] pl-3 text-sm">
      <p className="break-all">{preview.id}: {preview.result.profile_allowed ? "Profile contract allows this context" : "Profile contract denies this context"} · {preview.result.reason_code}</p>
      <p className="mt-1 text-xs text-[var(--text-secondary)]">Simulation only. No tool executed, caller credential verified, or firewall, DLP, policy or quota check performed.</p>
    </div>}
    {editing && <ProfileEditor key={editing === "new" ? "new" : `${editing.config_id}:${editing.revision}`} profile={editing === "new" ? null : editing} identities={identities} canWrite={canWrite} busy={busy}
      onCancel={() => { setEditing(null); setPreview(null); }} onSave={async body => {
        setBusy(true); setError(null);
        try { if (editing === "new") await api.createRuntimeProfile(body); else await api.updateRuntimeProfile(editing.config_id, body); setEditing(null); setPreview(null); await load(); }
        catch (caught) { setError(safeError(caught)); }
        finally { setBusy(false); }
      }} onTest={(profile, target) => void validate(profile, target)} />}
    {loading ? <p className="py-6 text-sm" role="status">Loading profiles…</p> : !profiles.length ? <p className="py-6 text-sm text-[var(--text-secondary)]">No runtime profiles in this tenant. Create a managed identity first, then bind its runtime profile.</p> :
      <div className="mt-4 divide-y divide-[var(--border-subtle)]">{profiles.map(profile => <article key={profile.config_id} className="min-w-0 py-3 text-xs">
        <div className="flex flex-wrap items-start justify-between gap-2">
          <div className="min-w-0"><h4 className="break-all font-semibold">{profile.name} · {profile.status} · revision {profile.revision}</h4>
            <p className="mt-1 break-all text-[var(--text-secondary)]">{profile.config_id} · identity {profile.identity_id || "Legacy unbound assignment"} · blueprint {profile.profile_id} · {profile.environment || "Environment unavailable"}</p></div>
          <div className="flex flex-wrap gap-2"><button className="graph-page-action" disabled={busy} onClick={() => { setEditing(profile); setPreview(null); }}>Inspect profile</button>
            <button className="graph-page-action" disabled={busy} onClick={() => void validate(profile)}>Validate profile</button>
            {canWrite && !profile.revoked && <button className="graph-page-action" disabled={busy} onClick={() => setRevoking(profile.config_id)}>Revoke profile</button>}</div>
        </div>
        <p className="mt-2 break-all text-[var(--text-secondary)]">Upstreams: {profile.connector_ids.join(", ")} · tools: {profile.allowed_tools.join(", ") || "inherited constraints"}</p>
        <p className="mt-1 break-all text-[var(--text-secondary)]">Policies: {profile.policy_ids.join(", ") || "none"} · scopes: {profile.required_scopes.join(", ") || "none"} · expires {profile.expires_at || "no profile expiry"}</p>
        {revoking === profile.config_id && <div className="mt-3 flex flex-wrap items-center gap-3" role="group" aria-label="Confirm profile revocation"><p>Revoke {profile.name}? Its managed gateway calls will be denied.</p><button className="graph-page-action" disabled={busy} onClick={() => void revoke(profile.config_id)}>Confirm revoke</button><button className="graph-page-action" onClick={() => setRevoking(null)}>Cancel revocation</button></div>}
      </article>)}</div>}
    {profiles.length === 1000 && <p className="mt-3 text-xs">Showing the API limit of 1,000 assignments; this list may be partial.</p>}
  </section>;
}

function ProfileEditor({ profile, identities, canWrite, busy, onCancel, onSave, onTest }: {
  profile: Profile | null; identities: AgentIdentitySummary[]; canWrite: boolean; busy: boolean;
  onCancel: () => void; onSave: (body: Record<string, unknown>) => Promise<void>; onTest: (profile: Profile, target: Target) => void;
}) {
  const [name, setName] = useState(profile?.name ?? "");
  const [identity, setIdentity] = useState(profile?.identity_id ?? "");
  const [environment, setEnvironment] = useState(profile?.environment ?? "prod");
  const [fields, setFields] = useState({ connector_ids: profile?.connector_ids.join(", ") ?? "", allowed_tools: profile?.allowed_tools.join(", ") ?? "", required_scopes: profile?.required_scopes.join(", ") ?? "", policy_ids: profile?.policy_ids.join(", ") ?? "", connection_ids: profile?.connection_ids.join(", ") ?? "" });
  const [expires, setExpires] = useState(profile?.expires_at ?? "");
  const [target, setTarget] = useState(profile?.connector_ids[0] ?? "");
  const [tool, setTool] = useState(profile?.allowed_tools[0] ?? "");
  const blueprint = profile?.profile_id ?? identities.find(item => item.identity_id === identity)?.blueprint_id;
  const writable = canWrite && !profile?.revoked;
  const labels = { connector_ids: "Upstream connector IDs", allowed_tools: "Allowed tools", required_scopes: "Required scopes", policy_ids: "Policy IDs", connection_ids: "Connection references" };
  return <div className="my-4 border-y border-[var(--border-subtle)] py-4">
    <h4 className="text-sm font-semibold">{profile ? `Profile revision ${profile.revision}` : "New managed profile"}</h4>
    <form onSubmit={event => {
      event.preventDefault(); if (!writable || !blueprint) return;
      void onSave({ name, profile_id: blueprint, environment, ...Object.fromEntries(Object.entries(fields).map(([key, value]) => [key, split(value)])), expires_at: expires, ...(profile ? { expected_revision: profile.revision } : { identity_id: identity, issuer: "agent-bom" }) });
    }}>
      <fieldset disabled={!writable || busy} className="mt-3 grid min-w-0 gap-3 sm:grid-cols-2">
        <label className="text-xs">Profile name<input className={inputClass} required maxLength={200} value={name} onChange={e => setName(e.target.value)} /></label>
        {!profile ? <label className="text-xs">Managed identity<select className={inputClass} required value={identity} onChange={e => setIdentity(e.target.value)}><option value="">Select an active identity</option>{identities.map(item => <option key={item.identity_id} value={item.identity_id}>{item.agent_id} · {item.blueprint_id}</option>)}</select></label> : null}
        <label className="text-xs">Environment<input className={inputClass} required maxLength={120} value={environment} onChange={e => setEnvironment(e.target.value)} /></label>
        {(Object.keys(labels) as (keyof typeof fields)[]).map(key => <label key={key} className="text-xs">{labels[key]} (comma separated)<input className={inputClass} required={key === "connector_ids"} value={fields[key]} onChange={e => setFields(current => ({ ...current, [key]: e.target.value }))} /></label>)}
        <label className="text-xs">Expiry (ISO timestamp, optional)<input className={inputClass} value={expires} onChange={e => setExpires(e.target.value)} /></label>
      </fieldset>
      <p className="mt-3 text-xs text-[var(--text-secondary)]">Blueprint: {blueprint || "select an identity"}. Connector IDs must exist in the registry. Connections are tenant-owned references, never credentials.</p>
      <div className="mt-3 flex gap-2">{writable && <button className="graph-page-action" disabled={busy || !blueprint} type="submit">{profile ? "Save profile revision" : "Create managed profile"}</button>}<button type="button" className="graph-page-action" onClick={onCancel}>Close profile</button></div>
    </form>
    {profile && <div className="mt-4 border-t border-[var(--border-subtle)] pt-4"><p className="text-xs text-[var(--text-secondary)]">Test the saved revision using its recorded issuer, environment and required scopes. Unsaved edits are excluded.</p>
      <div className="mt-2 grid gap-3 sm:grid-cols-2"><label className="text-xs">Test upstream<input className={inputClass} value={target} onChange={e => setTarget(e.target.value)} /></label><label className="text-xs">Test tool<input className={inputClass} value={tool} onChange={e => setTool(e.target.value)} /></label></div>
      <button className="graph-page-action mt-3" disabled={busy || !target.trim() || !tool.trim()} onClick={() => onTest(profile, { upstream: target.trim(), tool: tool.trim() })}>Test saved profile</button></div>}
  </div>;
}
