"use client";
import { ErrorBanner } from "@/components/empty-state";

import { Collapsible } from "@/components/collapsible";
import { PROVIDER_OPTIONS,providerOption } from "@/components/connections/catalog";
import { ProviderLogo } from "@/components/connections/display";
import { ConnectDepthControl,CopyTextButton,GrantMethodPicker,SnowflakePackagingPicker } from "@/components/connections/wizard-controls";
import { buildWizardForm,StepIndicator,type VerifyState,type WizardForm,type WizardStep } from "@/components/connections/wizard-support";
import {
  api,
  type CloudConnectionCreateRequest,
  type CloudConnectionRecord,
  type DiscoveryProvidersResponse,
  type ManagedTrialEnvelope
} from "@/lib/api";
import {
  buildAwsOrgStackSetScript,
  buildGrantScript,
  buildSnowflakeSpcsScript,
  cloudGrantMethodLabel,
  cloudProviderMeta,
  DEFAULT_AWS_ORG_ROLE_NAME,
  generateConnectionExternalId,
  type CloudGrantMethod,
  type ConnectDepth
} from "@/lib/cloud-connect-wizard";
import {
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  CheckCircle2,
  Loader2,
  Lock,
  Plus,
  RefreshCcw,
  ShieldCheck,
  X
} from "lucide-react";
import Link from "next/link";
import { useCallback,useEffect,useMemo,useRef,useState } from "react";


export function AddConnectionWizard({
  workloadAuthModes,
  providerContracts,
  initialProvider,
  managedTrial,
  managedTrialEnvelope,
  providerConnectionCount,
  onClose,
  onCreated,
}: {
  workloadAuthModes: Record<string, string[]>;
  providerContracts: DiscoveryProvidersResponse | null;
  initialProvider?: string | undefined;
  managedTrial: boolean;
  managedTrialEnvelope: ManagedTrialEnvelope | null;
  providerConnectionCount: number;
  onClose: () => void;
  onCreated: (created: CloudConnectionRecord) => void;
}) {
  const dialogRef = useRef<HTMLDivElement>(null);
  const [step, setStep] = useState<WizardStep>(0);
  const [form, setForm] = useState<WizardForm>(() =>
    buildWizardForm(initialProvider && providerOption(initialProvider) ? initialProvider : "aws"),
  );
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [generatedExternalId, setGeneratedExternalId] = useState("");
  const [grantMethod, setGrantMethod] = useState<CloudGrantMethod>("cli");
  // AWS onboarding scope: a single account, or the whole AWS Organization via a
  // CloudFormation StackSet (deploy once, every member account auto-enrolls).
  const [awsScope, setAwsScope] = useState<"account" | "organization">("account");
  // Connect depth (progressive disclosure): baseline (least privilege, default)
  // vs opt-in read-only deep-scan + optional bucket-scoped DSPM object read.
  const [deepScan, setDeepScan] = useState(false);
  const [dspmBucketsText, setDspmBucketsText] = useState("");
  // Explicit "All regions" affordance (AWS): scan every enabled region instead of
  // a single free-text region.
  const [allRegions, setAllRegions] = useState(false);
  // Snowflake packaging: read-only metadata role (default) vs the Snowpark
  // Container Services / Native App (run agent-bom inside the account).
  const [snowflakeSpcs, setSnowflakeSpcs] = useState(false);
  // Verify step: the created connection + the live connectivity/permission check
  // and optional first scan run against the real /test and /scan endpoints.
  const [createdRecord, setCreatedRecord] = useState<CloudConnectionRecord | null>(null);
  const [verifyState, setVerifyState] = useState<VerifyState>("idle");
  const [verifyError, setVerifyError] = useState<string | null>(null);
  const [scanState, setScanState] = useState<VerifyState>("idle");
  const [scanError, setScanError] = useState<string | null>(null);
  const [scanId, setScanId] = useState<string | null>(null);

  useEffect(() => {
    const previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const dialog = dialogRef.current;
    const focusableSelector =
      'button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), a[href]';
    const focusable = () => Array.from(dialog?.querySelectorAll<HTMLElement>(focusableSelector) ?? []);
    focusable()[0]?.focus();

    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        event.preventDefault();
        onClose();
        return;
      }
      if (event.key !== "Tab") return;
      const items = focusable();
      if (items.length === 0) return;
      const first = items[0]!;
      const last = items[items.length - 1]!;
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    }

    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("keydown", handleKeyDown);
      previousFocus?.focus();
    };
  }, [onClose]);

  const provider = useMemo(
    () => providerOption(form.provider) ?? PROVIDER_OPTIONS[0]!,
    [form.provider],
  );

  const supportedAuthModes = workloadAuthModes[provider.value] ?? [];
  const selectedAuthMode = form.auth.auth_mode ?? supportedAuthModes[0] ?? "";
  const usesWorkloadBinding = supportedAuthModes.includes(selectedAuthMode);
  const usesSnowflakeWorkload = provider.value === "snowflake" && usesWorkloadBinding;
  const activeAuthFields = usesSnowflakeWorkload ? [] : provider.authFields;
  const isAws = provider.value === "aws";
  const managedTrialProviders = managedTrialEnvelope?.providers ?? [];

  useEffect(() => {
    if (!isAws) return;
    setGeneratedExternalId((current) => current || generateConnectionExternalId());
  }, [isAws]);

  useEffect(() => {
    if (!isAws || !generatedExternalId) return;
    setForm((current) =>
      current.external_id === generatedExternalId
        ? current
        : { ...current, external_id: generatedExternalId },
    );
  }, [isAws, generatedExternalId]);

  function update<K extends keyof WizardForm>(field: K, value: WizardForm[K]) {
    setForm((current) => ({ ...current, [field]: value }));
  }

  function updateAuth(key: string, value: string) {
    setForm((current) => ({ ...current, auth: { ...current.auth, [key]: value } }));
  }

  function selectProvider(value: string) {
    if (managedTrial && !managedTrialProviders.includes(value)) return;
    setForm((current) => {
      if (current.provider === value) return current;
      setGeneratedExternalId("");
      setAwsScope("account");
      setDeepScan(false);
      setDspmBucketsText("");
      setAllRegions(false);
      setSnowflakeSpcs(false);
      return {
        ...current,
        provider: value,
        role_ref: "",
        external_id: "",
        regions: "",
        auth: {},
      };
    });
  }

  function goNext() {
    setStep((current) => (current === 3 ? current : ((current + 1) as WizardStep)));
  }

  function handleRegenerateExternalId() {
    const value = generateConnectionExternalId();
    setGeneratedExternalId(value);
    setForm((current) => ({ ...current, external_id: value }));
  }

  const runVerify = useCallback(async (record: CloudConnectionRecord) => {
    setVerifyState("running");
    setVerifyError(null);
    try {
      await api.testCloudConnection(record.id);
      setVerifyState("ok");
    } catch (err) {
      // Surface the sanitized "why + how to fix" from the API verbatim — never a
      // fabricated success. A failed verify keeps the connection in error state.
      setVerifyError(err instanceof Error ? err.message : "Connectivity check failed.");
      setVerifyState("error");
    }
  }, []);

  async function runFirstScan() {
    if (!createdRecord) return;
    setScanState("running");
    setScanError(null);
    try {
      const result = await api.scanCloudConnection(createdRecord.id);
      setScanId(typeof result.job_id === "string" ? result.job_id : null);
      setScanState("ok");
    } catch (err) {
      setScanError(err instanceof Error ? err.message : "First scan failed.");
      setScanState("error");
    }
  }

  // Auto-run the real connectivity/permission check on entering the Verify step.
  useEffect(() => {
    if (step === 3 && createdRecord && verifyState === "idle") {
      void runVerify(createdRecord);
    }
  }, [step, createdRecord, verifyState, runVerify]);

  const providerMeta = cloudProviderMeta(provider.value);
  const isSnowflake = provider.value === "snowflake";
  const supportsDepth = provider.value === "aws" || provider.value === "azure" || provider.value === "gcp";
  const dspmBuckets = dspmBucketsText
    .split(/[\s,]+/)
    .map((b) => b.trim())
    .filter(Boolean);
  const depth: ConnectDepth = { deepScan: deepScan || dspmBuckets.length > 0, dspmBuckets };
  const deployScript = buildGrantScript(
    provider.value,
    grantMethod,
    isAws ? generatedExternalId || undefined : undefined,
    supportsDepth ? depth : undefined,
  );
  const snowflakeSpcsScript = buildSnowflakeSpcsScript({ account: form.role_ref.trim() });
  const isOrgScope = isAws && awsScope === "organization";
  const orgStackSetScript = buildAwsOrgStackSetScript(
    generatedExternalId || undefined,
    DEFAULT_AWS_ORG_ROLE_NAME,
  );

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    // Only the Details step creates the connection; guard against Enter on
    // other steps re-submitting (and re-creating) an existing connection.
    if (step !== 2) return;
    setFormError(null);

    const displayName = form.display_name.trim();
    const roleRef = form.role_ref.trim();
    const externalId = form.external_id;
    const regions = !provider.usesRegions
      ? []
      : allRegions
        ? ["all"]
        : form.regions
            .split(/[\s,]+/)
            .map((region) => region.trim())
            .filter(Boolean);

    if (managedTrial) {
      if (!managedTrialEnvelope) {
        setFormError("Managed trial limits are unavailable. Refresh before creating a connection.");
        return;
      }
      if (!managedTrialEnvelope.providers.includes(form.provider)) {
        setFormError("This provider is unavailable in the managed trial.");
        return;
      }
      if (
        regions.length === 0 ||
        regions.length > managedTrialEnvelope.max_regions ||
        regions.includes("all")
      ) {
        setFormError(
          `Managed trial connections require one to ${managedTrialEnvelope.max_regions} explicit AWS regions.`,
        );
        return;
      }
    }

    if (!displayName) {
      setFormError("A display name is required.");
      return;
    }
    if (!roleRef) {
      setFormError(`${provider.roleField.label} is required.`);
      return;
    }
    const authParams: Record<string, string> = {};
    for (const field of activeAuthFields) {
      const value = (form.auth[field.key] ?? "").trim();
      if (!value) {
        setFormError(`${field.label} is required.`);
        return;
      }
      authParams[field.key] = value;
    }
    if (usesWorkloadBinding) {
      const binding = (form.auth.credential_binding ?? "").trim();
      if (!binding) { setFormError("Operator binding ID is required."); return; }
      if (usesSnowflakeWorkload) authParams.account = roleRef;
      authParams.auth_mode = selectedAuthMode;
      authParams.credential_binding = binding;
    }
    if (!usesWorkloadBinding && !externalId.trim()) {
      setFormError(`${provider.secretField.label} is required.`);
      return;
    }

    const payload: CloudConnectionCreateRequest = {
      provider: form.provider,
      display_name: displayName,
      role_ref: roleRef,
      external_id: usesWorkloadBinding ? "" : externalId,
      regions,
      auth_params: authParams,
      inventory_scope: managedTrial ? "account" : isAws && awsScope === "organization" ? "organization" : "account",
      scan_mode: managedTrial ? "full" : form.scan_mode,
      auto_scan_on_create: managedTrial ? false : form.auto_scan_on_create,
    };

    setSubmitting(true);
    try {
      const created = await api.createCloudConnection(payload);
      // Drop the secret from client state the moment it is persisted.
      setForm((current) => ({ ...current, external_id: "" }));
      setCreatedRecord(created);
      if (created.last_scan_id) {
        setScanId(created.last_scan_id);
        setScanState("ok");
      }
      // Refresh the background list + toast, but keep the wizard open so the
      // operator sees the live Verify step before finishing.
      onCreated(created);
      setStep(3);
    } catch (err) {
      setFormError(err instanceof Error ? err.message : "Failed to create connection.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div
      ref={dialogRef}
      className="fixed inset-0 z-[130] flex items-start justify-center overflow-y-auto bg-black/60 p-4 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-label="Add cloud account"
      onClick={onClose}
    >
      <div
        className="my-8 w-full max-w-xl rounded-2xl border border-outline bg-surface shadow-2xl shadow-black/40"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-outline px-5 py-4">
          <div className="flex items-center gap-3">
            <span className="flex h-10 w-10 items-center justify-center rounded-xl border border-outline bg-surface-elevated">
              <ProviderLogo provider={provider.value} className="h-5 w-5" />
            </span>
            <div>
              <h2 className="text-base font-semibold text-foreground">Add cloud account</h2>
              <p className="text-xs text-ink-secondary">Read-only connection · step {step + 1} of 4</p>
            </div>
          </div>
          <button
            onClick={onClose}
            aria-label="Close"
            className="rounded-lg p-1.5 text-ink-secondary transition hover:bg-surface-elevated hover:text-foreground"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <form onSubmit={handleSubmit}>
          <div className="space-y-5 px-5 py-5">
            <StepIndicator step={step} />

            {step === 0 ? (
              <fieldset className="space-y-3">
                <legend className="text-xs font-medium uppercase tracking-[0.18em] text-ink-tertiary">
                  Choose a provider
                </legend>
                {managedTrial ? (
                  managedTrialEnvelope ? (
                    <div className="rounded-xl border border-sky-500/30 bg-sky-500/10 px-3 py-2.5 text-[11px] leading-5 text-ink-secondary">
                      <p className="font-medium text-foreground">
                        {providerConnectionCount} of {managedTrialEnvelope.cloud_connections_per_provider} AWS connections
                      </p>
                      <p>
                        {managedTrialEnvelope.scan_credits_24h} scans per rolling 24 hours ·{" "}
                        {managedTrialEnvelope.active_scan_jobs === 1
                          ? "one"
                          : managedTrialEnvelope.active_scan_jobs} active scan
                        {managedTrialEnvelope.active_scan_jobs === 1 ? "" : "s"} and{" "}
                        {managedTrialEnvelope.retained_scan_jobs} retained jobs
                      </p>
                    </div>
                  ) : (
                    <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 px-3 py-2.5 text-[11px] text-amber-700 dark:text-amber-200">
                      Trial limits are unavailable. Refresh before creating a connection.
                    </div>
                  )
                ) : null}
                <div className="grid gap-2 sm:grid-cols-2">
                  {PROVIDER_OPTIONS.filter(
                    (option) => !managedTrial || managedTrialProviders.includes(option.value),
                  ).map((option) => {
                    const selected = form.provider === option.value;
                    return (
                      <button
                        type="button"
                        key={option.value}
                        onClick={() => selectProvider(option.value)}
                        aria-pressed={selected}
                        className={`flex items-center gap-3 rounded-xl border p-3 text-left transition ${
                          selected
                            ? "border-emerald-500 bg-emerald-950/20"
                            : "border-outline bg-surface-elevated hover:border-outline-strong"
                        }`}
                      >
                        <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-outline bg-surface">
                          <ProviderLogo provider={option.value} className="h-5 w-5" />
                        </span>
                        <span className="min-w-0">
                          <span className="block text-sm font-medium text-foreground">{option.label}</span>
                          <span className="mt-0.5 block text-[11px] text-ink-secondary">{option.tagline}</span>
                          {cloudProviderMeta(option.value) ? (
                            <span className="mt-1 block text-[10px] uppercase tracking-[0.12em] text-purple-700 dark:text-purple-300/80">
                              Read-only broker
                            </span>
                          ) : null}
                        </span>
                      </button>
                    );
                  })}
                </div>
                {supportedAuthModes.length > 0 ? (
                  <label className="block text-sm">
                    <span className="mb-2 block font-medium">Authentication method</span>
                    <select aria-label="Authentication method" value={selectedAuthMode} onChange={(event) => setForm(current => ({ ...current, external_id: "", auth: { ...current.auth, auth_mode: event.target.value, credential_binding: "" } }))} className="w-full rounded-lg border border-outline bg-surface p-2">
                      {supportedAuthModes.map((mode, index) => <option key={mode} value={mode}>{mode === "managed_identity" ? "Managed identity" : provider.value === "snowflake" ? "Native App workload identity" : "Workload identity"}{index === 0 ? " (recommended)" : ""}</option>)}
                      <option value="">Encrypted {provider.value === "gcp" ? "service-account key" : provider.value === "snowflake" ? "private key" : "client secret"} (legacy)</option>
                    </select>
                    <span className="mt-1 block text-xs text-ink-secondary">Workload authentication requires an operator-configured binding. Access is verified separately.</span>
                  </label>
                ) : null}
                <section aria-label="Server SDK prerequisites" className="rounded-xl border border-outline p-3 text-sm">
                  <p className="font-medium">Server SDK prerequisites</p>
                  {(providerContracts?.providers.find((item) => item.name === form.provider)?.sdk_readiness ?? []).map((sdk) => (
                    <p key={sdk.distribution}>{sdk.distribution}: {sdk.status === "ok" ? "installed" : sdk.status.replaceAll("_", " ")}{sdk.installed_version ? ` (${sdk.installed_version})` : ""}</p>
                  ))}
                  {!providerContracts?.providers.find((item) => item.name === form.provider)?.sdk_readiness?.length && <p>SDK readiness unavailable.</p>}
                  <p className="mt-2">Install in the control-plane environment before configuring credentials:</p>
                  <code className="block break-all">{`pip install 'agent-bom[ui,${form.provider}]'`}</code>
                  <p className="mt-2 text-ink-secondary">SDK checks do not verify cloud credentials or collection permissions.</p>
                </section>
              </fieldset>
            ) : null}

            {step === 1 && usesWorkloadBinding ? (
              <section aria-label="Workload setup" className="space-y-3 text-sm">
                <h3 className="font-semibold">Operator-managed workload binding</h3>
                <p>{usesSnowflakeWorkload ? "Requires a control plane running inside the Snowflake Native App. Ask your operator for a read-only binding matching this tenant and the service’s injected account. The service uses Snowflake’s rotating workload identity; user, role, warehouse and token paths cannot be selected here." : "Ask your operator for a read-only binding ID for this tenant, provider, identity and subscription or project. The control plane exchanges the configured workload identity for provider credentials."}</p>
                <p className="text-ink-secondary">Enter the binding ID in the next step. No password, client secret or service-account key is collected. Creating a connection does not prove access; use Verify after creation.</p>
                <p className="text-ink-secondary">The operator manages the binding’s scope, expiry and revocation. No file path or credential should be pasted into the binding field.</p>
              </section>
            ) : step === 1 ? (
              <div className="space-y-3">
                <p className="text-xs font-medium uppercase tracking-[0.18em] text-ink-tertiary">
                  Grant read-only access
                </p>
                <div className="rounded-xl border border-outline bg-surface-elevated p-4 text-xs leading-6 text-ink-secondary">
                  {isAws ? (
                    <div
                      role="group"
                      aria-label="AWS onboarding scope"
                      className="mb-3 grid grid-cols-2 gap-1 rounded-xl border border-outline bg-surface-muted p-1"
                    >
                      {(managedTrial ? (["account"] as const) : (["account", "organization"] as const)).map((scope) => {
                        const active = awsScope === scope;
                        return (
                          <button
                            key={scope}
                            type="button"
                            aria-pressed={active}
                            onClick={() => setAwsScope(scope)}
                            className={`rounded-lg px-2.5 py-1.5 text-[11px] font-medium transition ${
                              active
                                ? "bg-emerald-500 text-black"
                                : "text-ink-secondary hover:text-foreground"
                            }`}
                          >
                            {scope === "account" ? "Single account" : "Whole organization"}
                          </button>
                        );
                      })}
                    </div>
                  ) : null}
                  <p className="text-foreground">
                    {isOrgScope ? (
                      "Deploy one CloudFormation StackSet from your AWS Organization management (or delegated-admin) account. That grant mints the read-only role in every member account and auto-enrolls new ones — then paste this management account's role ARN in the next step. This connection is stored with inventory_scope=organization so Run scan fans out across member accounts (member roles must be deployed)."
                    ) : (
                      <>
                        Run this in your {provider.label} to create the read-only grant, then paste the{" "}
                        {provider.roleField.label.toLowerCase()} in the next step.
                      </>
                    )}
                  </p>
                  {isOrgScope ? (
                    <div className="mt-4 space-y-2" data-testid="wizard-org-explainer">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <p className="text-[10px] font-medium uppercase tracking-[0.14em] text-ink-tertiary">
                          Organization StackSet
                        </p>
                        <CopyTextButton text={orgStackSetScript} label="Copy StackSet" />
                      </div>
                      <pre
                        data-testid="wizard-org-stackset"
                        className="max-h-52 overflow-auto rounded-lg border border-outline bg-surface-muted p-2.5 font-mono text-[10px] leading-5 text-foreground"
                      >
                        {orgStackSetScript}
                      </pre>
                      <ul className="space-y-1 text-[11px] text-ink-secondary">
                        <li className="flex items-start gap-1.5">
                          <CheckCircle2 className="mt-0.5 h-3 w-3 shrink-0 text-emerald-400" />
                          Deploy once from the management account or a delegated admin — every member account gets the
                          same read-only <code className="font-mono">agent-bom-readonly</code> role.
                        </li>
                        <li className="flex items-start gap-1.5">
                          <CheckCircle2 className="mt-0.5 h-3 w-3 shrink-0 text-emerald-400" />
                          New accounts added to the org or OU auto-enroll automatically — no per-account onboarding.
                        </li>
                        <li className="flex items-start gap-1.5">
                          <Lock className="mt-0.5 h-3 w-3 shrink-0 text-emerald-400" />
                          Read-only least-privilege (SecurityAudit / ViewOnlyAccess), assumed via short-lived STS with
                          this ExternalId — no static keys, no per-action credentials.
                        </li>
                        <li className="flex items-start gap-1.5">
                          <CheckCircle2 className="mt-0.5 h-3 w-3 shrink-0 text-emerald-400" />
                          With Whole organization selected, this connection stores{" "}
                          <code className="font-mono">inventory_scope=organization</code> so Connections Run scan
                          fans out across member accounts (StackSet must have deployed the member roles). CLI /
                          Helm scanner Jobs still use <code className="font-mono">AGENT_BOM_AWS_ORG_INVENTORY</code>{" "}
                          when you scan outside Connections.
                        </li>
                      </ul>
                    </div>
                  ) : (
                    <div className="mt-4 space-y-2">
                      {isSnowflake ? (
                        <SnowflakePackagingPicker spcs={snowflakeSpcs} onChange={setSnowflakeSpcs} />
                      ) : null}
                      {isSnowflake && snowflakeSpcs ? (
                        <>
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <p className="text-[10px] font-medium uppercase tracking-[0.14em] text-ink-tertiary">
                              Snowpark native-app install (SQL)
                            </p>
                            <CopyTextButton text={snowflakeSpcsScript} label="Copy script" />
                          </div>
                          <pre
                            data-testid="wizard-snowflake-spcs"
                            className="max-h-52 overflow-auto rounded-lg border border-outline bg-surface-muted p-2.5 font-mono text-[10px] leading-5 text-foreground"
                          >
                            {snowflakeSpcsScript}
                          </pre>
                        </>
                      ) : (
                        <>
                          <GrantMethodPicker method={grantMethod} onChange={setGrantMethod} provider={provider.value} />
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <p className="text-[10px] font-medium uppercase tracking-[0.14em] text-ink-tertiary">
                              {cloudGrantMethodLabel(grantMethod)} grant script
                            </p>
                            {deployScript ? <CopyTextButton text={deployScript} label="Copy script" /> : null}
                          </div>
                          <pre className="max-h-40 overflow-auto rounded-lg border border-outline bg-surface-muted p-2.5 font-mono text-[10px] leading-5 text-foreground">
                            {deployScript || provider.cli}
                          </pre>
                        </>
                      )}
                      {supportsDepth ? (
                        <ConnectDepthControl
                          provider={provider.value}
                          deepScan={deepScan}
                          onDeepScanChange={setDeepScan}
                          dspmBucketsText={dspmBucketsText}
                          onDspmBucketsChange={setDspmBucketsText}
                        />
                      ) : null}
                    </div>
                  )}
                  {isAws ? (
                    <div className="mt-3 flex flex-wrap items-center justify-between gap-2 rounded-lg border border-emerald-900/50 bg-emerald-950/20 px-2.5 py-2">
                      <div className="min-w-0">
                        <p className="text-[10px] font-medium uppercase tracking-[0.14em] text-emerald-200/80">
                          ExternalId (embedded in the script above)
                        </p>
                        {generatedExternalId ? (
                          <p data-testid="wizard-external-id" className="break-all font-mono text-[11px] text-foreground">
                            {generatedExternalId}
                          </p>
                        ) : null}
                      </div>
                      <div className="flex items-center gap-1.5">
                        {generatedExternalId ? <CopyTextButton text={generatedExternalId} label="Copy" /> : null}
                        <button
                          type="button"
                          onClick={handleRegenerateExternalId}
                          className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-700/60 bg-emerald-500/10 px-2.5 py-1 text-[11px] font-medium text-emerald-700 dark:text-emerald-200 transition hover:border-emerald-500"
                        >
                          <RefreshCcw className="h-3 w-3" />
                          Regenerate
                        </button>
                      </div>
                    </div>
                  ) : null}
                  <Collapsible
                    title="How this works & security"
                    defaultOpen={false}
                    bare
                    className="mt-3"
                    titleClassName="text-[11px] font-medium uppercase tracking-[0.14em] text-ink-tertiary"
                  >
                    <ul className="mt-2 space-y-1 text-[11px] text-ink-secondary">
                      {providerMeta?.deployNotes.map((note) => (
                        <li key={note} className="flex items-start gap-1.5">
                          <CheckCircle2 className="mt-0.5 h-3 w-3 shrink-0 text-emerald-400" />
                          {note}
                        </li>
                      ))}
                      {isAws ? (
                        <li className="flex items-start gap-1.5">
                          <CheckCircle2 className="mt-0.5 h-3 w-3 shrink-0 text-emerald-400" />
                          The ExternalId is embedded in the grant script and is what the connection stores — it carries
                          to the next step unchanged. Regenerate only before you apply the grant.
                        </li>
                      ) : null}
                      <li className="flex items-start gap-1.5">
                        <Lock className="mt-0.5 h-3 w-3 shrink-0 text-emerald-400" />
                        The {provider.secretField.label.toLowerCase()} is stored encrypted at rest and never displayed
                        again.
                      </li>
                    </ul>
                  </Collapsible>
                </div>
              </div>
            ) : null}

            {step === 2 ? (
              <div className="space-y-4">
                <label className="block">
                  <span className="mb-1.5 block text-xs font-medium uppercase tracking-[0.18em] text-ink-tertiary">
                    Display name
                  </span>
                  <input
                    value={form.display_name}
                    onChange={(event) => update("display_name", event.target.value)}
                    placeholder="Production account"
                    className="w-full rounded-xl border border-outline bg-surface-elevated px-3 py-2 text-sm text-foreground outline-none transition focus:border-emerald-500"
                  />
                </label>
                <label className="block">
                  <span className="mb-1.5 block text-xs font-medium uppercase tracking-[0.18em] text-ink-tertiary">
                    {provider.roleField.label}
                  </span>
                  <input
                    value={form.role_ref}
                    onChange={(event) => update("role_ref", event.target.value)}
                    placeholder={provider.roleField.placeholder}
                    className={`w-full rounded-xl border border-outline bg-surface-elevated px-3 py-2 text-sm text-foreground outline-none transition focus:border-emerald-500 ${provider.roleField.mono ? "font-mono" : ""}`}
                  />
                </label>
                {activeAuthFields.map((field) => (
                  <label key={field.key} className="block">
                    <span className="mb-1.5 block text-xs font-medium uppercase tracking-[0.18em] text-ink-tertiary">
                      {field.label}
                    </span>
                    <input
                      value={form.auth[field.key] ?? ""}
                      onChange={(event) => updateAuth(field.key, event.target.value)}
                      placeholder={field.placeholder}
                      className={`w-full rounded-xl border border-outline bg-surface-elevated px-3 py-2 text-sm text-foreground outline-none transition focus:border-emerald-500 ${field.mono ? "font-mono" : ""}`}
                    />
                  </label>
                ))}
                {usesWorkloadBinding ? (
                  <label className="block text-sm">
                    <span className="mb-2 block font-medium">Operator binding ID</span>
                    <input aria-label="Operator binding ID" value={form.auth.credential_binding ?? ""} onChange={(event) => updateAuth("credential_binding", event.target.value)} placeholder="readonly-prod" autoComplete="off" className="w-full rounded-lg border border-outline bg-surface p-2 font-mono" />
                    <span className="mt-1 block text-xs text-ink-secondary">An operator-supplied identifier, never a secret or file path.</span>
                  </label>
                ) : (
                <label className="block">
                  <span className="mb-1.5 flex flex-wrap items-center justify-between gap-2">
                    <span className="text-xs font-medium uppercase tracking-[0.18em] text-ink-tertiary">
                      {provider.secretField.label}
                    </span>
                    {isAws ? (
                      <span className="inline-flex items-center gap-1 text-[10px] font-medium text-emerald-300">
                        <CheckCircle2 className="h-3 w-3" /> Carried from setup
                      </span>
                    ) : null}
                  </span>
                  {isAws ? (
                    <div className="flex items-center justify-between gap-2 rounded-xl border border-outline bg-surface-elevated px-3 py-2">
                      <code data-testid="wizard-external-id-details" className="min-w-0 break-all font-mono text-sm text-foreground">
                        {form.external_id}
                      </code>
                      <CopyTextButton text={form.external_id} label="Copy" />
                    </div>
                  ) : provider.secretField.multiline ? (
                    <textarea
                      autoComplete="off"
                      rows={5}
                      value={form.external_id}
                      onChange={(event) => update("external_id", event.target.value)}
                      placeholder={provider.secretField.placeholder}
                      className="w-full rounded-xl border border-outline bg-surface-elevated px-3 py-2 font-mono text-xs text-foreground outline-none transition focus:border-emerald-500"
                    />
                  ) : (
                    <input
                      type="password"
                      autoComplete="off"
                      value={form.external_id}
                      onChange={(event) => update("external_id", event.target.value)}
                      placeholder={provider.secretField.placeholder}
                      className="w-full rounded-xl border border-outline bg-surface-elevated px-3 py-2 text-sm text-foreground outline-none transition focus:border-emerald-500"
                    />
                  )}
                  <span className="mt-1.5 inline-flex items-center gap-1.5 text-[11px] text-ink-tertiary">
                    <Lock className="h-3 w-3" />{" "}
                    {isAws
                      ? "Matches the ExternalId in your trust policy. Stored encrypted at rest; regenerate on the Setup step only if you have not applied the grant yet."
                      : provider.secretField.hint}
                  </span>
                </label>
                )}
                <label className="flex cursor-pointer items-start gap-2.5 rounded-xl border border-outline bg-surface-elevated px-3 py-2.5">
                  <input
                    type="checkbox"
                    checked={form.auto_scan_on_create}
                    disabled={managedTrial}
                    onChange={(event) =>
                      setForm((current) => ({ ...current, auto_scan_on_create: event.target.checked }))
                    }
                    className="mt-0.5 h-4 w-4 shrink-0 accent-emerald-500"
                    data-testid="wizard-auto-scan-on-create"
                  />
                  <span className="min-w-0">
                    <span className="block text-sm font-medium text-foreground">
                      Run first scan after connect
                    </span>
                    <span className="mt-0.5 block text-[11px] text-ink-secondary">
                      {managedTrial
                        ? "Managed trials require verification before an explicit first scan."
                        : "Optional. Enable only when a scan should start before the explicit Verify step."}
                    </span>
                  </span>
                </label>
                <label className="flex cursor-pointer items-start gap-2.5 rounded-xl border border-outline bg-surface-elevated px-3 py-2.5">
                  <input
                    type="checkbox"
                    checked={form.scan_mode === "continuous"}
                    disabled={managedTrial}
                    onChange={(event) =>
                      setForm((current) => ({
                        ...current,
                        scan_mode: event.target.checked ? "continuous" : "full",
                      }))
                    }
                    className="mt-0.5 h-4 w-4 shrink-0 accent-sky-500"
                    data-testid="wizard-scan-mode-continuous"
                  />
                  <span className="min-w-0">
                    <span className="block text-sm font-medium text-foreground">Continuous</span>
                    <span className="mt-0.5 block text-[11px] text-ink-secondary">
                      {managedTrial
                        ? "Continuous scans are unavailable in managed trials."
                        : "Event-driven mid-interval refresh between full cadence scans."}
                    </span>
                    {form.scan_mode === "continuous" ? (
                      <span
                        className="mt-1.5 block text-[11px] text-ink-tertiary"
                        data-testid="wizard-continuous-queue-hint"
                      >
                        Mid-interval refresh needs both AGENT_BOM_CONNECTIONS_SCHEDULER=1 and a
                        provider event queue env (for example AGENT_BOM_AWS_EVENT_QUEUE_URL) on the
                        control plane.
                      </span>
                    ) : null}
                  </span>
                </label>
                {provider.usesRegions ? (
                  <div className="space-y-2">
                    <span className="block text-xs font-medium uppercase tracking-[0.18em] text-ink-tertiary">
                      Regions
                    </span>
                    <label className="flex cursor-pointer items-start gap-2.5 rounded-xl border border-outline bg-surface-elevated px-3 py-2.5">
                      <input
                        type="checkbox"
                        checked={allRegions}
                        disabled={managedTrial}
                        onChange={(event) => setAllRegions(event.target.checked)}
                        className="mt-0.5 h-4 w-4 shrink-0 accent-emerald-500"
                        data-testid="wizard-all-regions"
                      />
                      <span className="min-w-0">
                        <span className="block text-sm font-medium text-foreground">All enabled regions</span>
                        <span className="mt-0.5 block text-[11px] text-ink-secondary">
                          {managedTrial
                            ? managedTrialEnvelope
                              ? `Managed trials require one to ${managedTrialEnvelope.max_regions} explicit regions.`
                              : "Managed trial region limits are unavailable. Refresh before continuing."
                            : "Fan the scan across every region enabled in the account. Leave off to scan specific regions."}
                        </span>
                      </span>
                    </label>
                    {!allRegions ? (
                      <label className="block">
                        <span className="mb-1.5 block text-[11px] text-ink-tertiary">
                          Specific regions (optional — defaults to the account default region)
                        </span>
                        <input
                          value={form.regions}
                          onChange={(event) => update("regions", event.target.value)}
                          placeholder="us-east-1, us-west-2"
                          className="w-full rounded-xl border border-outline bg-surface-elevated px-3 py-2 font-mono text-sm text-foreground outline-none transition focus:border-emerald-500"
                        />
                      </label>
                    ) : null}
                  </div>
                ) : null}
              </div>
            ) : null}

            {step === 3 ? (
              <div className="space-y-4">
                <div>
                  <h3 className="text-sm font-semibold text-foreground">Verify connectivity</h3>
                  <p className="mt-1 text-xs text-ink-secondary">
                    We broker a short-lived read-only credential and check access — no inventory, findings, or writes.
                  </p>
                </div>

                {verifyState === "running" ? (
                  <div className="flex items-center gap-2.5 rounded-xl border border-outline bg-surface-elevated px-4 py-3 text-sm text-ink-secondary">
                    <Loader2 className="h-4 w-4 animate-spin text-ink-tertiary" />
                    Verifying read-only access…
                  </div>
                ) : null}

                {verifyState === "ok" ? (
                  <div className="space-y-3 rounded-xl border border-emerald-500/30 dark:border-emerald-800/70 bg-emerald-500/10 dark:bg-emerald-950/20 px-4 py-3">
                    <p className="flex items-center gap-2 text-sm font-medium text-emerald-700 dark:text-emerald-200">
                      <CheckCircle2 className="h-4 w-4" />
                      Read-only access verified
                    </p>
                    <p className="text-xs text-ink-secondary">
                      The connection is active. Run a first read-only scan now, or close and scan later from the table.
                    </p>
                    {scanState === "ok" ? (
                      <div className="flex flex-wrap items-center gap-2 text-xs text-emerald-700 dark:text-emerald-200">
                        <span className="inline-flex items-center gap-1.5">
                          <ShieldCheck className="h-3.5 w-3.5" />
                          First scan started{scanId ? ` — ${scanId}` : "."}
                        </span>
                        {scanId ? (
                          <Link href={`/scan?id=${encodeURIComponent(scanId)}`} className="font-medium underline underline-offset-2">
                            Track scan
                          </Link>
                        ) : null}
                      </div>
                    ) : scanState === "error" ? (
                      <div className="space-y-2">
                        <p className="flex items-start gap-1.5 text-xs text-red-700 dark:text-red-300">
                          <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                          <span>{scanError}</span>
                        </p>
                        <button
                          type="button"
                          onClick={() => void runFirstScan()}
                          className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-3 py-1.5 text-xs font-medium text-emerald-700 dark:text-emerald-200 transition hover:border-emerald-500"
                        >
                          <RefreshCcw className="h-3.5 w-3.5" /> Retry scan
                        </button>
                      </div>
                    ) : (
                      <button
                        type="button"
                        onClick={() => void runFirstScan()}
                        disabled={scanState === "running"}
                        className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-500 px-3 py-1.5 text-xs font-medium text-black transition hover:bg-emerald-400 disabled:cursor-not-allowed disabled:opacity-60"
                      >
                        {scanState === "running" ? (
                          <>
                            <Loader2 className="h-3.5 w-3.5 animate-spin" /> Starting first scan…
                          </>
                        ) : (
                          <>
                            <ShieldCheck className="h-3.5 w-3.5" /> Run first scan
                          </>
                        )}
                      </button>
                    )}
                  </div>
                ) : null}

                {verifyState === "error" ? (
                  <div className="space-y-3 rounded-xl border border-red-500/30 dark:border-red-900/60 bg-red-500/10 dark:bg-red-950/20 px-4 py-3">
                    <p className="flex items-center gap-2 text-sm font-medium text-red-700 dark:text-red-300">
                      <AlertTriangle className="h-4 w-4" />
                      Verification failed
                    </p>
                    <ErrorBanner compact message={verifyError ?? "Verification unavailable"} />
                    <p className="text-[11px] text-ink-tertiary">
                      The connection was saved but is not active. Fix the grant (or its permissions) and retry — nothing
                      was scanned.
                    </p>
                    <button
                      type="button"
                      onClick={() => createdRecord && void runVerify(createdRecord)}
                      className="inline-flex items-center gap-1.5 rounded-lg border border-outline bg-surface-elevated px-3 py-1.5 text-xs font-medium text-foreground transition hover:border-outline-strong"
                    >
                      <RefreshCcw className="h-3.5 w-3.5" /> Retry verification
                    </button>
                  </div>
                ) : null}
              </div>
            ) : null}

            {formError ? <ErrorBanner compact message={formError} /> : null}
          </div>

          <div className="flex items-center justify-between gap-3 border-t border-outline px-5 py-4">
            {step === 3 ? (
              // The connection already exists; going back would re-create it. Verify
              // and first-scan actions live in the panel; the footer only closes.
              <span aria-hidden className="h-9" />
            ) : (
              <button
                type="button"
                onClick={() => (step === 0 ? onClose() : setStep((s) => (s - 1) as WizardStep))}
                className="inline-flex items-center gap-1.5 rounded-xl border border-outline bg-surface-elevated px-4 py-2 text-sm text-foreground transition hover:border-outline-strong"
              >
                {step === 0 ? (
                  "Cancel"
                ) : (
                  <>
                    <ArrowLeft className="h-4 w-4" /> Back
                  </>
                )}
              </button>
            )}
            {step < 2 ? (
              <button
                key="wizard-next"
                type="button"
                onClick={goNext}
                className="inline-flex items-center gap-1.5 rounded-xl bg-emerald-500 px-4 py-2 text-sm font-medium text-black transition hover:bg-emerald-400"
              >
                Next <ArrowRight className="h-4 w-4" />
              </button>
            ) : step === 2 ? (
              <button
                key="wizard-submit"
                type="submit"
                disabled={submitting}
                className="inline-flex items-center gap-1.5 rounded-xl bg-emerald-500 px-4 py-2 text-sm font-medium text-black transition hover:bg-emerald-400 disabled:cursor-not-allowed disabled:opacity-60"
              >
                <Plus className="h-4 w-4" />
                {submitting ? "Connecting…" : "Create connection"}
              </button>
            ) : (
              <button
                key="wizard-done"
                type="button"
                onClick={onClose}
                className="inline-flex items-center gap-1.5 rounded-xl bg-emerald-500 px-4 py-2 text-sm font-medium text-black transition hover:bg-emerald-400"
              >
                Done
              </button>
            )}
          </div>
        </form>
      </div>
    </div>
  );
}
