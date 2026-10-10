"use client";




// ── Add connection wizard ─────────────────────────────────────────────────────

export interface WizardForm {
  provider: string;
  display_name: string;
  role_ref: string;
  external_id: string;
  regions: string;
  auth: Record<string, string>;
  auto_scan_on_create: boolean;
  scan_mode: "full" | "continuous";
}


export function buildWizardForm(provider: string): WizardForm {
  return {
    provider,
    display_name: "",
    role_ref: "",
    external_id: "",
    regions: "",
    auth: {},
    auto_scan_on_create: false,
    scan_mode: "full",
  };
}


export type WizardStep = 0 | 1 | 2 | 3;

export type VerifyState = "idle" | "running" | "ok" | "error";


export function StepIndicator({ step }: { step: number }) {
  const labels = ["Provider", "Setup", "Details", "Verify"];
  return (
    <div className="flex items-center gap-2">
      {labels.map((label, index) => (
        <div key={label} className="flex flex-1 items-center gap-2">
          <span
            className={`flex h-6 w-6 shrink-0 items-center justify-center rounded-full border text-[11px] font-semibold ${
              index <= step
                ? "border-emerald-500 bg-emerald-500 text-black"
                : "border-outline bg-surface-elevated text-ink-tertiary"
            }`}
          >
            {index + 1}
          </span>
          <span className={`text-xs ${index <= step ? "text-foreground" : "text-ink-tertiary"}`}>
            {label}
          </span>
          {index < labels.length - 1 ? <span className="h-px flex-1 bg-[color:var(--border-subtle)]" /> : null}
        </div>
      ))}
    </div>
  );
}
