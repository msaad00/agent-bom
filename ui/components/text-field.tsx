"use client";

import { useId, type InputHTMLAttributes } from "react";

type TextFieldProps = InputHTMLAttributes<HTMLInputElement> & {
  label: string;
  hint?: string;
  error?: string;
};

/** A native input with a stable label and explicitly associated help/errors. */
export function TextField({ label, hint, error, id, className = "", ...input }: TextFieldProps) {
  const generatedId = useId();
  const controlId = id ?? generatedId;
  const description = [input["aria-describedby"], hint ? `${controlId}-hint` : null, error ? `${controlId}-error` : null]
    .filter(Boolean).join(" ") || undefined;
  return (
    <div>
      <label htmlFor={controlId} className="mb-2 block text-xs font-medium uppercase tracking-[0.18em] text-ink-tertiary">{label}</label>
      <input {...input} id={controlId} aria-describedby={description} aria-invalid={error ? true : input["aria-invalid"]}
        className={`w-full rounded-lg border border-outline bg-surface-elevated px-3 py-2 text-sm text-foreground outline-none transition focus:border-[color:var(--accent-border)] disabled:opacity-60 ${className}`} />
      {hint ? <p id={`${controlId}-hint`} className="mt-1 text-xs text-ink-secondary">{hint}</p> : null}
      {error ? <p id={`${controlId}-error`} role="alert" className="mt-1 text-xs text-[color:var(--status-danger)]">{error}</p> : null}
    </div>
  );
}
