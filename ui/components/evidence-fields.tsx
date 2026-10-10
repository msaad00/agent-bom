import type { ReactNode } from "react";

type EvidenceField = { label: string; value: ReactNode; wide?: boolean };

/** Semantic, wrapping evidence terms; callers supply honest missing-data labels. */
export function EvidenceFields({ label, fields, className = "" }: {
  label: string;
  fields: readonly EvidenceField[];
  className?: string;
}) {
  return (
    <section aria-label={label} className={className}>
      <dl className="grid grid-cols-1 gap-x-5 gap-y-3 text-sm sm:grid-cols-2">
        {fields.map(field => (
          <div key={field.label} className={`min-w-0 ${field.wide ? "sm:col-span-2" : ""}`}>
            <dt className="text-xs text-ink-tertiary">{field.label}</dt>
            <dd className="mt-0.5 break-words font-medium text-foreground">{field.value}</dd>
          </div>
        ))}
      </dl>
    </section>
  );
}
