import type { ElementType, HTMLAttributes, ReactNode } from "react";

type CardProps = HTMLAttributes<HTMLDivElement> & {
  /** Render as a different element (e.g. "section", "li"). Defaults to div. */
  as?: ElementType;
  /** Drop the default p-5 padding (for tables / media that bleed to the edge). */
  flush?: boolean;
};

/**
 * Canonical card shell. The app duplicates this 50+× with two radius scales
 * (rounded-xl vs rounded-2xl). This standardizes on a single radius
 * (rounded-xl), the subtle border + surface tokens, and p-5 padding so every
 * card reads correctly across both light and dark themes.
 */
export function Card({ as, flush = false, className = "", children, ...rest }: CardProps) {
  const Tag = as ?? "div";
  return (
    <Tag
      className={`rounded-xl border border-[color:var(--border-subtle)] bg-[color:var(--surface)] ${flush ? "" : "p-5"} ${className}`}
      {...rest}
    >
      {children}
    </Tag>
  );
}

type SectionProps = HTMLAttributes<HTMLElement> & {
  as?: ElementType;
  /** Optional eyebrow label rendered above the content. */
  label?: ReactNode;
  /** Optional description rendered under the label. */
  description?: ReactNode;
  /** Draw a divider under the label header. */
  divider?: boolean;
  children: ReactNode;
};

/**
 * Consistent vertical rhythm for a block of content: an optional SectionLabel
 * eyebrow + description, an optional divider, then the children with a uniform
 * gap. Use to stop pages hand-picking different mb-/gap- values per section.
 */
export function Section({
  as,
  label,
  description,
  divider = false,
  className = "",
  children,
  ...rest
}: SectionProps) {
  const Tag = as ?? "section";
  return (
    <Tag className={`flex flex-col gap-4 ${className}`} {...rest}>
      {label || description ? (
        <div className={divider ? "border-b border-[color:var(--border-subtle)] pb-3" : undefined}>
          {label ? <SectionLabel>{label}</SectionLabel> : null}
          {description ? (
            <p className="mt-1 text-sm leading-6 text-[color:var(--text-secondary)]">{description}</p>
          ) : null}
        </div>
      ) : null}
      {children}
    </Tag>
  );
}

/** Uppercase eyebrow label shared by Section headers and standalone use. */
export function SectionLabel({
  children,
  className = "",
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={`text-xs font-medium uppercase tracking-[0.14em] text-[color:var(--text-tertiary)] ${className}`}
    >
      {children}
    </div>
  );
}
