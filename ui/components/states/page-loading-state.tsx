// Server-renderable loading markup: route boundaries do not need a client bundle.
export function PageLoadingState({
  title,
  detail,
  "data-testid": testId,
}: {
  title: string;
  detail: string;
  "data-testid"?: string | undefined;
}) {
  return (
    <div className="flex min-h-[18rem] items-center justify-center px-4 py-10" data-testid={testId} role="status" aria-live="polite">
      <div className="w-full max-w-3xl rounded-2xl border border-outline bg-surface p-5 elev-2">
        <div className="flex items-start gap-3">
          <div className="rounded-xl border border-outline bg-surface-elevated p-2">
            <span aria-hidden="true" className="block h-5 w-5 animate-spin rounded-full border-2 border-current border-r-transparent text-ink-secondary" />
          </div>
          <div>
            <h3 className="text-base font-semibold text-foreground">{title}</h3>
            <p className="mt-2 text-sm leading-6 text-ink-secondary">{detail}</p>
          </div>
        </div>
        <div className="mt-6 grid gap-4 md:grid-cols-3">
          {[0, 1, 2].map((column) => (
            <div key={column} className="rounded-xl border border-outline bg-surface-muted p-4">
              <div className="h-4 w-24 animate-pulse rounded-full bg-surface-elevated" />
              <div className="mt-4 space-y-3">
                {[0, 1, 2, 3].map((row) => (
                  <div
                    key={row}
                    className="h-3 animate-pulse rounded-full bg-surface-elevated"
                    style={{ width: `${92 - row * 13 - column * 4}%` }}
                  />
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
