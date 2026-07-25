import { Suspense } from "react";

import { LoginPageContent } from "@/app/login/login-page-content";

function TrialInvitationForm() {
  return (
    <details className="mb-6 rounded-2xl border border-[var(--border-subtle)] bg-[var(--surface)]/60 px-4 py-3">
      <summary className="cursor-pointer text-sm font-medium text-[var(--foreground)]">
        Use a trial invitation
      </summary>
      <form action="/v1/auth/trial/oidc/start-form" method="post" className="mt-3">
        <label
          htmlFor="agent-bom-managed-trial-token"
          className="mb-2 block text-xs uppercase tracking-[0.2em] text-[var(--text-tertiary)]"
        >
          Invitation token
        </label>
        <input
          id="agent-bom-managed-trial-token"
          name="token"
          type="password"
          required
          maxLength={128}
          autoComplete="one-time-code"
          className="w-full rounded-xl border border-[var(--border-subtle)] bg-[var(--background)] px-3 py-2.5 font-mono text-sm text-[var(--foreground)] outline-none placeholder:text-[var(--text-tertiary)] focus:border-emerald-500"
          placeholder="Paste the one-time invitation"
        />
        <p className="mt-2 text-xs leading-5 text-[var(--text-tertiary)]">
          The token is posted directly to this control plane and is never placed in the URL.
        </p>
        <button
          type="submit"
          className="mt-3 w-full rounded-xl bg-emerald-500 px-4 py-2.5 text-sm font-medium text-[var(--on-accent)] transition hover:bg-emerald-400"
        >
          Continue with invitation
        </button>
      </form>
    </details>
  );
}

export default function LoginPage() {
  return (
    <Suspense
      fallback={
        <div className="flex min-h-screen items-center justify-center text-[var(--text-secondary)]">
          <span
            role="status"
            aria-label="Loading sign-in"
            className="mr-2 h-5 w-5 animate-spin rounded-full border-2 border-[var(--border-subtle)] border-t-emerald-400"
          />
          Loading sign-in...
        </div>
      }
    >
      <LoginPageContent trialInvitation={<TrialInvitationForm />} />
    </Suspense>
  );
}
