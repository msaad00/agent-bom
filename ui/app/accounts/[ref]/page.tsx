// Server-component wrapper for the account drill-down.
//
// `/accounts/[ref]` is a dynamic route whose `ref` is only known at runtime —
// it is read client-side from the URL via `useParams()` inside
// `AccountDetailClient`. With `output: export` (the static bundle shipped in
// the Python package) Next requires every dynamic segment to declare its
// static params, and a `"use client"` page may not export
// `generateStaticParams`. So the page stays a server component that delegates
// rendering to the client child.
//
// Next 16 additionally rejects an *empty* `generateStaticParams()` result
// under `output: export` ("Page is missing generateStaticParams()"), so we
// emit a single inert placeholder segment. Real account refs are never
// prerendered — they resolve at runtime from the URL. `dynamicParams` must be
// `false` because `output: export` forbids `true`.
import AccountDetailClient from "./AccountDetailClient";

// Inert placeholder: `output: export` needs a non-empty static-param list, but
// no real account ref is enumerable at build time. This prerenders only
// `/accounts/_`; every real ref is read client-side from the URL.
export function generateStaticParams() {
  return [{ ref: "_" }];
}

// Required by `output: export`: Next 16 forbids `dynamicParams: true` here.
export const dynamicParams = false;

export default function AccountDrillPage() {
  return <AccountDetailClient />;
}
