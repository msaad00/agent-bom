const SAFE_OSV_ID = /^(CVE-\d{4}-\d{4,7}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})$/i;

export function getOsvVulnerabilityUrl(label: string | undefined | null): string | null {
  const value = String(label ?? "").trim();
  if (!SAFE_OSV_ID.test(value)) {
    return null;
  }
  return `https://osv.dev/vulnerability/${encodeURIComponent(value.toUpperCase())}`;
}
