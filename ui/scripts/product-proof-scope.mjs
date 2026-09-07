/** Reject fixture responses that belong to a different selected snapshot. */
export function assertCaptureSnapshotScope(requestUrl, expectedScanId, responseScanIds) {
  const requestedScanId = new URL(requestUrl).searchParams.get("scan_id");
  if (
    requestedScanId !== expectedScanId ||
    responseScanIds.length === 0 ||
    responseScanIds.some((scanId) => scanId !== requestedScanId)
  ) {
    throw new Error("Capture fixture snapshot scope mismatch");
  }
}
