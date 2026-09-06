import { PageLoadingState } from "@/components/states/page-state";

export default function ComplianceLoading() {
  return (
    <PageLoadingState
      title="Loading compliance"
      detail="Preparing control coverage, evidence freshness, and assessment status."
      data-testid="compliance-route-loading"
    />
  );
}
