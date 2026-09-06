import { PageLoadingState } from "@/components/states/page-loading-state";

export default function FindingsLoading() {
  return (
    <PageLoadingState
      title="Loading findings"
      detail="Preparing the prioritized evidence queue and remediation context."
      data-testid="findings-route-loading"
    />
  );
}
