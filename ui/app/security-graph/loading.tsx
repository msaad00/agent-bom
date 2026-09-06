import { PageLoadingState } from "@/components/states/page-loading-state";

export default function SecurityGraphLoading() {
  return (
    <PageLoadingState
      title="Loading investigation"
      detail="Hydrating graph evidence, relationships, and available investigation lenses."
      data-testid="security-graph-route-loading"
    />
  );
}
