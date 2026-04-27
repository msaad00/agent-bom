import dynamic from "next/dynamic";

const GraphPageClient = dynamic(() => import("./graph-page-client"), {
  ssr: false,
});

export default function GraphPage() {
  return <GraphPageClient />;
}
