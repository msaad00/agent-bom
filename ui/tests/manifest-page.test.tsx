import { render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import ManifestPage from "@/app/manifest/page";
const { getManifest } = vi.hoisted(() => ({ getManifest: vi.fn() }));
vi.mock("@/hooks/use-deployment-context", () => ({ useDeploymentContext: () => ({counts: null}) }));
vi.mock("@/lib/api", async () => ({...await vi.importActual("@/lib/api"), api: {getAgentBomManifest:getManifest}}));
const manifest = {
 schema_version:"agent-bom.manifest/v1",generated_at:"2026-09-06T12:00:00Z",source:"control-plane",tenant_id:"default",
 summary:{agents:0,mcp_servers:1,tools:0,credential_refs:0,runtime_observed_servers:0,gateway_registered_servers:0},
 agents:[],mcp_servers:[{id:"server1",name:"filesystem",agent_name:"claude-desktop",observed:{configured_locally:true}}],
 graph:{nodes:[],edges:[],stats:{nodes:0,edges:0}},
 boundaries:{stores_credential_values:false,stores_raw_prompts:false},
 blueprint_drift:{status:"aligned",signal_count:0},
 visibility:{owners:0,unowned_agents:0,shadow_runtime_servers:0,untracked_runtime_servers:0,servers_with_warnings:0,risky_credential_refs:0}
};
describe("AI BOM evidence scope",()=>{
 beforeEach(()=>{getManifest.mockReset();});
 it("distinguishes registered agents and uncollected scan dimensions",async()=>{
 getManifest.mockResolvedValue(manifest); render(<ManifestPage/>);
 await screen.findByText("claude-desktop");
 expect(screen.getByText("Registered agents")).toBeInTheDocument();
 expect(screen.getAllByText("Not collected").length).toBeGreaterThan(0);
 expect(screen.queryByText("Live")).not.toBeInTheDocument();
 expect(screen.getByText("Inventory relationships")).toBeInTheDocument();
 });
 it("does not render zero inventory after manifest request failure",async()=>{
 getManifest.mockRejectedValue(new Error("Request unavailable")); render(<ManifestPage/>);
 await screen.findByText("Request unavailable");
 await waitFor(()=>expect(screen.getByText("Inventory unavailable")).toBeInTheDocument());
 expect(screen.queryByText("0")).not.toBeInTheDocument();
 });
});
