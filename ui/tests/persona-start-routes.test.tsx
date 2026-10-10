import { render, screen } from "@testing-library/react";
import { expect, it } from "vitest";

import { PersonaStartRoutes } from "@/components/persona-start-routes";
import { version } from "../package.json";

it("pins first-run Docker and Action commands to the installed dashboard version", () => {
  render(<PersonaStartRoutes />);
  expect(screen.getByText(`docker run --rm agentbom/agent-bom:${version} scan --demo --offline`)).toBeInTheDocument();
  expect(screen.getByText(`uses: koda-ai-studio/agent-bom@v${version}`)).toBeInTheDocument();
});
