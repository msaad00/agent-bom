import { test, expect } from "@playwright/test";

const server = (name: string, credential = false) => ({ name, command: name, transport: "stdio", packages: [], credential_env_vars: credential ? ["API_TOKEN"] : [] });
const agents = [
  { name: "assistant-one", agent_type: "custom", mcp_servers: [server("files"), server("code", true)] },
  { name: "assistant-two", agent_type: "custom", mcp_servers: [server("files"), server("fetch"), server("chat", true), server("database", true)] },
  { name: "assistant-three", agent_type: "custom", mcp_servers: [server("browser"), server("runtime")] },
  { name: "assistant-four", agent_type: "custom", mcp_servers: [server("warehouse-one"), server("warehouse-two")] },
  { name: "assistant-five", agent_type: "custom", mcp_servers: [server("headless-browser")] },
  ...["unlinked-one", "unlinked-two", "unlinked-three"].map(name => ({ name, agent_type: "custom", mcp_servers: [] })),
];

for (const theme of ["light", "dark"] as const) for (const width of [1440, 390]) {
  test(`topology has distinct filters and readable relationships in ${theme} at ${width}`, async ({ page }) => {
    await page.setViewportSize({ width, height: 1200 });
    await page.emulateMedia({ colorScheme: theme });
    await page.addInitScript(value => localStorage.setItem("agent-bom-theme", value), theme);
    await page.route("**/v1/**", route => {
      const path = new URL(route.request().url()).pathname;
      if (path === "/v1/agents") return route.fulfill({ json: { agents, count: 8, warnings: [], scope: "local_discovery" } });
      if (path.startsWith("/v1/auth/")) return route.fulfill({ json: { authenticated: true, role: "analyst", tenant_id: "fixture", permissions: ["read"] } });
      return route.fulfill({ status: 503, json: { detail: "Outside topology fixture" } });
    });
    await page.goto("/agents/topology");
    await expect(page.getByRole("button", { name: "Needs attention", exact: true })).toHaveAttribute("aria-pressed", "true");
    await expect(page.getByText(/Showing 2 of 2 matching agents/)).toBeVisible();
    await page.getByRole("button", { name: "Full mesh", exact: true }).click();
    await expect(page.getByText(/Showing 8 of 8 matching agents/)).toBeVisible();
    await expect(page.getByText(/vulnerabilities are not assessed by this source/)).toBeVisible();
    await expect(page.getByRole("button", { name: /^Inspect Unlinked / })).toHaveCount(3);
    if (width < 768) {
      await expect(page.getByRole("region", { name: "Configured service relationships" })).toBeVisible();
      await expect(page.locator(".react-flow")).not.toBeVisible();
      await page.getByRole("button", { name: /^Inspect service / }).first().click();
      await expect(page.getByRole("dialog")).toBeVisible();
      await page.getByRole("button", { name: "Close topology details", exact: true }).click();
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
    } else {
      await expect(page.locator(".react-flow__node")).toHaveCount(15);
      // Poll past the viewport animation; measure SVG paths in screen coordinates.
      await expect.poll(() => page.evaluate(() => {
        const nodes = [...document.querySelectorAll<HTMLElement>(".react-flow__node")].map(node => ({ id: node.dataset.id ?? "", rect: node.getBoundingClientRect() }));
        const paths = [...document.querySelectorAll<SVGPathElement>(".react-flow__edge-path")];
        let intersections = 0;
        for (const node of nodes) for (const path of paths) {
          const edge = path.closest<HTMLElement>(".react-flow__edge")?.dataset.id ?? "";
          if (edge.includes(node.id)) continue;
          const transform = path.getScreenCTM();
          if (!transform) continue;
          for (let length = 0; length <= path.getTotalLength(); length += 2) {
            const point = path.getPointAtLength(length);
            const screen = new DOMPoint(point.x, point.y).matrixTransform(transform);
            if (screen.x > node.rect.left + 3 && screen.x < node.rect.right - 3 && screen.y > node.rect.top + 3 && screen.y < node.rect.bottom - 3) { intersections += 1; break; }
          }
        }
        return intersections;
      })).toBe(0);
      const viewport = page.locator(".react-flow__viewport");
      const initialTransform = await viewport.evaluate(element => element.style.transform);
      const canvas = await page.locator(".react-flow").boundingBox();
      if (!canvas) throw new Error("Topology canvas is missing");
      await page.mouse.move(canvas.x + canvas.width - 30, canvas.y + 30);
      await page.mouse.down();
      await page.mouse.move(canvas.x + canvas.width - 90, canvas.y + 70, { steps: 5 });
      await page.mouse.up();
      const pannedTransform = await viewport.evaluate(element => element.style.transform);
      expect(pannedTransform).not.toBe(initialTransform);
      await page.getByRole("button", { name: "Context", exact: true }).click();
      await expect(page.getByText(/Tenant fixture/)).toBeVisible();
      // The layout's delayed initial fit must not reclaim a manually panned view.
      await page.waitForTimeout(250);
      expect(await viewport.evaluate(element => element.style.transform)).toBe(pannedTransform);
      await page.locator('.react-flow__node[data-id="agent-assistant-one"]').click();
      await expect(page.getByRole("dialog")).toBeVisible();
      await page.getByRole("button", { name: "Close topology details", exact: true }).click();
      await page.waitForTimeout(250);
      expect(await viewport.evaluate(element => element.style.transform)).toBe(pannedTransform);
    }
    await page.getByRole("button", { name: "Unlinked", exact: true }).focus();
    await page.keyboard.press("Enter");
    await expect(page.getByRole("button", { name: "Unlinked", exact: true })).toHaveAttribute("aria-pressed", "true");
    await expect(page.locator(".react-flow__node")).toHaveCount(0);
    await page.getByRole("button", { name: "Inspect Unlinked One", exact: true }).click();
    await expect(page.getByRole("dialog", { name: "Topology details for Unlinked One" })).toBeVisible();
  });
}
