# Connections workflows

`app/connections/page.tsx` supplies the route's Suspense boundary. `hub.tsx`
owns shared loading, permissions, selection and refresh state. Workflow modules
receive that state through props:

- `connect-workflow.tsx`: connector catalog and coding-agent setup.
- `sources-workflow.tsx`: recorded sources, registration and operational links.
- `connection-wizard.tsx`: provider setup and verification, using wizard controls.
- `connection-detail.tsx` and `source-detail.tsx`: scoped detail and actions.
- `evidence.tsx`: recorded configuration and scan-result handoffs.

`catalog.tsx`, `display.tsx`, `provider-contract.tsx` and `wizard-support.tsx`
hold shared definitions and presentation helpers. Leaf modules must not import
the hub or route. Shared `TextField`, `EvidenceFields`, `PageLoadingState` and
`ErrorBanner` components supply labels, evidence semantics and feedback states.
Unknown verification or collection coverage remains explicit in the evidence.

Run `npm test -- --run tests/connections-page.test.tsx
tests/connection-primitives.test.tsx` for behavior contracts. After a production
build, `npm run test:e2e -- e2e/connections-screenshot.spec.ts` checks keyboard
navigation, focus restoration, provider setup, and light/dark desktop/mobile
layouts at enlarged text sizes.
