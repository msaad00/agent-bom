import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'

let mockedPathname = '/'

const authStateMock = vi.hoisted(() => ({
  session: null as {
    authenticated: boolean
    auth_required: boolean
    tenant_id: string
    subject: string | null
    role: string | null
    role_summary: { display_name: string; capabilities: string[] } | null
  } | null,
  loading: true,
  error: null as string | null,
  refresh: vi.fn(),
  hasCapability: vi.fn(() => false),
}))

// Mock next/link so it renders a plain anchor
vi.mock('next/link', () => ({
  default: ({ href, children, ...rest }: { href: string; children: React.ReactNode; [key: string]: unknown }) => (
    <a href={href} {...rest}>{children}</a>
  ),
}))

// Mock next/navigation
vi.mock('next/navigation', () => ({
  usePathname: () => mockedPathname,
}))

vi.mock('@/components/auth-provider', () => ({
  useAuthState: () => ({
    session: authStateMock.session,
    loading: authStateMock.loading,
    error: authStateMock.error,
    refresh: authStateMock.refresh,
    hasCapability: authStateMock.hasCapability,
  }),
}))

vi.mock('@/hooks/use-demo-mode', () => ({
  useDemoMode: () => ({ isDemoMode: false, loading: false }),
}))

// Mock the API so the component doesn't make real network calls
vi.mock('@/lib/api', () => ({
  api: {
    getPostureCounts: vi.fn().mockResolvedValue({
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      total: 0,
      kev: 0,
      compound_issues: 0,
      deployment_mode: 'local',
      has_mcp_context: false,
      has_agent_context: false,
      has_local_scan: false,
      has_fleet_ingest: false,
      has_cluster_scan: false,
      has_ci_cd_scan: false,
      has_mesh: false,
      has_gateway: false,
      has_proxy: false,
      has_traces: false,
      has_registry: false,
      scan_sources: [],
      scan_count: 0,
    }),
    health: vi.fn().mockResolvedValue({ status: 'ok', version: '0.96.1' }),
  },
}))

import { Nav } from '@/components/nav'
import { SidebarLayoutProvider } from '@/components/sidebar-layout'

function renderNav() {
  return render(
    <SidebarLayoutProvider>
      <Nav />
    </SidebarLayoutProvider>,
  )
}

function renderExpandedNav() {
  renderNav()
  fireEvent.click(screen.getByRole('button', { name: /expand sidebar/i }))
}

describe('Nav', () => {
  beforeEach(() => {
    mockedPathname = '/'
    window.history.replaceState({}, '', '/')
    authStateMock.session = null
    authStateMock.loading = true
    authStateMock.error = null
    authStateMock.refresh.mockReset()
    authStateMock.hasCapability.mockReset()
    authStateMock.hasCapability.mockReturnValue(false)
    vi.clearAllMocks()
  })

  it('renders the Posture nav group', () => {
    renderExpandedNav()
    expect(screen.getByText('Posture')).toBeInTheDocument()
  })

  it('renders the AI inventory nav group', () => {
    renderExpandedNav()
    expect(screen.getByText('AI inventory')).toBeInTheDocument()
  })

  it('uses a plain "AI" monogram (not a busy circuit icon) for the AI inventory group', () => {
    renderExpandedNav()
    const aiGroup = screen.getByRole('button', { name: /ai inventory/i })
    // The monogram is its own element whose full text is exactly "AI"; the
    // "AI inventory" label span reads differently and is not matched.
    expect(within(aiGroup).getByText('AI', { exact: true })).toBeInTheDocument()
  })

  it('renders the Connect nav group', () => {
    renderExpandedNav()
    expect(screen.getByText('Connect')).toBeInTheDocument()
  })

  it('renders the Runtime nav group', () => {
    renderExpandedNav()
    expect(screen.getByRole('button', { name: /^runtime/i })).toBeInTheDocument()
  })

  it('renders Governance, Reference, and Operations groups', () => {
    renderExpandedNav()
    expect(screen.getByText('Governance')).toBeInTheDocument()
    expect(screen.getByText('Reference')).toBeInTheDocument()
    expect(screen.getByText('Operations')).toBeInTheDocument()
  })

  it('contains link to Overview (/)', () => {
    renderExpandedNav()
    const links = screen.getAllByRole('link', { name: /overview/i })
    expect(links.length).toBeGreaterThan(0)
  })

  it('contains link to New Scan (/scan) under Connect', () => {
    renderExpandedNav()
    fireEvent.click(screen.getByRole('button', { name: /connect/i }))
    const links = screen.getAllByRole('link', { name: /new scan/i })
    expect(links.some((l) => l.getAttribute('href') === '/scan')).toBe(true)
  })

  it('groups Connections and Data Sources together under Connect', () => {
    renderExpandedNav()
    fireEvent.click(screen.getByRole('button', { name: /connect/i }))
    const hrefs = screen.getAllByRole('link').map((l) => l.getAttribute('href'))
    expect(hrefs).toContain('/connections')
    expect(hrefs).toContain('/sources')
  })

  it('contains link to Scan Jobs (/jobs) under Operations', () => {
    renderExpandedNav()
    fireEvent.click(screen.getByRole('button', { name: /operations/i }))
    const links = screen.getAllByRole('link', { name: /scan jobs/i })
    expect(links.some((l) => l.getAttribute('href') === '/jobs')).toBe(true)
  })

  it('contains link to Findings (/findings) under Posture', () => {
    renderExpandedNav()
    const links = screen.getAllByRole('link', { name: /findings/i })
    expect(links.some((l) => l.getAttribute('href') === '/findings')).toBe(true)
  })

  it('contains Remediation link under Posture', () => {
    renderExpandedNav()
    const links = screen.getAllByRole('link', { name: /remediation/i })
    expect(links.some((l) => l.getAttribute('href') === '/remediation')).toBe(true)
  })

  it('contains Security Graph link under Posture', () => {
    renderExpandedNav()
    const links = screen.getAllByRole('link', { name: /security graph/i })
    expect(links.some((l) => l.getAttribute('href') === '/security-graph')).toBe(true)
  })

  it('defaults to a collapsed sidebar rail with expand control', () => {
    renderNav()
    expect(screen.getByRole('button', { name: /expand sidebar/i })).toBeInTheDocument()
    expect(screen.queryByText('Proof path')).not.toBeInTheDocument()
  })

  it('opens the mobile drawer with usable expanded navigation links', () => {
    renderNav()

    fireEvent.click(screen.getByRole('button', { name: /open navigation menu/i }))

    const drawer = screen.getByLabelText('Mobile navigation')
    expect(within(drawer).getByText('Posture')).toBeInTheDocument()
    expect(within(drawer).getByRole('link', { name: /findings/i })).toHaveAttribute(
      'href',
      '/findings'
    )
    expect(within(drawer).queryByRole('button', { name: /expand sidebar/i })).not.toBeInTheDocument()
  })

  it('surfaces curated workflow links in the command palette', () => {
    renderNav()
    fireEvent.keyDown(window, { key: 'k', metaKey: true })
    const palette = screen.getByRole('dialog', { name: /command palette/i })
    const hrefs = within(palette).getAllByRole('link').map((l) => l.getAttribute('href'))
    expect(hrefs).toContain('/remediation')
    expect(hrefs).toContain('/security-graph')
    expect(hrefs).toContain('/runtime')
    expect(hrefs).toContain('/compliance')
    expect(hrefs).toContain('/connections')
  })

  it('contains MCP Catalog link in Reference', () => {
    renderExpandedNav()
    fireEvent.click(screen.getByRole('button', { name: /reference/i }))
    const links = screen.getAllByRole('link', { name: /mcp catalog/i })
    expect(links.some((l) => l.getAttribute('href') === '/registry')).toBe(true)
  })

  it('keeps graph lenses tucked under Posture instead of primary sidebar links', () => {
    renderExpandedNav()
    expect(screen.getByText(/graph lenses/i)).toBeInTheDocument()
    const hrefs = screen.getAllByRole('link').map((l) => l.getAttribute('href'))
    expect(hrefs).toContain('/security-graph')
    expect(screen.getByRole('link', { name: /^lineage$/i })).toBeInTheDocument()
    expect(hrefs).toContain('/graph')
    expect(hrefs).toContain('/mesh')
    expect(hrefs).toContain('/context')
    expect(hrefs).not.toContain('/insights')
  })

  it('drops the duplicate /overview home entry', () => {
    renderExpandedNav()
    const hrefs = screen.getAllByRole('link').map((l) => l.getAttribute('href'))
    expect(hrefs).not.toContain('/overview')
  })

  it('contains Compliance link under Governance', () => {
    renderExpandedNav()
    fireEvent.click(screen.getByRole('button', { name: /governance/i }))
    const links = screen.getAllByRole('link', { name: /^compliance$/i })
    expect(links.some((l) => l.getAttribute('href') === '/compliance')).toBe(true)
  })

  it('contains Governance link', () => {
    renderExpandedNav()
    fireEvent.click(screen.getByRole('button', { name: /governance/i }))
    const links = screen.getAllByRole('link', { name: /^governance$/i })
    expect(links.some((l) => l.getAttribute('href') === '/governance')).toBe(true)
  })

  it('labels cost as AI Spend under Operations', () => {
    renderExpandedNav()
    fireEvent.click(screen.getByRole('button', { name: /operations/i }))
    const links = screen.getAllByRole('link', { name: /ai spend/i })
    expect(links.some((l) => l.getAttribute('href') === '/cost')).toBe(true)
  })

  it('moves Identity into Runtime', () => {
    renderExpandedNav()
    fireEvent.click(screen.getByRole('button', { name: /^runtime/i }))
    const links = screen.getAllByRole('link', { name: /^identity$/i })
    expect(links.some((l) => l.getAttribute('href') === '/identity')).toBe(true)
  })

  it('moves Drift into Governance', () => {
    renderExpandedNav()
    fireEvent.click(screen.getByRole('button', { name: /governance/i }))
    const links = screen.getAllByRole('link', { name: /^drift$/i })
    expect(links.some((l) => l.getAttribute('href') === '/drift')).toBe(true)
  })

  it('moves the Audit Log into the Governance group', () => {
    renderExpandedNav()
    fireEvent.click(screen.getByRole('button', { name: /governance/i }))
    const links = screen.getAllByRole('link', { name: /audit log/i })
    expect(links.some((l) => l.getAttribute('href') === '/audit')).toBe(true)
  })

  it('opens the command palette with page links and actions', () => {
    renderNav()

    fireEvent.keyDown(window, { key: 'k', metaKey: true })

    const palette = screen.getByRole('dialog', { name: /command palette/i })
    expect(palette).toBeInTheDocument()
    expect(within(palette).getByRole('button', { name: /refresh current view/i })).toBeInTheDocument()
    expect(within(palette).getByRole('link', { name: /overview/i })).toHaveAttribute('href', '/')
    expect(within(palette).getByRole('link', { name: /lineage/i })).toHaveAttribute('href', '/graph')
    expect(within(palette).getByRole('link', { name: /agent mesh/i })).toHaveAttribute('href', '/mesh')
    expect(within(palette).getByRole('link', { name: /context/i })).toHaveAttribute('href', '/context')
  })

  it('renders the canonical agent-bom brand lockup in the top bar', () => {
    const { container } = renderNav()
    const wordmark = container.querySelector('img[alt="agent-bom"]')
    expect(wordmark).not.toBeNull()
    expect(wordmark!.getAttribute('src')).toMatch(/^\/brand\/wordmark-dark\.svg\?/)
    expect(screen.getByAltText('agent-bom')).toBeInTheDocument()
  })

  it('renders all 7 nav group labels', () => {
    renderExpandedNav()
    const groups = ['Posture', 'AI inventory', 'Governance', 'Connect', 'Runtime', 'Reference', 'Operations']
    for (const group of groups) {
      expect(screen.getAllByText(group).length).toBeGreaterThan(0)
    }
  })

  it('does not render sidebar group description paragraphs', () => {
    renderExpandedNav()
    expect(screen.queryByText('Inventory, coverage, and starting points')).not.toBeInTheDocument()
    expect(screen.queryByText('One security graph with attack-path, lineage, mesh, and context lenses')).not.toBeInTheDocument()
  })

  it('shows page counts for expanded nav groups', async () => {
    renderExpandedNav()
    expect(screen.getAllByText('3').length).toBeGreaterThan(0)
    fireEvent.click(screen.getByRole('button', { name: /governance/i }))
    await waitFor(() => {
      expect(screen.getAllByText('6').length).toBeGreaterThan(0)
    })
  })

  it('contains links for all primary pages across all groups', async () => {
    renderExpandedNav()
    const expectedByGroup: Record<string, string[]> = {
      Posture: ['/', '/findings', '/security-graph', '/remediation'],
      'AI inventory': ['/agents', '/manifest', '/fleet'],
      Governance: ['/compliance', '/blueprints', '/findings?lens=trust', '/governance', '/drift', '/audit'],
      Connect: ['/connections', '/sources', '/scan'],
      Runtime: ['/runtime', '/traces', '/identity'],
      Reference: ['/registry'],
      Operations: ['/cost', '/jobs', '/activity'],
    }

    for (const [group, hrefs] of Object.entries(expectedByGroup)) {
      const groupButton = screen.getByRole('button', { name: new RegExp(group, 'i') })
      if (groupButton.getAttribute('aria-expanded') !== 'true') {
        fireEvent.click(groupButton)
      }
      await waitFor(() => {
        const hrefsFound = screen.getAllByRole('link').map((l) => l.getAttribute('href'))
        for (const href of hrefs) {
          expect(hrefsFound).toContain(href)
        }
      })
    }
  })

  it('keeps the sidebar rail collapsed in capture mode so screenshots show the platform', async () => {
    window.history.replaceState({}, '', '/?capture=1')
    renderNav()

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /expand sidebar/i })).toBeInTheDocument()
    })
    expect(screen.queryByRole('button', { name: /collapse sidebar/i })).not.toBeInTheDocument()
  })

  it('moves inactive deployment surfaces into Unused capabilities', async () => {
    const { api } = await import('@/lib/api')
    vi.mocked(api.getPostureCounts).mockResolvedValueOnce({
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      total: 1,
      kev: 0,
      compound_issues: 0,
      deployment_mode: 'local',
      has_mcp_context: true,
      has_agent_context: true,
      has_local_scan: true,
      has_fleet_ingest: false,
      has_cluster_scan: false,
      has_ci_cd_scan: false,
      has_mesh: false,
      has_gateway: false,
      has_proxy: false,
      has_traces: false,
      has_registry: true,
      scan_sources: ['agent_discovery', 'sbom'],
      scan_count: 1,
    })

    renderExpandedNav()

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /ai inventory/i })).toBeInTheDocument()
    })

    fireEvent.click(screen.getByRole('button', { name: /ai inventory/i }))

    await waitFor(() => {
      expect(screen.getByText(/unused in local \(1\)/i)).toBeInTheDocument()
    })

    fireEvent.click(screen.getByText(/unused in local \(1\)/i))

    const fleetLink = screen.getByRole('link', { name: /^fleet$/i })
    expect(fleetLink).toHaveAttribute('href', '/fleet')
    expect(fleetLink).toHaveAttribute('title', 'Hidden until this deployment mode is detected')
  })

  it('keeps runtime and traces visible for hybrid deployments', async () => {
    const { api } = await import('@/lib/api')
    vi.mocked(api.getPostureCounts).mockResolvedValueOnce({
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      total: 4,
      kev: 0,
      compound_issues: 0,
      deployment_mode: 'hybrid',
      has_mcp_context: true,
      has_agent_context: true,
      has_local_scan: true,
      has_fleet_ingest: true,
      has_cluster_scan: true,
      has_ci_cd_scan: false,
      has_mesh: true,
      has_gateway: true,
      has_proxy: true,
      has_traces: true,
      has_registry: true,
      scan_sources: ['agent_discovery', 'k8s', 'sbom'],
      scan_count: 3,
    })

    renderExpandedNav()

    fireEvent.click(screen.getByRole('button', { name: /runtime/i }))
    await waitFor(() => {
      expect(screen.getAllByRole('link', { name: /^runtime$/i }).some((link) => link.getAttribute('href') === '/runtime')).toBe(true)
    })

    expect(screen.getAllByRole('link', { name: /^traces$/i }).some((link) => link.getAttribute('href') === '/traces')).toBe(true)
  })

  it('shows a single sign-in hint in the expanded session footer without duplicate copy', () => {
    authStateMock.loading = false
    authStateMock.session = {
      authenticated: false,
      auth_required: true,
      tenant_id: 'default',
      subject: null,
      role: null,
      role_summary: null,
    }

    renderExpandedNav()

    expect(screen.getByText('Sign-in required')).toBeInTheDocument()
    expect(
      screen.queryByText('Sign-in required for protected control-plane actions'),
    ).not.toBeInTheDocument()

    fireEvent.click(screen.getByText('Sign-in required'))
    expect(
      screen.queryByText('Sign-in required for protected control-plane actions'),
    ).not.toBeInTheDocument()
  })

  it('surfaces signed-in identity when the session footer is expanded', () => {
    authStateMock.loading = false
    authStateMock.session = {
      authenticated: true,
      auth_required: true,
      tenant_id: 'tenant-acme',
      subject: 'security@acme.example',
      role: 'analyst',
      role_summary: { display_name: 'Security analyst', capabilities: ['inventory.read'] },
    }

    renderExpandedNav()

    expect(screen.getByText(/Signed in · security@acme\.example/)).toBeInTheDocument()
    fireEvent.click(screen.getByText(/Signed in · security@acme\.example/))
    expect(screen.getByText('Signed in')).toBeInTheDocument()
    expect(screen.getByText('security@acme.example')).toBeInTheDocument()
    expect(screen.getByText(/Security analyst · tenant tenant-acme/)).toBeInTheDocument()
  })

  it('keeps CI-only scans from masquerading as workstation deployment context', async () => {
    const { api } = await import('@/lib/api')
    vi.mocked(api.getPostureCounts).mockResolvedValueOnce({
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      total: 1,
      kev: 0,
      compound_issues: 0,
      deployment_mode: 'local',
      has_mcp_context: false,
      has_agent_context: false,
      has_local_scan: false,
      has_fleet_ingest: false,
      has_cluster_scan: false,
      has_ci_cd_scan: true,
      has_mesh: false,
      has_gateway: false,
      has_proxy: false,
      has_traces: false,
      has_registry: false,
      scan_sources: ['github_actions'],
      scan_count: 1,
    })

    renderExpandedNav()

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /ai inventory/i })).toBeInTheDocument()
    })

    fireEvent.click(screen.getByRole('button', { name: /ai inventory/i }))

    await waitFor(() => {
      expect(screen.getByText(/unused in local/i)).toBeInTheDocument()
    })

    fireEvent.click(screen.getByText(/unused in local/i))

    const agentsLink = screen.getByRole('link', { name: /^agents$/i })
    expect(agentsLink).toHaveAttribute('href', '/agents')
    expect(agentsLink).toHaveAttribute('title', 'Hidden until this deployment mode is detected')
  })
})
