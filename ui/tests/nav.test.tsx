import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'

// Mock next/link so it renders a plain anchor
vi.mock('next/link', () => ({
  default: ({ href, children, ...rest }: { href: string; children: React.ReactNode; [key: string]: unknown }) => (
    <a href={href} {...rest}>{children}</a>
  ),
}))

// Mock next/navigation
vi.mock('next/navigation', () => ({
  usePathname: () => '/',
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
      has_mcp_context: false,
      has_agent_context: false,
      scan_sources: [],
      scan_count: 0,
    }),
    health: vi.fn().mockResolvedValue({ status: 'ok', version: '0.76.4' }),
  },
}))

import { Nav } from '@/components/nav'

describe('Nav', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders the Discover nav group', () => {
    render(<Nav />)
    expect(screen.getByText('Discover')).toBeInTheDocument()
    expect(screen.getByText('Inventory, coverage, and starting points')).toBeInTheDocument()
  })

  it('renders the Scan nav group', () => {
    render(<Nav />)
    expect(screen.getByText('Scan')).toBeInTheDocument()
  })

  it('renders the Analyze nav group', () => {
    render(<Nav />)
    expect(screen.getByText('Analyze')).toBeInTheDocument()
  })

  it('renders the Protect nav group', () => {
    render(<Nav />)
    expect(screen.getByText('Protect')).toBeInTheDocument()
  })

  it('renders the Governance nav group', () => {
    render(<Nav />)
    // 'Govern' appears both as a group label and as a page link, so use getAllByText
    expect(screen.getAllByText('Govern').length).toBeGreaterThan(0)
  })

  it('contains link to Dashboard (/)', () => {
    render(<Nav />)
    const links = screen.getAllByRole('link', { name: /dashboard/i })
    expect(links.length).toBeGreaterThan(0)
  })

  it('contains link to New Scan (/scan)', () => {
    render(<Nav />)
    fireEvent.click(screen.getByRole('button', { name: /scan/i }))
    const links = screen.getAllByRole('link', { name: /new scan/i })
    expect(links.some((l) => l.getAttribute('href') === '/scan')).toBe(true)
  })

  it('contains link to Data Sources (/sources)', () => {
    render(<Nav />)
    fireEvent.click(screen.getByRole('button', { name: /scan/i }))
    const links = screen.getAllByRole('link', { name: /data sources/i })
    expect(links.some((l) => l.getAttribute('href') === '/sources')).toBe(true)
  })

  it('contains link to Scan Jobs (/jobs)', () => {
    render(<Nav />)
    fireEvent.click(screen.getByRole('button', { name: /scan/i }))
    const links = screen.getAllByRole('link', { name: /scan jobs/i })
    expect(links.some((l) => l.getAttribute('href') === '/jobs')).toBe(true)
  })

  it('contains link to Findings (/findings)', () => {
    render(<Nav />)
    fireEvent.click(screen.getByRole('button', { name: /scan/i }))
    const links = screen.getAllByRole('link', { name: /findings/i })
    expect(links.some((l) => l.getAttribute('href') === '/findings')).toBe(true)
  })

  it('contains Remediation link', () => {
    render(<Nav />)
    fireEvent.click(screen.getByRole('button', { name: /govern/i }))
    const links = screen.getAllByRole('link', { name: /remediation/i })
    expect(links.some((l) => l.getAttribute('href') === '/remediation')).toBe(true)
  })

  it('contains Security Graph link', () => {
    render(<Nav />)
    fireEvent.click(screen.getByRole('button', { name: /analyze/i }))
    const links = screen.getAllByRole('link', { name: /security graph/i })
    expect(links.some((l) => l.getAttribute('href') === '/security-graph')).toBe(true)
  })

  it('contains Lineage Graph link', () => {
    render(<Nav />)
    fireEvent.click(screen.getByRole('button', { name: /analyze/i }))
    const links = screen.getAllByRole('link', { name: /lineage graph/i })
    expect(links.some((l) => l.getAttribute('href') === '/graph')).toBe(true)
  })

  it('contains Agent Mesh link', () => {
    render(<Nav />)
    fireEvent.click(screen.getByRole('button', { name: /analyze/i }))
    const links = screen.getAllByRole('link', { name: /agent mesh/i })
    expect(links.some((l) => l.getAttribute('href') === '/mesh')).toBe(true)
  })

  it('contains Compliance link', () => {
    render(<Nav />)
    fireEvent.click(screen.getByRole('button', { name: /govern/i }))
    const links = screen.getAllByRole('link', { name: /^compliance$/i })
    expect(links.some((l) => l.getAttribute('href') === '/compliance')).toBe(true)
  })

  it('contains Governance link', () => {
    render(<Nav />)
    fireEvent.click(screen.getByRole('button', { name: /govern/i }))
    const links = screen.getAllByRole('link', { name: /^governance$/i })
    expect(links.some((l) => l.getAttribute('href') === '/governance')).toBe(true)
  })

  it('contains Audit Log link', () => {
    render(<Nav />)
    fireEvent.click(screen.getByRole('button', { name: /protect/i }))
    const links = screen.getAllByRole('link', { name: /audit log/i })
    expect(links.some((l) => l.getAttribute('href') === '/audit')).toBe(true)
  })

  it('renders the agent-bom brand text', () => {
    render(<Nav />)
    expect(screen.getAllByText('agent-bom').length).toBeGreaterThan(0)
  })

  it('renders all 5 nav group labels', () => {
    render(<Nav />)
    // Use getAllByText to handle cases where a label also appears as a page link (e.g. Governance)
    const groups = ['Discover', 'Scan', 'Analyze', 'Protect', 'Govern']
    for (const group of groups) {
      expect(screen.getAllByText(group).length).toBeGreaterThan(0)
    }
  })

  it('shows page counts for expanded nav groups', async () => {
    render(<Nav />)
    expect(screen.getAllByText('4').length).toBeGreaterThan(0)
    fireEvent.click(screen.getByRole('button', { name: /analyze/i }))
    await waitFor(() => {
      expect(screen.getAllByText('5').length).toBeGreaterThan(0)
    })
  })

  it('contains links for all primary pages across all groups', async () => {
    render(<Nav />)
    const expectedByGroup: Record<string, string[]> = {
      Discover: ['/', '/agents', '/fleet'],
      Scan: ['/sources', '/scan', '/jobs', '/findings'],
      Analyze: ['/security-graph', '/graph', '/mesh', '/context', '/insights'],
      Protect: ['/proxy', '/audit', '/gateway'],
      Govern: ['/compliance', '/remediation', '/governance', '/traces', '/activity'],
    }

    for (const [group, hrefs] of Object.entries(expectedByGroup)) {
      fireEvent.click(screen.getByRole('button', { name: new RegExp(group, 'i') }))
      await waitFor(() => {
        const hrefsFound = screen.getAllByRole('link').map((l) => l.getAttribute('href'))
        for (const href of hrefs) {
          expect(hrefsFound).toContain(href)
        }
      })
    }
  })
})
