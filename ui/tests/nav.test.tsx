import { render, screen } from '@testing-library/react'
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
    health: vi.fn().mockResolvedValue({ status: 'ok', version: '0.75.12' }),
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
    const links = screen.getAllByRole('link', { name: /new scan/i })
    expect(links.some((l) => l.getAttribute('href') === '/scan')).toBe(true)
  })

  it('contains link to Scan Jobs (/jobs)', () => {
    render(<Nav />)
    const links = screen.getAllByRole('link', { name: /scan jobs/i })
    expect(links.some((l) => l.getAttribute('href') === '/jobs')).toBe(true)
  })

  it('contains link to Vulnerabilities (/vulns)', () => {
    render(<Nav />)
    const links = screen.getAllByRole('link', { name: /vulnerabilities/i })
    expect(links.some((l) => l.getAttribute('href') === '/vulns')).toBe(true)
  })

  it('contains Remediation link', () => {
    render(<Nav />)
    const links = screen.getAllByRole('link', { name: /remediation/i })
    expect(links.some((l) => l.getAttribute('href') === '/remediation')).toBe(true)
  })

  it('contains Security Graph link', () => {
    render(<Nav />)
    const links = screen.getAllByRole('link', { name: /security graph/i })
    expect(links.some((l) => l.getAttribute('href') === '/security-graph')).toBe(true)
  })

  it('contains Lineage Graph link', () => {
    render(<Nav />)
    const links = screen.getAllByRole('link', { name: /lineage graph/i })
    expect(links.some((l) => l.getAttribute('href') === '/graph')).toBe(true)
  })

  it('contains Agent Mesh link', () => {
    render(<Nav />)
    const links = screen.getAllByRole('link', { name: /agent mesh/i })
    expect(links.some((l) => l.getAttribute('href') === '/mesh')).toBe(true)
  })

  it('contains Compliance link', () => {
    render(<Nav />)
    const links = screen.getAllByRole('link', { name: /^compliance$/i })
    expect(links.some((l) => l.getAttribute('href') === '/compliance')).toBe(true)
  })

  it('contains Governance link', () => {
    render(<Nav />)
    const links = screen.getAllByRole('link', { name: /^governance$/i })
    expect(links.some((l) => l.getAttribute('href') === '/governance')).toBe(true)
  })

  it('contains Audit Log link', () => {
    render(<Nav />)
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

  it('contains links for all 23 pages across all groups', () => {
    render(<Nav />)
    const expectedHrefs = [
      '/', '/scan', '/jobs',
      '/agents', '/vulns', '/fleet', '/registry',
      '/security-graph', '/graph', '/mesh', '/context', '/insights',
      '/proxy', '/audit', '/gateway',
      '/compliance', '/remediation', '/governance', '/traces', '/activity',
    ]
    const allLinks = screen.getAllByRole('link')
    const hrefsFound = allLinks.map((l) => l.getAttribute('href'))
    for (const href of expectedHrefs) {
      expect(hrefsFound).toContain(href)
    }
  })
})
