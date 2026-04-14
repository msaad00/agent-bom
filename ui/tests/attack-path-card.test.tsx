import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import { AttackPathCard } from '@/components/attack-path-card'

describe('AttackPathCard', () => {
  const baseNodes = [
    { type: 'cve' as const, label: 'CVE-2024-1234', severity: 'critical' },
    { type: 'package' as const, label: 'lodash@4.17.20', severity: 'high' },
    { type: 'server' as const, label: 'mcp-filesystem' },
    { type: 'agent' as const, label: 'claude-desktop' },
  ]

  it('renders CVE ID', () => {
    render(<AttackPathCard nodes={baseNodes} riskScore={9.1} />)
    expect(screen.getByText('CVE-2024-1234')).toBeInTheDocument()
  })

  it('renders package name and version', () => {
    render(<AttackPathCard nodes={baseNodes} riskScore={9.1} />)
    expect(screen.getByText('lodash@4.17.20')).toBeInTheDocument()
  })

  it('renders server name in the chain', () => {
    render(<AttackPathCard nodes={baseNodes} riskScore={9.1} />)
    expect(screen.getByText('mcp-filesystem')).toBeInTheDocument()
  })

  it('renders agent name in the chain', () => {
    render(<AttackPathCard nodes={baseNodes} riskScore={9.1} />)
    expect(screen.getByText('claude-desktop')).toBeInTheDocument()
  })

  it('renders risk score', () => {
    render(<AttackPathCard nodes={baseNodes} riskScore={9.1} />)
    expect(screen.getByText('9.1')).toBeInTheDocument()
  })

  it('renders risk score formatted to 1 decimal place', () => {
    render(<AttackPathCard nodes={[{ type: 'cve' as const, label: 'CVE-2024-0001' }]} riskScore={7} />)
    expect(screen.getByText('7.0')).toBeInTheDocument()
  })

  it('calls onClick when button is clicked', () => {
    const onClick = vi.fn()
    render(<AttackPathCard nodes={baseNodes} riskScore={9.1} onClick={onClick} />)
    fireEvent.click(screen.getByRole('button'))
    expect(onClick).toHaveBeenCalledOnce()
  })

  it('renders without onClick without crashing', () => {
    expect(() =>
      render(<AttackPathCard nodes={baseNodes} riskScore={5.5} />)
    ).not.toThrow()
  })

  it('renders as a link when href is provided without onClick', () => {
    render(<AttackPathCard nodes={baseNodes} riskScore={5.5} href="/security-graph" />)
    const link = screen.getByRole('link')
    expect(link).toHaveAttribute('href', '/security-graph')
    expect(screen.getByText('Open focused security graph')).toBeInTheDocument()
  })

  it('applies critical severity styling to cve node', () => {
    const { container } = render(
      <AttackPathCard
        nodes={[{ type: 'cve' as const, label: 'CVE-2024-1234', severity: 'critical' }]}
        riskScore={9.5}
      />
    )
    const criticalEl = container.querySelector('.border-red-500\\/30')
    expect(criticalEl).toBeInTheDocument()
  })

  it('applies high severity styling', () => {
    const { container } = render(
      <AttackPathCard
        nodes={[{ type: 'package' as const, label: 'pkg@1.0.0', severity: 'high' }]}
        riskScore={7.2}
      />
    )
    const highEl = container.querySelector('.border-orange-500\\/30')
    expect(highEl).toBeInTheDocument()
  })

  it('renders arrow separators between nodes', () => {
    const { getAllByText } = render(<AttackPathCard nodes={baseNodes} riskScore={8.0} />)
    // 4 nodes → 3 arrows
    const arrows = getAllByText('→')
    expect(arrows).toHaveLength(3)
  })

  it('handles single node without arrows', () => {
    const { queryAllByText } = render(
      <AttackPathCard
        nodes={[{ type: 'agent' as const, label: 'cursor-ide' }]}
        riskScore={3.0}
      />
    )
    expect(queryAllByText('→')).toHaveLength(0)
  })

  it('shows Risk label', () => {
    render(<AttackPathCard nodes={baseNodes} riskScore={9.1} />)
    expect(screen.getByText('Risk')).toBeInTheDocument()
  })

  it('applies red color class for risk >= 8', () => {
    const { container } = render(
      <AttackPathCard nodes={baseNodes} riskScore={8.5} />
    )
    const riskEl = container.querySelector('.text-red-400')
    expect(riskEl).toBeInTheDocument()
  })

  it('applies orange color class for risk between 5 and 8', () => {
    const { container } = render(
      <AttackPathCard nodes={baseNodes} riskScore={6.5} />
    )
    const riskEl = container.querySelector('.text-orange-400')
    expect(riskEl).toBeInTheDocument()
  })

  it('applies zinc color class for risk below 5', () => {
    const { container } = render(
      <AttackPathCard nodes={baseNodes} riskScore={3.0} />
    )
    const riskEl = container.querySelector('.text-zinc-400')
    expect(riskEl).toBeInTheDocument()
  })

  it('renders credential node type with key icon', () => {
    render(
      <AttackPathCard
        nodes={[{ type: 'credential' as const, label: 'ANTHROPIC_KEY' }]}
        riskScore={6.0}
      />
    )
    expect(screen.getByText('ANTHROPIC_KEY')).toBeInTheDocument()
  })
})
