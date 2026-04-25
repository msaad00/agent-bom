import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { GraphFindingsFallback } from '@/components/graph-state-panels'
import type { LineageNodeData } from '@/components/lineage-nodes'

function finding(index: number): { id: string; data: LineageNodeData } {
  const id = `CVE-2026-${String(index).padStart(4, '0')}`
  return {
    id,
    data: {
      label: id,
      nodeType: 'vulnerability',
      entityType: 'vulnerability',
      severity: index % 2 === 0 ? 'critical' : 'high',
      riskScore: 9 - (index % 3),
      cvssScore: 9.8,
      epssScore: 0.4,
      description: `Finding ${index}`,
      attributes: {},
    },
  }
}

describe('GraphFindingsFallback', () => {
  it('renders small finding sets without virtualization', () => {
    render(<GraphFindingsFallback nodes={[finding(1), finding(2)]} onSelect={vi.fn()} />)

    expect(screen.queryByTestId('virtualized-graph-findings')).not.toBeInTheDocument()
    expect(screen.getByText('CVE-2026-0001')).toBeInTheDocument()
    expect(screen.getByText('CVE-2026-0002')).toBeInTheDocument()
  })

  it('windows large finding sets instead of rendering every card', () => {
    const nodes = Array.from({ length: 120 }, (_, index) => finding(index))
    render(<GraphFindingsFallback nodes={nodes} onSelect={vi.fn()} />)

    expect(screen.getByTestId('virtualized-graph-findings')).toBeInTheDocument()
    expect(screen.getByText('CVE-2026-0000')).toBeInTheDocument()
    expect(screen.queryByText('CVE-2026-0119')).not.toBeInTheDocument()
  })

  it('keeps evidence selection wired in virtualized mode', () => {
    const onSelect = vi.fn()
    const nodes = Array.from({ length: 120 }, (_, index) => finding(index))
    render(<GraphFindingsFallback nodes={nodes} onSelect={onSelect} />)

    fireEvent.click(screen.getAllByRole('button', { name: /open evidence/i })[0])

    expect(onSelect).toHaveBeenCalledWith('CVE-2026-0000', nodes[0].data)
  })
})
