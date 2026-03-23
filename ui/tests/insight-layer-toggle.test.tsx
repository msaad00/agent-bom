import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import { InsightLayerToggle } from '@/components/insight-layer-toggle'

const defaultLayers = [
  { id: 'blast', label: 'Blast Radius', icon: '💥', active: true },
  { id: 'compliance', label: 'Compliance', icon: '🛡️', active: false },
  { id: 'lateral', label: 'Lateral Movement', icon: '↔️', active: false },
]

describe('InsightLayerToggle', () => {
  it('renders three toggle options', () => {
    render(<InsightLayerToggle layers={defaultLayers} onToggle={vi.fn()} />)
    expect(screen.getAllByRole('button')).toHaveLength(3)
  })

  it('renders label for each layer', () => {
    render(<InsightLayerToggle layers={defaultLayers} onToggle={vi.fn()} />)
    expect(screen.getByText('Blast Radius')).toBeInTheDocument()
    expect(screen.getByText('Compliance')).toBeInTheDocument()
    expect(screen.getByText('Lateral Movement')).toBeInTheDocument()
  })

  it('renders icon for each layer', () => {
    render(<InsightLayerToggle layers={defaultLayers} onToggle={vi.fn()} />)
    expect(screen.getByText('💥')).toBeInTheDocument()
    expect(screen.getByText('🛡️')).toBeInTheDocument()
    expect(screen.getByText('↔️')).toBeInTheDocument()
  })

  it('calls onToggle with correct id when first button is clicked', () => {
    const onToggle = vi.fn()
    render(<InsightLayerToggle layers={defaultLayers} onToggle={onToggle} />)
    fireEvent.click(screen.getByText('Blast Radius').closest('button')!)
    expect(onToggle).toHaveBeenCalledWith('blast')
  })

  it('calls onToggle with correct id when second button is clicked', () => {
    const onToggle = vi.fn()
    render(<InsightLayerToggle layers={defaultLayers} onToggle={onToggle} />)
    fireEvent.click(screen.getByText('Compliance').closest('button')!)
    expect(onToggle).toHaveBeenCalledWith('compliance')
  })

  it('calls onToggle with correct id when third button is clicked', () => {
    const onToggle = vi.fn()
    render(<InsightLayerToggle layers={defaultLayers} onToggle={onToggle} />)
    fireEvent.click(screen.getByText('Lateral Movement').closest('button')!)
    expect(onToggle).toHaveBeenCalledWith('lateral')
  })

  it('applies active styling to active layer button', () => {
    const { container } = render(
      <InsightLayerToggle layers={defaultLayers} onToggle={vi.fn()} />
    )
    // active layer (blast) should have purple styling
    const buttons = container.querySelectorAll('button')
    expect(buttons[0].className).toContain('purple')
  })

  it('does not apply active styling to inactive layer buttons', () => {
    const { container } = render(
      <InsightLayerToggle layers={defaultLayers} onToggle={vi.fn()} />
    )
    const buttons = container.querySelectorAll('button')
    // second and third buttons are inactive
    expect(buttons[1].className).not.toContain('purple')
    expect(buttons[2].className).not.toContain('purple')
  })

  it('highlights correct active option when second layer is active', () => {
    const layers = [
      { id: 'blast', label: 'Blast Radius', icon: '💥', active: false },
      { id: 'compliance', label: 'Compliance', icon: '🛡️', active: true },
      { id: 'lateral', label: 'Lateral Movement', icon: '↔️', active: false },
    ]
    const { container } = render(
      <InsightLayerToggle layers={layers} onToggle={vi.fn()} />
    )
    const buttons = container.querySelectorAll('button')
    expect(buttons[0].className).not.toContain('purple')
    expect(buttons[1].className).toContain('purple')
    expect(buttons[2].className).not.toContain('purple')
  })

  it('renders "Insight Layers:" label', () => {
    render(<InsightLayerToggle layers={defaultLayers} onToggle={vi.fn()} />)
    expect(screen.getByText('Insight Layers:')).toBeInTheDocument()
  })

  it('renders correctly with all layers active', () => {
    const allActive = defaultLayers.map((l) => ({ ...l, active: true }))
    const { container } = render(
      <InsightLayerToggle layers={allActive} onToggle={vi.fn()} />
    )
    const buttons = container.querySelectorAll('button')
    buttons.forEach((btn) => {
      expect(btn.className).toContain('purple')
    })
  })

  it('renders correctly with no layers active', () => {
    const noneActive = defaultLayers.map((l) => ({ ...l, active: false }))
    const { container } = render(
      <InsightLayerToggle layers={noneActive} onToggle={vi.fn()} />
    )
    const buttons = container.querySelectorAll('button')
    buttons.forEach((btn) => {
      expect(btn.className).not.toContain('purple')
    })
  })

  it('renders with empty layers array without crashing', () => {
    expect(() =>
      render(<InsightLayerToggle layers={[]} onToggle={vi.fn()} />)
    ).not.toThrow()
  })

  it('renders custom layer ids and labels correctly', () => {
    const custom = [
      { id: 'custom-1', label: 'Custom Layer', icon: '🔍', active: false },
    ]
    render(<InsightLayerToggle layers={custom} onToggle={vi.fn()} />)
    expect(screen.getByText('Custom Layer')).toBeInTheDocument()
  })
})
