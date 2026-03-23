import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { PostureGrade } from '@/components/posture-grade'

describe('PostureGrade', () => {
  it('renders the grade letter', () => {
    render(<PostureGrade grade="A" score={95} />)
    expect(screen.getByText('A')).toBeInTheDocument()
  })

  it('renders the score number', () => {
    render(<PostureGrade grade="B" score={72} />)
    expect(screen.getByText('72/100')).toBeInTheDocument()
  })

  it('renders grade F with correct score', () => {
    render(<PostureGrade grade="F" score={22} />)
    expect(screen.getByText('F')).toBeInTheDocument()
    expect(screen.getByText('22/100')).toBeInTheDocument()
  })

  it('renders SVG ring with correct stroke-dashoffset for score 100', () => {
    const { container } = render(<PostureGrade grade="A" score={100} />)
    const circles = container.querySelectorAll('circle')
    // second circle is the progress ring
    const progressCircle = circles[1]
    // circumference = 2 * π * 52 ≈ 326.726
    // dashOffset at score=100 → 0
    const dashOffset = parseFloat(progressCircle.getAttribute('stroke-dashoffset') ?? '1')
    expect(dashOffset).toBeCloseTo(0, 0)
  })

  it('renders SVG ring with correct stroke-dashoffset for score 0', () => {
    const { container } = render(<PostureGrade grade="F" score={0} />)
    const circles = container.querySelectorAll('circle')
    const progressCircle = circles[1]
    const circumference = 2 * Math.PI * 52
    const dashOffset = parseFloat(progressCircle.getAttribute('stroke-dashoffset') ?? '0')
    expect(dashOffset).toBeCloseTo(circumference, 0)
  })

  it('renders SVG ring with correct stroke-dashoffset for score 50', () => {
    const { container } = render(<PostureGrade grade="C" score={50} />)
    const circles = container.querySelectorAll('circle')
    const progressCircle = circles[1]
    const circumference = 2 * Math.PI * 52
    const expectedOffset = circumference - 0.5 * circumference
    const dashOffset = parseFloat(progressCircle.getAttribute('stroke-dashoffset') ?? '0')
    expect(dashOffset).toBeCloseTo(expectedOffset, 0)
  })

  it('renders dimensions when provided', () => {
    render(
      <PostureGrade
        grade="B"
        score={70}
        dimensions={{
          vuln: { score: 65, label: 'Vulns' },
          compliance: { score: 80, label: 'Compliance' },
        }}
      />
    )
    expect(screen.getByText('Vulns')).toBeInTheDocument()
    expect(screen.getByText('Compliance')).toBeInTheDocument()
  })

  it('does not render dimensions section when dimensions is undefined', () => {
    render(<PostureGrade grade="A" score={90} />)
    // No dimension labels should appear
    expect(screen.queryByText('Vulns')).not.toBeInTheDocument()
  })

  it('does not render dimensions section when dimensions is empty object', () => {
    const { container } = render(<PostureGrade grade="A" score={90} dimensions={{}} />)
    // No dimension bars rendered
    const bars = container.querySelectorAll('.grid')
    expect(bars.length).toBe(0)
  })

  it('uses fallback color for unknown grade', () => {
    // N/A grade — should not crash
    const { container } = render(<PostureGrade grade="N/A" score={0} />)
    expect(container).toBeTruthy()
    expect(screen.getByText('N/A')).toBeInTheDocument()
  })
})
