import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { api } from '@/lib/api'

// ─── Mock fetch globally ───────────────────────────────────────────────────────

function mockFetch(data: unknown, ok = true, status = 200) {
  return vi.fn().mockResolvedValue({
    ok,
    status,
    statusText: ok ? 'OK' : 'Error',
    json: () => Promise.resolve(data),
  })
}

const originalFetch = global.fetch

afterEach(() => {
  global.fetch = originalFetch
  vi.restoreAllMocks()
})

describe('api.listJobs', () => {
  it('returns expected shape', async () => {
    const payload = {
      jobs: [
        { job_id: 'abc123', status: 'done', created_at: '2024-01-01T00:00:00Z' },
      ],
      count: 1,
    }
    global.fetch = mockFetch(payload)
    const result = await api.listJobs()
    expect(result.jobs).toHaveLength(1)
    expect(result.jobs[0].job_id).toBe('abc123')
    expect(result.count).toBe(1)
  })

  it('throws on non-ok response', async () => {
    global.fetch = mockFetch({ detail: 'Not found' }, false, 404)
    await expect(api.listJobs()).rejects.toThrow('Not found')
  })
})

describe('api.getScan', () => {
  it('returns expected shape', async () => {
    const payload = {
      job_id: 'job-1',
      status: 'done',
      created_at: '2024-01-01T00:00:00Z',
      request: {},
      progress: [],
      result: {
        agents: [],
        blast_radius: [],
        summary: {
          total_agents: 2,
          total_servers: 5,
          total_packages: 100,
          total_vulnerabilities: 3,
          critical_findings: 1,
          high_findings: 2,
          medium_findings: 0,
          low_findings: 0,
        },
      },
    }
    global.fetch = mockFetch(payload)
    const result = await api.getScan('job-1')
    expect(result.job_id).toBe('job-1')
    expect(result.status).toBe('done')
    expect(result.result?.summary?.total_agents).toBe(2)
  })

  it('preserves richer scan contract fields from the backend', async () => {
    const payload = {
      job_id: 'job-2',
      status: 'done',
      created_at: '2024-01-01T00:00:00Z',
      request: {},
      progress: [],
      result: {
        agents: [],
        blast_radius: [],
        scorecard_summary: {
          total_packages: 12,
          unique_packages: 10,
          eligible_packages: 5,
          attempted_packages: 5,
          enriched_packages: 3,
          unresolved_packages: 2,
          failed_packages: 2,
          transient_failed_packages: 1,
          persistent_failed_packages: 1,
          failed_reasons: {
            scorecard_rate_limited: 1,
            scorecard_access_denied: 1,
          },
        },
        scan_performance: {
          pypi_cache_hits: 4,
          pypi_cache_misses: 1,
          osv_cache_hits: 6,
        },
        posture_scorecard: {
          grade: 'B',
          score: 78,
          summary: 'Good posture overall.',
          dimensions: {
            supply_chain_quality: {
              name: 'Supply Chain Quality',
              score: 80,
              weight: 0.15,
              weighted_score: 12,
              details: '3/5 packages enriched.',
            },
          },
        },
        remediation_plan: [
          {
            package: 'demo-pkg',
            ecosystem: 'pypi',
            current_version: '1.0.0',
            fixed_version: null,
            severity: 'high',
            is_kev: false,
            impact_score: 70,
            priority: 1,
            action: 'review',
            reason: 'Only prerelease fixes were available and suppressed by default.',
            command: null,
            verify_command: null,
            vulnerabilities: ['CVE-2026-0001'],
            affected_agents: ['Claude Desktop'],
            agents_pct: 100,
            exposed_credentials: [],
            credentials_pct: 0,
            reachable_tools: ['filesystem'],
            tools_pct: 100,
            owasp_tags: ['LLM05'],
            atlas_tags: ['AML.T0010'],
            risk_narrative: 'Test narrative.',
          },
        ],
        summary: {
          total_agents: 1,
          total_servers: 1,
          total_packages: 12,
          total_vulnerabilities: 1,
          critical_findings: 0,
          high_findings: 1,
          medium_findings: 0,
          low_findings: 0,
        },
      },
    }

    global.fetch = mockFetch(payload)
    const result = await api.getScan('job-2')
    expect(result.result?.scorecard_summary?.transient_failed_packages).toBe(1)
    expect(result.result?.scorecard_summary?.failed_reasons?.scorecard_access_denied).toBe(1)
    expect(result.result?.scan_performance?.osv_cache_hits).toBe(6)
    expect(result.result?.posture_scorecard?.dimensions.supply_chain_quality.weighted_score).toBe(12)
    expect(result.result?.remediation_plan?.[0].reason).toContain('prerelease')
  })

  it('throws on error', async () => {
    global.fetch = mockFetch({}, false, 500)
    await expect(api.getScan('bad-id')).rejects.toThrow('500')
  })
})

describe('api.getPosture', () => {
  it('returns expected shape', async () => {
    const payload = {
      grade: 'B',
      score: 72,
      summary: 'Good posture',
      dimensions: {
        vuln: { score: 65, label: 'Vulnerabilities' },
      },
    }
    global.fetch = mockFetch(payload)
    const result = await api.getPosture()
    expect(result.grade).toBe('B')
    expect(result.score).toBe(72)
    expect(result.dimensions).toHaveProperty('vuln')
    expect(result.dimensions.vuln.score).toBe(65)
  })

  it('throws on error', async () => {
    global.fetch = mockFetch({}, false, 503)
    await expect(api.getPosture()).rejects.toThrow('503')
  })
})

describe('api.getComplianceNarrative', () => {
  it('returns expected shape', async () => {
    const payload = {
      executive_summary: 'Overall posture is good.',
      framework_narratives: [
        {
          framework: 'OWASP LLM Top 10',
          slug: 'owasp-llm',
          status: 'passing',
          score: 80,
          narrative: 'All controls pass.',
          recommendations: [],
          failing_controls: [],
        },
      ],
      remediation_impact: [],
      risk_narrative: 'Low risk.',
      generated_at: '2024-01-01T00:00:00Z',
    }
    global.fetch = mockFetch(payload)
    const result = await api.getComplianceNarrative()
    expect(result.executive_summary).toBe('Overall posture is good.')
    expect(result.framework_narratives).toHaveLength(1)
    expect(result.framework_narratives[0].framework).toBe('OWASP LLM Top 10')
    expect(result.generated_at).toBe('2024-01-01T00:00:00Z')
  })

  it('throws on error', async () => {
    global.fetch = mockFetch({}, false, 500)
    await expect(api.getComplianceNarrative()).rejects.toThrow('500')
  })
})

describe('api.createJiraTicket', () => {
  it('sends correct payload', async () => {
    global.fetch = mockFetch({ ticket_key: 'SEC-42', status: 'created' })
    const body = {
      jira_url: 'https://example.atlassian.net',
      email: 'user@example.com',
      api_token: 'token-abc',
      project_key: 'SEC',
      finding: { cve: 'CVE-2024-1234', severity: 'critical' },
    }
    const result = await api.createJiraTicket(body)
    expect(global.fetch).toHaveBeenCalledOnce()
    const [url, opts] = (global.fetch as ReturnType<typeof vi.fn>).mock.calls[0]
    expect(url).toContain('/v1/findings/jira')
    expect(opts.method).toBe('POST')
    expect(opts.headers).toMatchObject({
      'Content-Type': 'application/json',
      'X-Jira-Api-Token': 'token-abc',
    })
    const sent = JSON.parse(opts.body as string)
    expect(sent.project_key).toBe('SEC')
    expect(sent.finding.cve).toBe('CVE-2024-1234')
    expect(sent.api_token).toBeUndefined()
    expect(result.ticket_key).toBe('SEC-42')
    expect(result.status).toBe('created')
  })

  it('throws on error', async () => {
    global.fetch = mockFetch({}, false, 400)
    await expect(
      api.createJiraTicket({
        jira_url: '',
        email: '',
        api_token: '',
        project_key: '',
        finding: {},
      })
    ).rejects.toThrow('400')
  })
})

describe('api.markFalsePositive', () => {
  it('sends correct payload', async () => {
    global.fetch = mockFetch({
      id: 'fp-1',
      vulnerability_id: 'CVE-2024-1234',
      package: 'lodash',
      status: 'suppressed',
    })
    const body = {
      vulnerability_id: 'CVE-2024-1234',
      package: 'lodash',
      reason: 'Not reachable in our use case',
      marked_by: 'security-team',
    }
    const result = await api.markFalsePositive(body)
    expect(global.fetch).toHaveBeenCalledOnce()
    const [url, opts] = (global.fetch as ReturnType<typeof vi.fn>).mock.calls[0]
    expect(url).toContain('/v1/findings/false-positive')
    expect(opts.method).toBe('POST')
    const sent = JSON.parse(opts.body as string)
    expect(sent.vulnerability_id).toBe('CVE-2024-1234')
    expect(sent.package).toBe('lodash')
    expect(sent.reason).toBe('Not reachable in our use case')
    expect(result.id).toBe('fp-1')
    expect(result.status).toBe('suppressed')
  })

  it('throws on error', async () => {
    global.fetch = mockFetch({}, false, 422)
    await expect(
      api.markFalsePositive({ vulnerability_id: 'CVE-2024-0001', package: 'pkg' })
    ).rejects.toThrow('422')
  })
})

describe('api error handling', () => {
  it('listJobs rejects with network error', async () => {
    global.fetch = vi.fn().mockRejectedValue(new Error('Network error'))
    await expect(api.listJobs()).rejects.toThrow('Network error')
  })

  it('getPosture rejects with network error', async () => {
    global.fetch = vi.fn().mockRejectedValue(new Error('Network error'))
    await expect(api.getPosture()).rejects.toThrow('Network error')
  })

  it('getScan rejects with network error', async () => {
    global.fetch = vi.fn().mockRejectedValue(new Error('Network error'))
    await expect(api.getScan('id')).rejects.toThrow('Network error')
  })
})
