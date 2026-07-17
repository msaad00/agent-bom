import { describe, it, expect, vi, afterEach } from 'vitest'
import { api } from '@/lib/api'
import { clearSessionApiKey, setSessionApiKey } from '@/lib/auth'

// ─── Mock fetch globally ───────────────────────────────────────────────────────

function mockFetch(data: unknown, ok = true, status = 200) {
  return vi.fn().mockResolvedValue({
    ok,
    status,
    statusText: ok ? 'OK' : 'Error',
    json: () => Promise.resolve(data),
  })
}

function mockBlobFetch(contents: string, ok = true, status = 200, type = 'application/json') {
  return vi.fn().mockResolvedValue({
    ok,
    status,
    statusText: ok ? 'OK' : 'Error',
    json: () => Promise.resolve({}),
    blob: () => Promise.resolve(new Blob([contents], { type })),
  })
}

const originalFetch = global.fetch

afterEach(() => {
  global.fetch = originalFetch
  window.__AGENT_BOM_CONFIG__ = undefined
  clearSessionApiKey()
  vi.restoreAllMocks()
})

describe('api.listJobs', () => {
  it('prefers a same-origin runtime API URL over the build-time env', async () => {
    const oldApiUrl = process.env.NEXT_PUBLIC_API_URL
    process.env.NEXT_PUBLIC_API_URL = "https://build.example"
    window.__AGENT_BOM_CONFIG__ = { apiUrl: "/agent-bom-api" }

    const fetchMock = mockFetch({ jobs: [], count: 0 })
    global.fetch = fetchMock

    await api.listJobs()

    expect(fetchMock).toHaveBeenCalledWith(
      "/agent-bom-api/v1/jobs",
      expect.objectContaining({ signal: expect.any(AbortSignal) }),
    )

    if (oldApiUrl === undefined) {
      delete process.env.NEXT_PUBLIC_API_URL
    } else {
      process.env.NEXT_PUBLIC_API_URL = oldApiUrl
    }
  })

  it('rejects cross-origin runtime API URLs', async () => {
    const oldApiUrl = process.env.NEXT_PUBLIC_API_URL
    process.env.NEXT_PUBLIC_API_URL = "https://build.example"
    window.__AGENT_BOM_CONFIG__ = { apiUrl: "https://runtime.example" }

    const fetchMock = mockFetch({ jobs: [], count: 0 })
    global.fetch = fetchMock

    await api.listJobs()

    expect(fetchMock).toHaveBeenCalledWith(
      "/v1/jobs",
      expect.objectContaining({ signal: expect.any(AbortSignal) }),
    )

    if (oldApiUrl === undefined) {
      delete process.env.NEXT_PUBLIC_API_URL
    } else {
      process.env.NEXT_PUBLIC_API_URL = oldApiUrl
    }
  })

  it('rejects cross-origin build-time API URLs in the browser', async () => {
    const oldApiUrl = process.env.NEXT_PUBLIC_API_URL
    process.env.NEXT_PUBLIC_API_URL = "https://build.example"
    window.__AGENT_BOM_CONFIG__ = undefined

    const fetchMock = mockFetch({ jobs: [], count: 0 })
    global.fetch = fetchMock

    await api.listJobs()

    expect(fetchMock).toHaveBeenCalledWith(
      "/v1/jobs",
      expect.objectContaining({ signal: expect.any(AbortSignal) }),
    )

    if (oldApiUrl === undefined) {
      delete process.env.NEXT_PUBLIC_API_URL
    } else {
      process.env.NEXT_PUBLIC_API_URL = oldApiUrl
    }
  })

  it('allows same-origin runtime routing when the runtime API URL is blank', async () => {
    const oldApiUrl = process.env.NEXT_PUBLIC_API_URL
    process.env.NEXT_PUBLIC_API_URL = "https://build.example"
    window.__AGENT_BOM_CONFIG__ = { apiUrl: "" }

    const fetchMock = mockFetch({ jobs: [], count: 0 })
    global.fetch = fetchMock

    await api.listJobs()

    expect(fetchMock).toHaveBeenCalledWith(
      "/v1/jobs",
      expect.objectContaining({ signal: expect.any(AbortSignal) }),
    )

    if (oldApiUrl === undefined) {
      delete process.env.NEXT_PUBLIC_API_URL
    } else {
      process.env.NEXT_PUBLIC_API_URL = oldApiUrl
    }
  })

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
    expect(result.jobs[0]!.job_id).toBe('abc123')
    expect(result.count).toBe(1)
  })

  it('does not propagate browser-stored API keys and relies on same-origin credentials', async () => {
    setSessionApiKey("pilot-key-123")
    const fetchMock = mockFetch({ jobs: [], count: 0 })
    global.fetch = fetchMock

    await api.listJobs()

    expect(fetchMock).toHaveBeenCalledWith(
      "/v1/jobs",
      expect.objectContaining({
        credentials: "include",
        headers: {},
        signal: expect.any(AbortSignal),
      }),
    )
  })

  it('ignores legacy browser token setter paths', async () => {
    window.__AGENT_BOM_CONFIG__ = { apiUrl: "" }
    setSessionApiKey("pilot-key-123")
    const fetchMock = mockFetch({ jobs: [], count: 0 })
    global.fetch = fetchMock

    await api.listJobs()

    expect(fetchMock).toHaveBeenCalledWith(
      "/v1/jobs",
      expect.objectContaining({
        credentials: "include",
        headers: {},
        signal: expect.any(AbortSignal),
      }),
    )
  })

  it('throws on non-ok response', async () => {
    global.fetch = mockFetch({ detail: 'Not found' }, false, 404)
    await expect(api.listJobs()).rejects.toThrow('Not found')
  })
})

describe('api.getGraphImpact', () => {
  it('requests the blast-radius endpoint with node, scan, and depth', async () => {
    const payload = {
      node_id: 'server:github-mcp',
      affected_nodes: ['agent:coder', 'tool:read_file'],
      affected_by_type: { agent: 1, tool: 1 },
      affected_count: 2,
      max_depth_reached: 2,
    }
    const fetchMock = mockFetch(payload)
    global.fetch = fetchMock

    const result = await api.getGraphImpact('server:github-mcp', 'scan-1', 4)

    expect(fetchMock).toHaveBeenCalledWith(
      '/v1/graph/impact?node=server%3Agithub-mcp&scan_id=scan-1&max_depth=4',
      expect.objectContaining({ credentials: 'include' }),
    )
    expect(result.affected_count).toBe(2)
    expect(result.affected_nodes).toContain('agent:coder')
  })

  it('omits optional params when not provided', async () => {
    const fetchMock = mockFetch({
      node_id: 'n1',
      affected_nodes: [],
      affected_by_type: {},
      affected_count: 0,
      max_depth_reached: 0,
    })
    global.fetch = fetchMock

    await api.getGraphImpact('n1')

    expect(fetchMock).toHaveBeenCalledWith(
      '/v1/graph/impact?node=n1',
      expect.objectContaining({ credentials: 'include' }),
    )
  })
})

describe('api.getGraphRollup', () => {
  it('requests the estate roll-up endpoint with scan and drill params', async () => {
    const payload = {
      scan_id: 'scan-1',
      tenant_id: 'default',
      created_at: '2026-01-01T00:00:00Z',
      mode: 'drilldown',
      filters: {},
      children: [],
      summary: { direct_child_count: 2, returned_child_count: 2 },
    }
    const fetchMock = mockFetch(payload)
    global.fetch = fetchMock

    const result = await api.getGraphRollup('scan-1', {
      node: 'account:prod',
      minSeverity: 'high',
      exposed: true,
      toxic: true,
      mode: 'attack_path',
    })

    expect(fetchMock).toHaveBeenCalledWith(
      '/v1/graph/rollup?scan_id=scan-1&node=account%3Aprod&min_severity=high&exposed=true&toxic=true&mode=attack_path',
      expect.objectContaining({ credentials: 'include' }),
    )
    expect(result.mode).toBe('drilldown')
  })

  it('omits optional params when not provided', async () => {
    const fetchMock = mockFetch({
      scan_id: 'scan-1',
      tenant_id: 'default',
      created_at: '2026-01-01T00:00:00Z',
      mode: 'rollup',
      filters: {},
      top_level: [],
      summary: { top_level_count: 0 },
    })
    global.fetch = fetchMock

    await api.getGraphRollup()

    expect(fetchMock).toHaveBeenCalledWith(
      '/v1/graph/rollup',
      expect.objectContaining({ credentials: 'include' }),
    )
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

  it('polls lightweight scan status without requesting full results', async () => {
    const payload = {
      job_id: 'job-1',
      status: 'running',
      created_at: '2024-01-01T00:00:00Z',
      request: {},
      summary: {
        total_agents: 2,
        total_servers: 5,
        total_packages: 100,
        total_vulnerabilities: 3,
      },
    }
    const fetchMock = mockFetch(payload)
    global.fetch = fetchMock

    const result = await api.getScanStatus('job-1')

    expect(fetchMock).toHaveBeenCalledWith(
      "/v1/scan/job-1/status",
      expect.objectContaining({
        credentials: "include",
        headers: {},
        signal: expect.any(AbortSignal),
      }),
    )
    expect(result.job_id).toBe('job-1')
    expect(result.summary?.total_packages).toBe(100)
    expect('result' in result).toBe(false)
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
            impact_score: 7.0,
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
    expect(result.result?.posture_scorecard?.dimensions.supply_chain_quality?.weighted_score).toBe(12)
    expect(result.result?.remediation_plan?.[0]?.reason).toContain('prerelease')
  })

  it('throws on error', async () => {
    global.fetch = mockFetch({}, false, 500)
    await expect(api.getScan('bad-id')).rejects.toThrow('500')
  })
})

describe('api key lifecycle helpers', () => {
  it('lists keys through the enterprise auth route', async () => {
    const payload = {
      keys: [
        {
          key_id: 'key-1',
          key_prefix: 'abom_demo',
          name: 'ci-service',
          role: 'admin',
          created_at: '2026-04-21T00:00:00Z',
          expires_at: '2026-05-21T00:00:00Z',
          scopes: [],
          tenant_id: 'tenant-alpha',
          revoked_at: null,
          rotation_overlap_until: null,
          replacement_key_id: null,
          state: 'active',
          overlap_seconds_remaining: null,
        },
      ],
    }
    const fetchMock = mockFetch(payload)
    global.fetch = fetchMock

    const result = await api.listKeys()

    expect(result.keys).toHaveLength(1)
    expect(result.keys[0]!.name).toBe('ci-service')
    expect(fetchMock).toHaveBeenCalledWith(
      "/v1/auth/keys",
      expect.objectContaining({
        credentials: "include",
        headers: expect.any(Object),
        signal: expect.any(AbortSignal),
      }),
    )
  })

  it('posts rotate requests to the expected endpoint', async () => {
    const payload = {
      raw_key: 'abom_new_secret',
      key_id: 'key-2',
      replaced_key_id: 'key-1',
      key_prefix: 'abom_new_',
      name: 'ci-service',
      role: 'admin',
      created_at: '2026-04-21T00:05:00Z',
      expires_at: '2026-05-21T00:05:00Z',
      tenant_id: 'tenant-alpha',
      revoked_at: null,
      rotation_overlap_until: '2026-04-21T00:20:00Z',
      replacement_key_id: null,
      state: 'active',
      overlap_seconds_remaining: null,
      overlap_until: '2026-04-21T00:20:00Z',
      overlap_seconds: 900,
      scopes: [],
      message: 'rotated',
    }
    const fetchMock = mockFetch(payload)
    global.fetch = fetchMock

    const result = await api.rotateKey('key-1', { overlap_seconds: 900 })

    expect(result.replaced_key_id).toBe('key-1')
    expect(fetchMock).toHaveBeenCalledWith(
      "/v1/auth/keys/key-1/rotate",
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({ "Content-Type": "application/json" }),
        body: JSON.stringify({ overlap_seconds: 900 }),
        signal: expect.any(AbortSignal),
      }),
    )
  })
})

describe('api.downloadScanGraph', () => {
  it('downloads graph export with same-origin browser credentials only', async () => {
    setSessionApiKey('pilot-key-123')
    const fetchMock = mockBlobFetch('{"nodes":[],"edges":[]}')
    global.fetch = fetchMock

    const blob = await api.downloadScanGraph('job-1')

    expect(blob).toBeInstanceOf(Blob)
    expect(fetchMock).toHaveBeenCalledWith(
      '/v1/scan/job-1/graph-export?format=json',
      expect.objectContaining({
        credentials: 'include',
        headers: {},
        signal: expect.any(AbortSignal),
      }),
    )
  })
})

describe('api.getAgentBomManifest', () => {
  it('loads the canonical Agent BOM manifest route', async () => {
    const payload = {
      schema_version: 'agent-bom.manifest/v1',
      generated_at: '2026-05-18T00:00:00Z',
      source: 'control-plane',
      summary: {
        agents: 1,
        mcp_servers: 1,
        tools: 2,
        credential_refs: 1,
        runtime_observed_servers: 1,
        gateway_registered_servers: 0,
      },
      visibility: {
        owners: 1,
        unowned_agents: 0,
        shadow_runtime_servers: 1,
        untracked_runtime_servers: 0,
        servers_with_warnings: 0,
        risky_credential_refs: 1,
        risk_signals: {
          unowned_agent_ids: [],
          shadow_runtime_server_ids: ['srv-1'],
          untracked_runtime_server_ids: [],
          risky_credential_refs: ['API_KEY'],
        },
      },
      blueprint_drift: {
        status: 'needs_review',
        mode: 'observation_only',
        fail_behavior: 'report_only',
        signal_count: 1,
        signals: [
          {
            kind: 'unregistered_runtime_server',
            entity_id: 'srv-1',
            severity: 'warning',
            message: 'srv-1 was observed at runtime but is not registered with the gateway.',
          },
        ],
      },
      agents: [],
      mcp_servers: [],
      graph: { nodes: [], edges: [], stats: { nodes: 0, edges: 0, relationships: [] } },
      boundaries: {
        stores_credential_values: false,
        stores_raw_prompts: false,
        credential_value_policy: 'redacted',
      },
    }
    const fetchMock = mockFetch(payload)
    global.fetch = fetchMock

    const result = await api.getAgentBomManifest()

    expect(result.schema_version).toBe('agent-bom.manifest/v1')
    expect(fetchMock).toHaveBeenCalledWith(
      '/v1/agent-bom/manifest',
      expect.objectContaining({
        headers: {},
        signal: expect.any(AbortSignal),
      }),
    )
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
    expect(result.dimensions.vuln?.score).toBe(65)
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
    expect(result.framework_narratives[0]!.framework).toBe('OWASP LLM Top 10')
    expect(result.generated_at).toBe('2024-01-01T00:00:00Z')
  })

  it('throws on error', async () => {
    global.fetch = mockFetch({}, false, 500)
    await expect(api.getComplianceNarrative()).rejects.toThrow('500')
  })
})

describe('api ticketing (connect-once)', () => {
  it('listTicketingConnections reads the connect-once endpoint', async () => {
    global.fetch = mockFetch({
      schema_version: 'ticketing.connections.v1',
      tenant_id: 't1',
      connections: [{ id: 'c1', provider: 'jira', status: 'active' }],
      count: 1,
    })
    const result = await api.listTicketingConnections()
    const [url, opts] = (global.fetch as ReturnType<typeof vi.fn>).mock.calls[0]!
    expect(url).toContain('/v1/ticketing/connections')
    expect(opts.method ?? 'GET').toBe('GET')
    expect(result.connections[0]!.id).toBe('c1')
  })

  it('createTicket posts finding + connection, never a credential', async () => {
    global.fetch = mockFetch({
      schema_version: 'ticketing.ticket.v1',
      ticket: { id: 'tk1', key: 'SEC-42', status: 'open', dedupe_key: 'CVE-1:pkg' },
      connection_id: 'c1',
      provider: 'jira',
      deduplicated: false,
    })
    const result = await api.createTicket({
      connection_id: 'c1',
      finding_id: 'CVE-1:pkg',
      project: 'SEC',
      finding: { vulnerability_id: 'CVE-1', package: 'pkg', severity: 'critical' },
    })
    const [url, opts] = (global.fetch as ReturnType<typeof vi.fn>).mock.calls[0]!
    expect(url).toContain('/v1/ticketing/tickets')
    expect(opts.method).toBe('POST')
    const sent = JSON.parse(opts.body as string)
    expect(sent.connection_id).toBe('c1')
    expect(sent.finding.vulnerability_id).toBe('CVE-1')
    // No credential / token / base-url field may ever be sent.
    expect(sent.api_token).toBeUndefined()
    expect(sent.jira_url).toBeUndefined()
    expect(sent.secret).toBeUndefined()
    // No per-action credential header either.
    expect(opts.headers['X-Jira-Api-Token']).toBeUndefined()
    expect(result.ticket.key).toBe('SEC-42')
  })

  it('listTickets filters by finding id when given', async () => {
    global.fetch = mockFetch({
      schema_version: 'ticketing.tickets.v1',
      tenant_id: 't1',
      tickets: [
        { id: 'a', dedupe_key: 'CVE-1:pkg', status: 'open' },
        { id: 'b', dedupe_key: 'CVE-2:other', status: 'done' },
      ],
      count: 2,
    })
    const result = await api.listTickets('CVE-1:pkg')
    expect(result.tickets).toHaveLength(1)
    expect(result.tickets[0]!.id).toBe('a')
    expect(result.count).toBe(1)
  })

  it('syncTicket posts to the ticket sync endpoint', async () => {
    global.fetch = mockFetch({
      schema_version: 'ticketing.ticket.v1',
      ticket: { id: 'tk1', key: 'SEC-42', status: 'done', dedupe_key: 'CVE-1:pkg' },
      connection_id: 'c1',
      provider: 'jira',
      deduplicated: false,
    })
    const result = await api.syncTicket('tk1')
    const [url, opts] = (global.fetch as ReturnType<typeof vi.fn>).mock.calls[0]!
    expect(url).toContain('/v1/ticketing/tickets/tk1/sync')
    expect(opts.method).toBe('POST')
    expect(result.ticket.status).toBe('done')
  })

  it('throws on error', async () => {
    global.fetch = mockFetch({}, false, 409)
    await expect(
      api.createTicket({ finding: {} })
    ).rejects.toThrow('409')
  })
})

describe('api risk campaigns', () => {
  it('reads the authoritative campaign collection', async () => {
    global.fetch = mockFetch({
      schema_version: 'risk-campaigns.v1',
      tenant_id: 't1',
      campaigns: [],
      count: 0,
      finding_window_days: 90,
      finding_limit: 1000,
      truncated: false,
      total_findings: 0,
      total_approximate: false,
    })

    const result = await api.listRiskCampaigns()
    const [url, opts] = (global.fetch as ReturnType<typeof vi.fn>).mock.calls[0]!
    expect(url).toContain('/v1/campaigns')
    expect(opts.method ?? 'GET').toBe('GET')
    expect(result.finding_window_days).toBe(90)
    expect(result.total_approximate).toBe(false)
  })

  it('reads the durable inactive verification queue', async () => {
    global.fetch = mockFetch({
      schema_version: 'risk-campaign-verification-queue.v1',
      tenant_id: 't1',
      entries: [],
      count: 0,
      has_more: false,
      next_cursor: null,
      limit: 25,
    })

    await api.listRiskCampaignVerificationQueue({ cursor: 'next page', limit: 500 })
    const [url, opts] = (global.fetch as ReturnType<typeof vi.fn>).mock.calls[0]!
    expect(url).toContain('/v1/campaigns/verification-queue')
    expect(url).toContain('cursor=next+page')
    expect(url).toContain('limit=100')
    expect(opts.method ?? 'GET').toBe('GET')
  })

  it('patches only workflow fields', async () => {
    global.fetch = mockFetch({ id: 'campaign-1', state: 'blocked' })
    await api.updateRiskCampaign('campaign-1', { version: 4, state: 'blocked' })

    const [url, opts] = (global.fetch as ReturnType<typeof vi.fn>).mock.calls[0]!
    expect(url).toContain('/v1/campaigns/campaign-1')
    expect(opts.method).toBe('PATCH')
    expect(JSON.parse(opts.body as string)).toEqual({ version: 4, state: 'blocked' })
  })

  it('requests server-owned campaign verification using only the workflow version', async () => {
    global.fetch = mockFetch({
      schema_version: 'risk-campaign-verification.v1',
      campaign_id: 'campaign-1',
      verification_status: 'verified',
      state: 'done',
      remaining_finding_ids: [],
      remaining_count: 0,
      original_member_count: 2,
      evidence_scope: {
        source: 'canonical_findings_spine',
        finding_window_days: 90,
        finding_limit: 1000,
        membership_complete: true,
      },
      version: 5,
      verified_at: '2026-07-17T13:00:00Z',
    })

    await api.verifyRiskCampaign('campaign-1', { version: 4 })

    const [url, opts] = (global.fetch as ReturnType<typeof vi.fn>).mock.calls[0]!
    expect(url).toContain('/v1/campaigns/campaign-1/verify')
    expect(opts.method).toBe('POST')
    expect(JSON.parse(opts.body as string)).toEqual({ version: 4 })
  })

  it('creates campaign tickets through stored connections without credential fields', async () => {
    global.fetch = mockFetch({
      schema_version: 'risk-campaign-tickets.v1',
      campaign_id: 'campaign-1',
      created: 2,
      failed: 0,
      tickets: [],
      errors: [],
      per_action_credential: false,
    })
    await api.createRiskCampaignTickets('campaign-1', {
      connection_id: 'connection-1',
      project: 'SEC',
    })

    const [url, opts] = (global.fetch as ReturnType<typeof vi.fn>).mock.calls[0]!
    expect(url).toContain('/v1/campaigns/campaign-1/tickets')
    expect(opts.method).toBe('POST')
    const body = JSON.parse(opts.body as string)
    expect(body).toEqual({ connection_id: 'connection-1', project: 'SEC', limit: 25 })
    expect(body.credential).toBeUndefined()
    expect(body.token).toBeUndefined()
  })

  it('bounds campaign action pages to 25 for create and sync', async () => {
    global.fetch = mockFetch({
      schema_version: 'risk-campaign-ticket-sync.v1',
      campaign_id: 'campaign-1',
      synced: 0,
      failed: 0,
      tickets: [],
      errors: [],
      per_action_credential: false,
      total: 0,
      processed: 0,
      next_cursor: null,
      has_more: false,
      action_limit: 25,
    })

    await api.syncRiskCampaignTickets('campaign-1', { cursor: 'next page', limit: 500 })
    const [url, opts] = (global.fetch as ReturnType<typeof vi.fn>).mock.calls[0]!
    expect(url).toContain('/v1/campaigns/campaign-1/tickets/sync?')
    expect(url).toContain('cursor=next+page')
    expect(url).toContain('limit=25')
    expect(opts.method).toBe('POST')
    expect(JSON.parse(opts.body as string)).toEqual({})
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
    const [url, opts] = (global.fetch as ReturnType<typeof vi.fn>).mock.calls[0]!
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

describe('api finding triage helpers', () => {
  it('lists tenant-scoped triage queue entries with filters', async () => {
    global.fetch = mockFetch({
      schema_version: 'findings.triage.v1',
      triage: [
        {
          id: 'triage-1',
          vulnerability_id: 'CVE-2026-0101',
          package: 'pkg:pypi/requests@2.31.0',
          server_name: '',
          queue_state: 'decided',
          decision: 'not_affected',
          justification: 'vulnerable_code_not_in_execute_path',
          decision_reason: 'not reachable',
          assignee: 'secops@example.com',
          created_by: 'alice',
          created_at: '2026-05-29T00:00:00Z',
          reviewed_at: '2026-05-29T00:01:00Z',
          expires_at: '',
          tenant_id: 'tenant-alpha',
          vex_eligible: true,
        },
      ],
      total: 1,
      limit: 100,
      offset: 0,
    })

    const result = await api.listFindingTriage({ decision: 'not_affected', limit: 100 })

    expect(global.fetch).toHaveBeenCalledOnce()
    const [url, opts] = (global.fetch as ReturnType<typeof vi.fn>).mock.calls[0]!
    expect(url).toContain('/v1/findings/triage?')
    expect(url).toContain('decision=not_affected')
    expect(url).toContain('limit=100')
    expect(opts.method).toBeUndefined()
    expect(result.triage[0]!.vex_eligible).toBe(true)
  })

  it('creates and updates finding triage decisions', async () => {
    const created = {
      id: 'triage-1',
      vulnerability_id: 'CVE-2026-0101',
      package: 'requests',
      server_name: '',
      queue_state: 'assigned',
      decision: 'under_investigation',
      decision_reason: 'needs review',
      assignee: '',
      created_by: 'alice',
      created_at: '2026-05-29T00:00:00Z',
      reviewed_at: '',
      expires_at: '',
      tenant_id: 'tenant-alpha',
      vex_eligible: false,
    }
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({
        ok: true,
        status: 201,
        statusText: 'Created',
        json: () => Promise.resolve(created),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        statusText: 'OK',
        json: () => Promise.resolve({
          ...created,
          queue_state: 'decided',
          decision: 'affected',
          reviewed_at: '2026-05-29T00:01:00Z',
        }),
      })
    global.fetch = fetchMock

    const result = await api.createFindingTriage({
      vulnerability_id: 'CVE-2026-0101',
      package: 'requests',
      decision: 'under_investigation',
    })
    const updated = await api.updateFindingTriageDecision('triage-1', {
      decision: 'affected',
      decision_reason: 'reachable package',
    })

    expect(result.id).toBe('triage-1')
    expect(updated.decision).toBe('affected')
    const [createUrl, createOpts] = fetchMock.mock.calls[0]!
    expect(createUrl).toContain('/v1/findings/triage')
    expect(createOpts.method).toBe('POST')
    expect(JSON.parse(createOpts.body as string).decision).toBe('under_investigation')
    const [updateUrl, updateOpts] = fetchMock.mock.calls[1]!
    expect(updateUrl).toContain('/v1/findings/triage/triage-1/decision')
    expect(updateOpts.method).toBe('PUT')
    expect(JSON.parse(updateOpts.body as string).decision).toBe('affected')
  })

  it('exports signed OpenVEX triage evidence', async () => {
    global.fetch = mockFetch({
      schema_version: 'findings.triage.vex.v1',
      tenant_id: 'tenant-alpha',
      count: 1,
      format: 'openvex',
      vex: { statements: [{ status: 'not_affected' }] },
      signature: { algorithm: 'HMAC-SHA256', signature_hex: 'abc123', key_id: 'audit-hmac' },
    })

    const result = await api.exportFindingTriageVex()

    expect(global.fetch).toHaveBeenCalledOnce()
    const [url] = (global.fetch as ReturnType<typeof vi.fn>).mock.calls[0]!
    expect(url).toContain('/v1/findings/triage/vex')
    expect(result.count).toBe(1)
    expect(result.signature.signature_hex).toBe('abc123')
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
