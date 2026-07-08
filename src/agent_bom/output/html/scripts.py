"""Embedded JavaScript layers and offline-asset post-processing."""
from __future__ import annotations

_EXTERNAL_SCRIPT_TAGS = (
    '  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.2/dist/chart.umd.min.js"></script>\n',
    '  <script src="https://unpkg.com/cytoscape@3.30.2/dist/cytoscape.min.js"></script>\n',
    '  <script src="https://unpkg.com/dagre@0.8.5/dist/dagre.min.js"></script>\n',
    '  <script src="https://unpkg.com/cytoscape-dagre@2.5.0/cytoscape-dagre.js"></script>\n',
    '  <script src="https://unpkg.com/cytoscape-popper@2.0.0/cytoscape-popper.js"></script>\n',
)


SCALE_REPORT_SCRIPT = f"""<script>
// agent-bom scale-report: tabs + client-side pagination. Kept in a standalone
// script (distinct opening so offline mode does not strip it) and independent of
// the CDN chart/graph libs, so a large report stays tabbed and paginated even
// when opened offline or from an email attachment.
(function scaleReport() {{
  window.PAGINATORS = window.PAGINATORS || {{}};

  function makePaginator(tableId, filterFn) {{
    var table = document.getElementById(tableId);
    if (!table) return null;
    var tbody = table.querySelector('tbody');
    var bar = document.querySelector('.pager[data-pager="' + tableId + '"]');
    var allRows = Array.prototype.slice.call(tbody.querySelectorAll('tr'));
    var pageSize = bar ? (parseInt(bar.getAttribute('data-page-size'), 10) || 50) : 50;
    var page = 1;
    var matched = allRows;
    var infoEl = bar ? bar.querySelector('.pager-info') : null;
    function render() {{
      var total = matched.length;
      var pages = Math.max(1, Math.ceil(total / pageSize));
      if (page > pages) page = pages;
      if (page < 1) page = 1;
      var start = (page - 1) * pageSize;
      var end = start + pageSize;
      allRows.forEach(function(r) {{ r.classList.add('pg-hidden'); }});
      matched.slice(start, end).forEach(function(r) {{ r.classList.remove('pg-hidden'); }});
      if (bar) {{
        if (infoEl) infoEl.innerHTML = total ? (start + 1) + '&ndash;' + Math.min(end, total) + ' of ' + total : '0 of 0';
        var f = bar.querySelector('[data-act="first"]'), pv = bar.querySelector('[data-act="prev"]'),
            nx = bar.querySelector('[data-act="next"]'), ls = bar.querySelector('[data-act="last"]');
        if (f) f.disabled = page <= 1;
        if (pv) pv.disabled = page <= 1;
        if (nx) nx.disabled = page >= pages;
        if (ls) ls.disabled = page >= pages;
        bar.style.display = pages > 1 ? '' : 'none';
      }}
    }}
    function apply() {{ matched = filterFn ? allRows.filter(filterFn) : allRows; page = 1; render(); }}
    function resort() {{ allRows = Array.prototype.slice.call(tbody.querySelectorAll('tr')); apply(); }}
    if (bar) {{
      bar.addEventListener('click', function(e) {{
        var act = e.target.getAttribute && e.target.getAttribute('data-act');
        if (!act) return;
        var pages = Math.max(1, Math.ceil(matched.length / pageSize));
        if (act === 'first') page = 1;
        else if (act === 'prev') page = Math.max(1, page - 1);
        else if (act === 'next') page = Math.min(pages, page + 1);
        else if (act === 'last') page = pages;
        render();
      }});
      var sizeSel = bar.querySelector('.pager-size');
      if (sizeSel) sizeSel.addEventListener('change', function() {{ pageSize = parseInt(this.value, 10) || 50; page = 1; render(); }});
    }}
    var api = {{ apply: apply, resort: resort, render: render }};
    window.PAGINATORS[tableId] = api;
    apply();
    return api;
  }}

  // Vulnerability table filter (drives its paginator).
  function vulnRowMatch(row) {{
    var checkedSevs = Array.prototype.slice.call(document.querySelectorAll('.vuln-sev-filter:checked')).map(function(c) {{ return c.value; }});
    var kevOnly = document.getElementById('kevToggle') && document.getElementById('kevToggle').checked;
    var q = ((document.getElementById('vulnSearch') || {{}}).value || '').toLowerCase();
    var sev = row.getAttribute('data-severity') || '';
    if (checkedSevs.indexOf(sev) === -1) return false;
    if (kevOnly && row.getAttribute('data-kev') !== '1') return false;
    if (q && row.textContent.toLowerCase().indexOf(q) === -1) return false;
    return true;
  }}
  function filterVulnTable() {{ if (window.PAGINATORS.vulnTable) window.PAGINATORS.vulnTable.apply(); }}
  makePaginator('vulnTable', vulnRowMatch);
  document.querySelectorAll('.vuln-sev-filter').forEach(function(cb) {{ cb.addEventListener('change', filterVulnTable); }});
  var kevToggle = document.getElementById('kevToggle');
  if (kevToggle) kevToggle.addEventListener('change', filterVulnTable);
  var vulnSearchInput = document.getElementById('vulnSearch');
  if (vulnSearchInput) vulnSearchInput.addEventListener('input', filterVulnTable);

  // Unified policy/security finding filter (drives its paginator).
  function policyRowMatch(row) {{
    var checkedSevs = Array.prototype.slice.call(document.querySelectorAll('.policy-sev-filter:checked')).map(function(c) {{ return c.value; }});
    var typeFilter = (document.getElementById('policyTypeFilter') || {{}}).value || '';
    var assetFilter = (document.getElementById('policyAssetFilter') || {{}}).value || '';
    var q = ((document.getElementById('policySearch') || {{}}).value || '').toLowerCase();
    var sev = row.getAttribute('data-severity') || '';
    if (checkedSevs.indexOf(sev) === -1) return false;
    if (typeFilter && (row.getAttribute('data-type') || '') !== typeFilter) return false;
    if (assetFilter && (row.getAttribute('data-asset-type') || '') !== assetFilter) return false;
    if (q && row.textContent.toLowerCase().indexOf(q) === -1) return false;
    return true;
  }}
  function filterPolicyFindingsTable() {{
    if (window.PAGINATORS.policyFindingsTable) window.PAGINATORS.policyFindingsTable.apply();
    var count = document.getElementById('policyVisibleCount');
    var table = document.getElementById('policyFindingsTable');
    if (count && table) {{
      var all = table.querySelectorAll('tbody tr');
      var vis = Array.prototype.slice.call(all).filter(policyRowMatch).length;
      count.textContent = vis + ' of ' + all.length + ' shown';
    }}
  }}
  makePaginator('policyFindingsTable', policyRowMatch);
  document.querySelectorAll('.policy-sev-filter').forEach(function(cb) {{ cb.addEventListener('change', filterPolicyFindingsTable); }});
  var policyTypeFilter = document.getElementById('policyTypeFilter');
  if (policyTypeFilter) policyTypeFilter.addEventListener('change', filterPolicyFindingsTable);
  var policyAssetFilter = document.getElementById('policyAssetFilter');
  if (policyAssetFilter) policyAssetFilter.addEventListener('change', filterPolicyFindingsTable);
  var policySearchInput = document.getElementById('policySearch');
  if (policySearchInput) policySearchInput.addEventListener('input', filterPolicyFindingsTable);
  filterPolicyFindingsTable();

  // ── Tabbed navigation ─────────────────────────────────────────────────────
  var tabBar = document.querySelector('.tab-bar');
  function tabForSection(id) {{
    var sec = document.getElementById(id);
    return sec ? sec.getAttribute('data-tab') : null;
  }}
  function activateTab(key) {{
    if (!key) return;
    document.querySelectorAll('.tab-btn').forEach(function(b) {{ b.classList.toggle('active', b.getAttribute('data-tab') === key); }});
    document.querySelectorAll('.container>section[data-tab]').forEach(function(s) {{ s.classList.toggle('tab-active', s.getAttribute('data-tab') === key); }});
    // Tables re-render because a hidden tab had zero layout width.
    Object.keys(window.PAGINATORS).forEach(function(id) {{ window.PAGINATORS[id].render(); }});
  }}
  if (tabBar) {{
    document.body.classList.add('js-tabs');
    tabBar.querySelectorAll('.tab-btn').forEach(function(b) {{
      b.addEventListener('click', function() {{ activateTab(b.getAttribute('data-tab')); window.scrollTo(0, 0); }});
    }});
    var firstTab = tabBar.querySelector('.tab-btn');
    if (firstTab) activateTab(firstTab.getAttribute('data-tab'));
  }}

  // Sidebar / in-page anchors reveal the target's tab, then scroll to it.
  document.querySelectorAll('a[href^="#"]').forEach(function(a) {{
    a.addEventListener('click', function(e) {{
      var id = a.getAttribute('href').slice(1);
      if (!id) return;
      var el = document.getElementById(id);
      var key = tabForSection(id);
      if (tabBar && key) {{
        e.preventDefault();
        activateTab(key);
        if (el) setTimeout(function() {{ el.scrollIntoView({{ behavior: 'smooth', block: 'start' }}); }}, 30);
      }}
    }});
  }});
}})();
</script>"""


def render_graph_script(
    chart_data_json: str, elements_json: str, attack_flow_json: str
) -> str:
    """Return the Chart.js + Cytoscape graph/interaction <script> block."""
    return f"""<script>
(function() {{
  // Injected data
  var CHART_DATA = {chart_data_json};
  var GRAPH_ELEMENTS = {elements_json};
  var ATTACK_FLOW = {attack_flow_json};

  // Chart.js: Severity donut
  var sevCtx = document.getElementById('sevChart');
  if (sevCtx && CHART_DATA.sev.data.some(function(v){{ return v > 0; }})) {{
    new Chart(sevCtx, {{
      type: 'doughnut',
      data: {{
        labels: CHART_DATA.sev.labels,
        datasets: [{{
          data: CHART_DATA.sev.data,
          backgroundColor: CHART_DATA.sev.colors,
          borderColor: '#0b1120',
          borderWidth: 3,
          hoverOffset: 8,
        }}],
      }},
      options: {{
        responsive: true,
        cutout: '68%',
        plugins: {{
          legend: {{
            position: 'bottom',
            labels: {{
              color: '#94a3b8',
              font: {{ size: 11 }},
              boxWidth: 12,
              padding: 14,
            }},
          }},
          tooltip: {{
            backgroundColor: '#0f172a',
            borderColor: '#334155',
            borderWidth: 1,
            titleColor: '#e2e8f0',
            bodyColor: '#94a3b8',
            cornerRadius: 8,
            padding: 10,
            callbacks: {{
              label: function(ctx) {{
                return ' ' + ctx.label + ': ' + ctx.parsed;
              }},
            }},
          }},
        }},
      }},
    }});
  }} else if (sevCtx) {{
    var p = document.createElement('p');
    p.style.cssText = 'color:#4ade80;text-align:center;padding:50px 0;font-size:.88rem';
    p.innerHTML = '&#x2705; No vulnerabilities';
    sevCtx.parentNode.replaceChild(p, sevCtx);
  }}

  // Chart.js: Blast radius bar
  var blastCtx = document.getElementById('blastChart');
  if (blastCtx && CHART_DATA.blast.labels.length > 0) {{
    new Chart(blastCtx, {{
      type: 'bar',
      data: {{
        labels: CHART_DATA.blast.labels,
        datasets: [{{
          label: 'Blast Score',
          data: CHART_DATA.blast.scores,
          backgroundColor: CHART_DATA.blast.colors,
          borderRadius: 6,
          borderSkipped: false,
        }}],
      }},
      options: {{
        indexAxis: 'y',
        responsive: true,
        scales: {{
          x: {{
            min: 0, max: 10,
            grid: {{ color: '#1e293b' }},
            ticks: {{ color: '#64748b', font: {{ size: 11 }} }},
          }},
          y: {{
            grid: {{ display: false }},
            ticks: {{ color: '#94a3b8', font: {{ size: 11 }} }},
          }},
        }},
        plugins: {{
          legend: {{ display: false }},
          tooltip: {{
            backgroundColor: '#0f172a',
            borderColor: '#334155',
            borderWidth: 1,
            titleColor: '#e2e8f0',
            bodyColor: '#94a3b8',
            cornerRadius: 8,
            callbacks: {{
              label: function(ctx) {{
                return ' Score: ' + ctx.parsed.x.toFixed(2);
              }},
            }},
          }},
        }},
      }},
    }});
  }} else if (blastCtx) {{
    var p2 = document.createElement('p');
    p2.style.cssText = 'color:#4ade80;text-align:center;padding:50px 0;font-size:.88rem';
    p2.innerHTML = '&#x2705; No blast radius data';
    blastCtx.parentNode.replaceChild(p2, blastCtx);
  }}

  // Cytoscape: Supply chain graph with dagre hierarchical layout
  var cyContainer = document.getElementById('cy');
  if (cyContainer && GRAPH_ELEMENTS.length > 0) {{
    var cy = cytoscape({{
      container: cyContainer,
      elements: GRAPH_ELEMENTS,
      style: [
        {{
          selector: 'node[type="provider"]',
          style: {{
            'background-color': '#1e1b4b',
            'border-color': '#818cf8',
            'border-width': 3,
            'label': 'data(label)',
            'color': '#c7d2fe',
            'font-size': '13px',
            'font-weight': '700',
            'text-valign': 'center',
            'text-halign': 'center',
            'width': 140,
            'height': 44,
            'shape': 'round-rectangle',
            'text-wrap': 'wrap',
            'text-max-width': '125px',
          }},
        }},
        {{
          selector: 'node[type="agent"]',
          style: {{
            'background-color': '#1e3a8a',
            'border-color': '#3b82f6',
            'border-width': 2,
            'label': 'data(label)',
            'color': '#bfdbfe',
            'font-size': '12px',
            'font-weight': '700',
            'text-valign': 'center',
            'text-halign': 'center',
            'width': 120,
            'height': 40,
            'shape': 'round-rectangle',
            'text-wrap': 'wrap',
            'text-max-width': '105px',
          }},
        }},
        {{
          selector: 'node[type="server_clean"]',
          style: {{
            'background-color': '#052e16',
            'border-color': '#10b981',
            'border-width': 2,
            'label': 'data(label)',
            'color': '#6ee7b7',
            'font-size': '10px',
            'text-valign': 'center',
            'text-halign': 'center',
            'width': 120,
            'height': 36,
            'shape': 'round-rectangle',
            'text-wrap': 'wrap',
            'text-max-width': '110px',
          }},
        }},
        {{
          selector: 'node[type="server_cred"]',
          style: {{
            'background-color': '#431407',
            'border-color': '#f59e0b',
            'border-width': 2,
            'label': 'data(label)',
            'color': '#fde68a',
            'font-size': '10px',
            'text-valign': 'center',
            'text-halign': 'center',
            'width': 120,
            'height': 36,
            'shape': 'round-rectangle',
            'text-wrap': 'wrap',
            'text-max-width': '110px',
          }},
        }},
        {{
          selector: 'node[type="server_vuln"]',
          style: {{
            'background-color': '#450a0a',
            'border-color': '#ef4444',
            'border-width': 2.5,
            'label': 'data(label)',
            'color': '#fca5a5',
            'font-size': '10px',
            'text-valign': 'center',
            'text-halign': 'center',
            'width': 120,
            'height': 36,
            'shape': 'round-rectangle',
            'text-wrap': 'wrap',
            'text-max-width': '110px',
          }},
        }},
        {{
          selector: 'node[type="pkg_vuln"]',
          style: {{
            'background-color': '#7f1d1d',
            'border-color': '#dc2626',
            'border-width': 2,
            'label': 'data(label)',
            'color': '#fca5a5',
            'font-size': '9px',
            'font-weight': '700',
            'text-valign': 'center',
            'text-halign': 'center',
            'width': 130,
            'height': 38,
            'shape': 'round-rectangle',
            'text-wrap': 'wrap',
            'text-max-width': '120px',
          }},
        }},
        {{
          selector: 'node[type="cve"][severity="critical"], node[type^="cve_critical"]',
          style: {{
            'background-color': '#991b1b',
            'border-color': '#f87171',
            'border-width': 2,
            'label': 'data(label)',
            'color': '#fecaca',
            'font-size': '8px',
            'text-valign': 'center',
            'text-halign': 'center',
            'width': 110,
            'height': 30,
            'shape': 'diamond',
            'underlay-color': '#ef4444',
            'underlay-padding': '6px',
            'underlay-opacity': 0.15,
            'underlay-shape': 'ellipse',
          }},
        }},
        {{
          selector: 'node[type="cve"][severity="high"], node[type^="cve_high"]',
          style: {{
            'background-color': '#9a3412',
            'border-color': '#fb923c',
            'border-width': 2,
            'label': 'data(label)',
            'color': '#fed7aa',
            'font-size': '8px',
            'text-valign': 'center',
            'text-halign': 'center',
            'width': 100,
            'height': 28,
            'shape': 'diamond',
            'underlay-color': '#fb923c',
            'underlay-padding': '4px',
            'underlay-opacity': 0.1,
            'underlay-shape': 'ellipse',
          }},
        }},
        {{
          selector: 'node[type="cve"][severity="medium"], node[type="cve"][severity="low"], node[type="cve"][severity="none"], node[type^="cve_medium"], node[type^="cve_low"], node[type^="cve_none"]',
          style: {{
            'background-color': '#854d0e',
            'border-color': '#fbbf24',
            'border-width': 1.5,
            'label': 'data(label)',
            'color': '#fef08a',
            'font-size': '8px',
            'text-valign': 'center',
            'text-halign': 'center',
            'width': 90,
            'height': 26,
            'shape': 'diamond',
          }},
        }},
        {{
          selector: 'edge',
          style: {{
            'width': 1.8,
            'line-color': '#334155',
            'target-arrow-color': '#475569',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'arrow-scale': 0.8,
          }},
        }},
        {{
          selector: 'edge[type="hosts"]',
          style: {{
            'line-color': '#818cf850',
            'target-arrow-color': '#818cf880',
            'line-style': 'dashed',
            'line-dash-pattern': [6, 3],
          }},
        }},
        {{
          selector: 'edge[type="affects"]',
          style: {{
            'line-color': '#dc262650',
            'target-arrow-color': '#dc262680',
          }},
        }},
        {{
          selector: '.highlighted',
          style: {{
            'border-width': 4,
            'border-color': '#f1f5f9',
            'z-index': 999,
          }},
        }},
        {{
          selector: '.faded',
          style: {{ 'opacity': 0.08 }},
        }},
      ],
      layout: {{
        name: 'dagre',
        rankDir: 'LR',
        nodeSep: 50,
        rankSep: 80,
        edgeSep: 15,
        padding: 30,
        animate: false,
        fit: true,
      }},
      minZoom: 0.15,
      maxZoom: 4,
      wheelSensitivity: 0.3,
      autoungrabify: false,
    }});
    cy.ready(function() {{ cy.fit(cy.elements(), 40); }});

    // Tooltip
    var tip = document.getElementById('tip');
    cy.on('mouseover', 'node', function(e) {{
      var t = e.target.data('tip');
      if (t) {{ tip.textContent = t; tip.style.display = 'block'; }}
    }});
    cy.on('mousemove', function(e) {{
      if (tip.style.display === 'block') {{
        tip.style.left = (e.originalEvent.clientX + 14) + 'px';
        tip.style.top  = (e.originalEvent.clientY + 14) + 'px';
      }}
    }});
    cy.on('mouseout', 'node', function() {{ tip.style.display = 'none'; }});

    // Click to highlight + sidebar
    var sidebar = document.getElementById('nodeDetailSidebar');
    var sidebarCloseBtn = document.getElementById('sidebarClose');

    function escHtml(value) {{
      return String(value == null ? '' : value).replace(/[&<>"']/g, function(ch) {{
        return {{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[ch];
      }});
    }}

    function urlPart(value) {{
      return encodeURIComponent(String(value == null ? '' : value));
    }}

    function showSidebar(node) {{
      var d = node.data();
      var t = d.type || '';
      var isCveNode = t === 'cve' || t.indexOf('cve_')===0;
      var typeLabels = {{'provider':'Provider','agent':'Agent','server_clean':'MCP Server','server_cred':'MCP Server','server_vuln':'MCP Server','pkg_vuln':'Package','cve':'Vulnerability'}};
      var typeLabel = typeLabels[t] || (isCveNode ? 'Vulnerability' : t);
      var typeColors = {{'provider':'#818cf8','agent':'#3b82f6','server_clean':'#10b981','server_cred':'#f59e0b','server_vuln':'#ef4444','pkg_vuln':'#dc2626'}};
      var badgeColor = typeColors[t] || (isCveNode ? '#f87171' : '#64748b');

      document.getElementById('sidebarNodeType').textContent = typeLabel;
      document.getElementById('sidebarNodeType').style.borderColor = badgeColor;
      document.getElementById('sidebarNodeType').style.color = badgeColor;
      document.getElementById('sidebarNodeName').textContent = d.label || d.id;

      ['sidebarMeta','sidebarConnected','sidebarCredentials','sidebarCves','sidebarRemediation'].forEach(function(id) {{
        document.getElementById(id).innerHTML = '';
      }});

      // Connected nodes
      var neighbors = node.neighborhood('node');
      if (neighbors.length > 0) {{
        var h = '<div class="sidebar-label">Connected (' + neighbors.length + ')</div><ul class="sidebar-list">';
        neighbors.forEach(function(n) {{
          var nt = n.data('type') || '';
          var icon = nt === 'agent' ? '&#x1f916;' : nt.indexOf('server')===0 ? '&#x2699;' : nt === 'pkg_vuln' ? '&#x1f4e6;' : (nt === 'cve' || nt.indexOf('cve_')===0) ? '&#x1f41b;' : '&#x25cf;';
          h += '<li>' + icon + ' ' + escHtml((n.data('label') || n.data('id')).replace('\\n',' ')) + '</li>';
        }});
        h += '</ul>';
        document.getElementById('sidebarConnected').innerHTML = h;
      }}

      // Agent
      if (t === 'agent') {{
        var meta = '';
        if (d.agentType) meta += 'Type: ' + d.agentType + '\\n';
        if (d.source) meta += 'Source: ' + d.source + '\\n';
        if (d.configPath) meta += 'Config: ' + d.configPath;
        document.getElementById('sidebarMeta').textContent = meta;
        var s = '<div class="sidebar-label">Statistics</div><ul class="sidebar-list">';
        s += '<li>Servers: ' + (d.serverCount || 0) + '</li>';
        s += '<li>Packages: ' + (d.packageCount || 0) + '</li>';
        if (d.vulnCount) s += '<li style="color:#f87171">Vulnerabilities: ' + d.vulnCount + '</li>';
        s += '</ul>';
        document.getElementById('sidebarRemediation').innerHTML = s;
      }}

      // Server
      if (t.indexOf('server_')===0) {{
        if (d.command) document.getElementById('sidebarMeta').textContent = d.command;
        var creds = []; try {{ creds = JSON.parse(d.credentials || '[]'); }} catch(e) {{}}
        if (creds.length > 0) {{
          var ch = '<div class="sidebar-label">Credentials (' + creds.length + ')</div><ul class="sidebar-list">';
          creds.forEach(function(c) {{ ch += '<li>&#x1f511; <span class="sidebar-cred">' + escHtml(c) + '</span></li>'; }});
          ch += '</ul>';
          document.getElementById('sidebarCredentials').innerHTML = ch;
        }}
        var tools = []; try {{ tools = JSON.parse(d.toolNames || '[]'); }} catch(e) {{}}
        if (tools.length > 0) {{
          var th = '<div class="sidebar-label">MCP Tools (' + tools.length + ')</div><ul class="sidebar-list">';
          tools.forEach(function(tl) {{ th += '<li>&#x1f527; ' + escHtml(tl) + '</li>'; }});
          th += '</ul>';
          document.getElementById('sidebarRemediation').innerHTML = th;
        }}
        var ph = '<div class="sidebar-label">Packages</div><ul class="sidebar-list">';
        ph += '<li>Total: ' + (d.packageCount || 0) + '</li>';
        if (d.vulnCount) ph += '<li style="color:#f87171">Vulnerable: ' + d.vulnCount + '</li>';
        ph += '</ul>';
        document.getElementById('sidebarCves').innerHTML = ph;
      }}

      // Package
      if (t === 'pkg_vuln') {{
        document.getElementById('sidebarMeta').textContent = (d.ecosystem || '') + ' \\u00b7 ' + (d.version || '');
        var vids = []; try {{ vids = JSON.parse(d.vulnIds || '[]'); }} catch(e) {{}}
        if (vids.length > 0) {{
          var vh = '<div class="sidebar-label">CVEs (' + vids.length + ')</div><ul class="sidebar-list">';
          vids.forEach(function(vid) {{
            vh += '<li><a class="sidebar-link" href="https://osv.dev/vulnerability/' + urlPart(vid) + '" target="_blank" rel="noopener noreferrer">' + escHtml(vid) + ' &#x2197;</a></li>';
          }});
          vh += '</ul>';
          document.getElementById('sidebarCves').innerHTML = vh;
        }}
      }}

      // CVE
      if (isCveNode) {{
        var sev = d.severity || t.replace('cve_', '');
        var mp = [];
        if (sev) mp.push('Severity: ' + sev.toUpperCase());
        if (d.cvssScore) mp.push('CVSS: ' + d.cvssScore);
        document.getElementById('sidebarMeta').textContent = mp.join(' \\u00b7 ');
        if (d.summary) {{
          document.getElementById('sidebarCredentials').innerHTML = '<div class="sidebar-label">Summary</div><p style="font-size:.8rem;color:#cbd5e1;margin:0">' + escHtml(d.summary) + '</p>';
        }}
        var rh = '<div class="sidebar-label">Remediation</div><ul class="sidebar-list">';
        if (d.fixVersion) {{
          rh += '<li style="color:#4ade80">&#x2705; Fix: upgrade to <code>' + escHtml(d.fixVersion) + '</code></li>';
        }} else {{
          rh += '<li style="color:#f59e0b">&#x26a0; No fix available</li>';
        }}
        var lbl = d.label || '';
        rh += '<li><a class="sidebar-link" href="https://osv.dev/vulnerability/' + urlPart(lbl) + '" target="_blank" rel="noopener noreferrer">View on OSV &#x2197;</a></li>';
        rh += '<li><a class="sidebar-link" href="https://nvd.nist.gov/vuln/detail/' + urlPart(lbl) + '" target="_blank" rel="noopener noreferrer">View on NVD &#x2197;</a></li>';
        rh += '</ul>';
        document.getElementById('sidebarRemediation').innerHTML = rh;
      }}

      sidebar.classList.add('open');
      sidebar.style.display = 'block';
    }}

    function closeSidebar() {{
      sidebar.classList.remove('open');
      setTimeout(function() {{ sidebar.style.display = 'none'; }}, 250);
    }}

    sidebarCloseBtn.addEventListener('click', closeSidebar);

    cy.on('tap', 'node', function(e) {{
      cy.elements().removeClass('faded highlighted');
      var hood = e.target.closedNeighborhood();
      cy.elements().not(hood).addClass('faded');
      e.target.addClass('highlighted');
      showSidebar(e.target);
    }});
    cy.on('tap', function(e) {{
      if (e.target === cy) {{
        cy.elements().removeClass('faded highlighted');
        closeSidebar();
      }}
    }});

    // Graph controls
    document.getElementById('zoomIn').addEventListener('click', function() {{
      cy.zoom({{ level: cy.zoom() * 1.3, renderedPosition: {{ x: cy.width() / 2, y: cy.height() / 2 }} }});
    }});
    document.getElementById('zoomOut').addEventListener('click', function() {{
      cy.zoom({{ level: cy.zoom() / 1.3, renderedPosition: {{ x: cy.width() / 2, y: cy.height() / 2 }} }});
    }});
    document.getElementById('fitBtn').addEventListener('click', function() {{
      cy.fit(cy.elements(), 40);
    }});
    document.getElementById('fullscreenBtn').addEventListener('click', function() {{
      var gc = document.querySelector('.graph-container');
      if (!document.fullscreenElement) {{
        gc.requestFullscreen().then(function() {{
          setTimeout(function() {{ cy.resize(); cy.fit(cy.elements(), 50); }}, 100);
        }}).catch(function() {{}});
      }} else {{
        document.exitFullscreen();
      }}
    }});
    document.addEventListener('fullscreenchange', function() {{
      if (!document.fullscreenElement) {{
        setTimeout(function() {{ cy.resize(); cy.fit(cy.elements(), 40); }}, 100);
      }}
    }});
    // Graph severity filter
    document.querySelectorAll('.graph-sev-filter').forEach(function(cb) {{
      cb.addEventListener('change', function() {{
        var checked = Array.from(document.querySelectorAll('.graph-sev-filter:checked')).map(function(c) {{ return c.value; }});
        cy.nodes().forEach(function(n) {{
          var t = n.data('type') || '';
          if (t === 'cve' || t.startsWith('cve_')) {{
            var sev = n.data('severity') || t.replace('cve_', '');
            if (checked.indexOf(sev) === -1) {{
              n.style('display', 'none');
              n.connectedEdges().style('display', 'none');
            }} else {{
              n.style('display', 'element');
              n.connectedEdges().style('display', 'element');
            }}
          }}
        }});
      }});
    }});

    // Graph search
    var graphSearchInput = document.getElementById('graphSearch');
    if (graphSearchInput) {{
      graphSearchInput.addEventListener('input', function() {{
        var q = this.value.toLowerCase();
        if (!q) {{
          cy.elements().removeClass('faded highlighted');
          return;
        }}
        cy.elements().removeClass('faded highlighted');
        var matched = cy.nodes().filter(function(n) {{
          return (n.data('label') || '').toLowerCase().indexOf(q) >= 0;
        }});
        if (matched.length > 0) {{
          var hood = matched.closedNeighborhood();
          cy.elements().not(hood).addClass('faded');
          matched.addClass('highlighted');
        }} else {{
          cy.elements().addClass('faded');
        }}
      }});
    }}

    // Context menu (right-click on nodes)
    var ctxMenu = document.createElement('div');
    ctxMenu.className = 'cy-ctx-menu';
    document.body.appendChild(ctxMenu);

    function hideCtxMenu() {{ ctxMenu.classList.remove('show'); }}
    document.addEventListener('click', hideCtxMenu);
    document.addEventListener('scroll', hideCtxMenu);

    cy.on('cxttap', 'node', function(e) {{
      e.originalEvent.preventDefault();
      var node = e.target;
      var d = node.data();
      var t = d.type || '';
      var items = [];

      // Focus neighborhood
      items.push({{icon:'&#x1f50d;',label:'Focus neighborhood',action:function(){{
        cy.elements().removeClass('faded highlighted');
        var hood = node.closedNeighborhood();
        cy.elements().not(hood).addClass('faded');
        node.addClass('highlighted');
        showSidebar(node);
      }}}});
      // Fit to node
      items.push({{icon:'&#x1f4cd;',label:'Zoom to node',action:function(){{
        cy.animate({{ fit: {{ eles: node.closedNeighborhood(), padding: 80 }}, duration: 400 }});
      }}}});
      // Highlight path to root
      items.push({{icon:'&#x2b06;',label:'Trace to root',action:function(){{
        cy.elements().removeClass('faded highlighted');
        var path = node.predecessors().union(node);
        cy.elements().not(path).addClass('faded');
        path.nodes().addClass('highlighted');
      }}}});
      // Highlight downstream
      items.push({{icon:'&#x2b07;',label:'Show downstream impact',action:function(){{
        cy.elements().removeClass('faded highlighted');
        var downstream = node.successors().union(node);
        cy.elements().not(downstream).addClass('faded');
        downstream.nodes().addClass('highlighted');
      }}}});

      // Vulnerability node: open in OSV
      if (t === 'cve' || t.indexOf('cve_')===0) {{
        var vid = d.label || '';
        items.push({{sep:true}});
        items.push({{icon:'&#x1f517;',label:'Open in OSV',action:function(){{
          window.open('https://osv.dev/vulnerability/'+vid, '_blank');
        }}}});
        items.push({{icon:'&#x1f517;',label:'Open in NVD',action:function(){{
          window.open('https://nvd.nist.gov/vuln/detail/'+vid, '_blank');
        }}}});
      }}

      // Build menu HTML
      ctxMenu.innerHTML = '';
      items.forEach(function(item) {{
        if (item.sep) {{
          var sep = document.createElement('div');
          sep.className = 'cy-ctx-sep';
          ctxMenu.appendChild(sep);
        }} else {{
          var el = document.createElement('div');
          el.className = 'cy-ctx-item';
          el.innerHTML = '<span>'+item.icon+'</span> '+item.label;
          el.addEventListener('click', function(ev) {{
            ev.stopPropagation();
            hideCtxMenu();
            item.action();
          }});
          ctxMenu.appendChild(el);
        }}
      }});

      var cx = e.originalEvent.clientX, cy2 = e.originalEvent.clientY;
      ctxMenu.style.left = cx + 'px';
      ctxMenu.style.top = cy2 + 'px';
      ctxMenu.classList.add('show');
    }});

    // Minimap — render a small overview of the full graph
    var minimapEl = document.createElement('div');
    minimapEl.className = 'cy-minimap';
    cyContainer.parentNode.appendChild(minimapEl);
    var mmCanvas = document.createElement('canvas');
    mmCanvas.width = 180; mmCanvas.height = 130;
    minimapEl.appendChild(mmCanvas);

    function drawMinimap() {{
      var ctx2d = mmCanvas.getContext('2d');
      ctx2d.clearRect(0, 0, 180, 130);
      var bb = cy.elements().boundingBox();
      if (!bb || bb.w === 0) return;
      var scaleX = 170 / bb.w, scaleY = 120 / bb.h;
      var sc = Math.min(scaleX, scaleY);
      var offX = (180 - bb.w * sc) / 2 - bb.x1 * sc;
      var offY = (130 - bb.h * sc) / 2 - bb.y1 * sc;

      // Draw edges
      ctx2d.strokeStyle = '#334155'; ctx2d.lineWidth = 0.5;
      cy.edges().forEach(function(edge) {{
        var sp = edge.sourceEndpoint(), tp = edge.targetEndpoint();
        ctx2d.beginPath();
        ctx2d.moveTo(sp.x * sc + offX, sp.y * sc + offY);
        ctx2d.lineTo(tp.x * sc + offX, tp.y * sc + offY);
        ctx2d.stroke();
      }});

      // Draw nodes
      cy.nodes().forEach(function(n) {{
        var pos = n.position(); var t = n.data('type') || '';
        var colors = {{'provider':'#818cf8','agent':'#3b82f6','server_clean':'#10b981','server_cred':'#f59e0b','server_vuln':'#ef4444','pkg_vuln':'#dc2626'}};
        ctx2d.fillStyle = colors[t] || (t === 'cve' || t.indexOf('cve_')===0 ? '#f87171' : '#64748b');
        var nx = pos.x * sc + offX, ny = pos.y * sc + offY;
        ctx2d.beginPath();
        if (t === 'cve' || t.indexOf('cve_')===0) {{
          // Diamond
          ctx2d.moveTo(nx, ny - 4); ctx2d.lineTo(nx + 5, ny); ctx2d.lineTo(nx, ny + 4); ctx2d.lineTo(nx - 5, ny);
        }} else {{
          ctx2d.arc(nx, ny, 3, 0, Math.PI * 2);
        }}
        ctx2d.fill();
      }});

      // Viewport rectangle
      var ext = cy.extent();
      ctx2d.strokeStyle = '#60a5fa'; ctx2d.lineWidth = 1.5;
      ctx2d.strokeRect(ext.x1 * sc + offX, ext.y1 * sc + offY, ext.w * sc, ext.h * sc);
    }}

    cy.on('render viewport', drawMinimap);
    setTimeout(drawMinimap, 500);

    // Click minimap to pan
    mmCanvas.addEventListener('click', function(e) {{
      var rect = mmCanvas.getBoundingClientRect();
      var mx = e.clientX - rect.left, my = e.clientY - rect.top;
      var bb = cy.elements().boundingBox();
      if (!bb || bb.w === 0) return;
      var scaleX = 170 / bb.w, scaleY = 120 / bb.h;
      var sc = Math.min(scaleX, scaleY);
      var offX = (180 - bb.w * sc) / 2 - bb.x1 * sc;
      var offY = (130 - bb.h * sc) / 2 - bb.y1 * sc;
      var targetX = (mx - offX) / sc, targetY = (my - offY) / sc;
      cy.animate({{ center: {{ x: targetX, y: targetY }}, duration: 300 }});
    }});

    // Node statistics overlay
    var nodeStats = document.createElement('div');
    nodeStats.style.cssText = 'position:absolute;bottom:12px;right:12px;background:rgba(15,23,42,.9);border:1px solid #334155;border-radius:8px;padding:8px 14px;font-size:.72rem;color:#64748b;z-index:10;backdrop-filter:blur(8px)';
    var nodeCounts = {{}};
    cy.nodes().forEach(function(n) {{
      var t = n.data('type') || 'other';
      if (t === 'cve' || t.indexOf('cve_')===0) t = 'cve';
      else if (t.indexOf('server_')===0) t = 'server';
      nodeCounts[t] = (nodeCounts[t] || 0) + 1;
    }});
    var statsHTML = [];
    if (nodeCounts.agent) statsHTML.push('<span style="color:#3b82f6">' + nodeCounts.agent + ' agents</span>');
    if (nodeCounts.server) statsHTML.push('<span style="color:#10b981">' + nodeCounts.server + ' servers</span>');
    if (nodeCounts.pkg_vuln) statsHTML.push('<span style="color:#dc2626">' + nodeCounts.pkg_vuln + ' packages</span>');
    if (nodeCounts.cve) statsHTML.push('<span style="color:#f87171">' + nodeCounts.cve + ' CVEs</span>');
    nodeStats.innerHTML = statsHTML.join(' &middot; ');
    cyContainer.parentNode.appendChild(nodeStats);

  }} else if (cyContainer) {{
    cyContainer.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;color:#4ade80;font-size:.9rem">&#x2705; No supply chain nodes to display</div>';
  }}

  // Findings-table pagination, filtering, and tabs live in the standalone
  // scale-report script (below) so they keep working even if the CDN chart /
  // graph libraries fail to load — the common case for an offline or emailed
  // report. Nothing table/tab related runs here.

  // Cytoscape: CVE Attack Flow graph
  var cyAtkContainer = document.getElementById('cyAttack');
  if (cyAtkContainer && ATTACK_FLOW.length > 0) {{
    var cyAtk = cytoscape({{
      container: cyAtkContainer,
      elements: ATTACK_FLOW,
      style: [
        {{
          selector: 'node[type="cve"], node[type^="cve_"]',
          style: {{
            'shape': 'diamond',
            'width': 120,
            'height': 34,
            'label': 'data(label)',
            'font-size': '9px',
            'font-weight': '700',
            'text-valign': 'center',
            'text-halign': 'center',
            'color': '#fecaca',
            'background-color': '#991b1b',
            'border-color': '#f87171',
            'border-width': 2.5,
          }},
        }},
        {{
          selector: 'node[type="cve"][severity="critical"], node[type="cve_critical"]',
          style: {{
            'background-color': '#7f1d1d',
            'border-color': '#ef4444',
            'border-width': 3,
            'width': 130,
            'height': 38,
            'underlay-color': '#ef4444',
            'underlay-padding': '6px',
            'underlay-opacity': 0.15,
            'underlay-shape': 'ellipse',
          }},
        }},
        {{
          selector: 'node[type="cve"][severity="high"], node[type="cve_high"]',
          style: {{
            'background-color': '#9a3412',
            'border-color': '#fb923c',
            'color': '#fed7aa',
            'underlay-color': '#fb923c',
            'underlay-padding': '4px',
            'underlay-opacity': 0.1,
            'underlay-shape': 'ellipse',
          }},
        }},
        {{
          selector: 'node[type="cve"][severity="medium"], node[type="cve"][severity="low"], node[type="cve"][severity="none"], node[type="cve_medium"], node[type="cve_low"], node[type="cve_none"]',
          style: {{
            'background-color': '#854d0e',
            'border-color': '#fbbf24',
            'border-width': 1.5,
            'color': '#fef08a',
            'width': 100,
            'height': 28,
          }},
        }},
        {{
          selector: 'node[type="pkg_vuln"]',
          style: {{
            'background-color': '#7f1d1d',
            'border-color': '#dc2626',
            'border-width': 2,
            'label': 'data(label)',
            'color': '#fca5a5',
            'font-size': '9px',
            'font-weight': '700',
            'text-valign': 'center',
            'text-halign': 'center',
            'width': 130,
            'height': 38,
            'shape': 'round-rectangle',
            'text-wrap': 'wrap',
            'text-max-width': '120px',
          }},
        }},
        {{
          selector: 'node[type="server"]',
          style: {{
            'background-color': '#1e293b',
            'border-color': '#475569',
            'border-width': 2,
            'label': 'data(label)',
            'color': '#cbd5e1',
            'font-size': '10px',
            'font-weight': '600',
            'text-valign': 'center',
            'text-halign': 'center',
            'width': 120,
            'height': 36,
            'shape': 'round-rectangle',
            'text-wrap': 'wrap',
            'text-max-width': '110px',
          }},
        }},
        {{
          selector: 'node[type="credential"]',
          style: {{
            'background-color': '#78350f',
            'border-color': '#fbbf24',
            'border-width': 2,
            'label': 'data(label)',
            'color': '#fde68a',
            'font-size': '9px',
            'font-weight': '700',
            'text-valign': 'center',
            'text-halign': 'center',
            'width': 100,
            'height': 32,
            'shape': 'hexagon',
          }},
        }},
        {{
          selector: 'node[type="tool"]',
          style: {{
            'background-color': '#312e81',
            'border-color': '#818cf8',
            'border-width': 2,
            'label': 'data(label)',
            'color': '#c7d2fe',
            'font-size': '9px',
            'text-valign': 'center',
            'text-halign': 'center',
            'width': 100,
            'height': 30,
            'shape': 'round-tag',
            'text-wrap': 'wrap',
            'text-max-width': '90px',
          }},
        }},
        {{
          selector: 'node[type="agent"]',
          style: {{
            'background-color': '#1e3a8a',
            'border-color': '#3b82f6',
            'border-width': 2,
            'label': 'data(label)',
            'color': '#bfdbfe',
            'font-size': '11px',
            'font-weight': '700',
            'text-valign': 'center',
            'text-halign': 'center',
            'width': 120,
            'height': 38,
            'shape': 'round-rectangle',
            'text-wrap': 'wrap',
            'text-max-width': '105px',
          }},
        }},
        {{
          selector: 'edge',
          style: {{
            'width': 1.8,
            'line-color': '#334155',
            'target-arrow-color': '#475569',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'arrow-scale': 0.8,
          }},
        }},
        {{
          selector: 'edge[type="exploits"]',
          style: {{
            'line-color': '#dc2626',
            'target-arrow-color': '#ef4444',
            'width': 2.5,
          }},
        }},
        {{
          selector: 'edge[type="runs_on"]',
          style: {{
            'line-color': '#475569',
            'target-arrow-color': '#64748b',
          }},
        }},
        {{
          selector: 'edge[type="exposes"]',
          style: {{
            'line-color': '#f59e0b',
            'target-arrow-color': '#fbbf24',
            'line-style': 'dashed',
            'line-dash-pattern': [6, 3],
            'width': 2,
          }},
        }},
        {{
          selector: 'edge[type="reaches"]',
          style: {{
            'line-color': '#818cf8',
            'target-arrow-color': '#a5b4fc',
            'line-style': 'dashed',
            'line-dash-pattern': [4, 4],
          }},
        }},
        {{
          selector: 'edge[type="compromises"]',
          style: {{
            'line-color': '#ef4444',
            'target-arrow-color': '#f87171',
            'line-style': 'dashed',
            'line-dash-pattern': [8, 4],
            'width': 2.5,
          }},
        }},
        {{
          selector: '.highlighted',
          style: {{
            'border-width': 4,
            'border-color': '#f1f5f9',
            'z-index': 999,
          }},
        }},
        {{
          selector: '.faded',
          style: {{ 'opacity': 0.08 }},
        }},
      ],
      layout: {{
        name: 'dagre',
        rankDir: 'LR',
        nodeSep: 40,
        rankSep: 100,
        edgeSep: 12,
        padding: 30,
        animate: false,
        fit: true,
      }},
      minZoom: 0.15,
      maxZoom: 4,
      wheelSensitivity: 0.3,
    }});
    cyAtk.ready(function() {{ cyAtk.fit(cyAtk.elements(), 40); }});

    // Attack flow tooltip
    cyAtk.on('mouseover', 'node', function(e) {{
      var t = e.target.data('tip');
      if (t) {{ tip.textContent = t; tip.style.display = 'block'; }}
    }});
    cyAtk.on('mousemove', function(e) {{
      if (tip.style.display === 'block') {{
        tip.style.left = (e.originalEvent.clientX + 14) + 'px';
        tip.style.top  = (e.originalEvent.clientY + 14) + 'px';
      }}
    }});
    cyAtk.on('mouseout', 'node', function() {{ tip.style.display = 'none'; }});

    // Attack flow click to highlight
    cyAtk.on('tap', 'node', function(e) {{
      cyAtk.elements().removeClass('faded highlighted');
      var hood = e.target.closedNeighborhood();
      cyAtk.elements().not(hood).addClass('faded');
      e.target.addClass('highlighted');
    }});
    cyAtk.on('tap', function(e) {{
      if (e.target === cyAtk) {{
        cyAtk.elements().removeClass('faded highlighted');
      }}
    }});

    // Attack flow controls
    var afZoomIn = document.getElementById('afZoomIn');
    var afZoomOut = document.getElementById('afZoomOut');
    var afFitBtn = document.getElementById('afFitBtn');
    if (afZoomIn) afZoomIn.addEventListener('click', function() {{
      cyAtk.zoom({{ level: cyAtk.zoom() * 1.3, renderedPosition: {{ x: cyAtk.width() / 2, y: cyAtk.height() / 2 }} }});
    }});
    if (afZoomOut) afZoomOut.addEventListener('click', function() {{
      cyAtk.zoom({{ level: cyAtk.zoom() / 1.3, renderedPosition: {{ x: cyAtk.width() / 2, y: cyAtk.height() / 2 }} }});
    }});
    if (afFitBtn) afFitBtn.addEventListener('click', function() {{
      cyAtk.fit(cyAtk.elements(), 40);
    }});

    // Animated dash flow on exploit/compromises edges
    var dashOffset = 0;
    function animateAttackEdges() {{
      dashOffset = (dashOffset + 0.5) % 24;
      cyAtk.edges('[type="exploits"],[type="compromises"]').forEach(function(edge) {{
        edge.style('line-dash-offset', -dashOffset);
      }});
      requestAnimationFrame(animateAttackEdges);
    }}
    // Only animate if attack edges exist
    if (cyAtk.edges('[type="exploits"],[type="compromises"]').length > 0) {{
      // Set dashed style for animation
      cyAtk.edges('[type="exploits"]').style({{
        'line-style': 'dashed',
        'line-dash-pattern': [8, 4],
      }});
      cyAtk.edges('[type="compromises"]').style({{
        'line-style': 'dashed',
        'line-dash-pattern': [10, 5],
      }});
      animateAttackEdges();
    }}

    // Attack flow node count stats
    var afStats = document.createElement('div');
    afStats.style.cssText = 'position:absolute;bottom:12px;right:12px;background:rgba(15,23,42,.9);border:1px solid #334155;border-radius:8px;padding:8px 14px;font-size:.72rem;color:#64748b;z-index:10;backdrop-filter:blur(8px)';
    var afCounts = {{}};
    cyAtk.nodes().forEach(function(n) {{
      var t = n.data('type') || 'other';
      if (t === 'cve' || t.indexOf('cve_')===0) t = 'cve';
      afCounts[t] = (afCounts[t] || 0) + 1;
    }});
    var afParts = [];
    if (afCounts.cve) afParts.push('<span style="color:#f87171">' + afCounts.cve + ' CVEs</span>');
    if (afCounts.pkg_vuln) afParts.push('<span style="color:#dc2626">' + afCounts.pkg_vuln + ' pkgs</span>');
    if (afCounts.server) afParts.push('<span style="color:#64748b">' + afCounts.server + ' servers</span>');
    if (afCounts.credential) afParts.push('<span style="color:#fbbf24">' + afCounts.credential + ' creds</span>');
    if (afCounts.tool) afParts.push('<span style="color:#818cf8">' + afCounts.tool + ' tools</span>');
    if (afCounts.agent) afParts.push('<span style="color:#3b82f6">' + afCounts.agent + ' agents</span>');
    afStats.innerHTML = afParts.join(' &middot; ');
    cyAtkContainer.parentNode.appendChild(afStats);
  }}

  // Table sorting
  document.querySelectorAll('.data-table.sortable th').forEach(function(th) {{
    th.addEventListener('click', function() {{
      var table = th.closest('table');
      var tbody = table.querySelector('tbody');
      var rows = Array.from(tbody.querySelectorAll('tr'));
      var col = parseInt(th.getAttribute('data-col'));
      var arrow = th.querySelector('.sort-arrow');
      var asc = !arrow.classList.contains('asc');

      table.querySelectorAll('.sort-arrow').forEach(function(a) {{ a.className = 'sort-arrow'; }});
      arrow.className = 'sort-arrow ' + (asc ? 'asc' : 'desc');

      rows.sort(function(a, b) {{
        var at = (a.children[col] || {{}}).textContent || '';
        var bt = (b.children[col] || {{}}).textContent || '';
        var an = parseFloat(at.replace(/[^\\d.-]/g, ''));
        var bn = parseFloat(bt.replace(/[^\\d.-]/g, ''));
        if (!isNaN(an) && !isNaN(bn)) return asc ? an - bn : bn - an;
        return asc ? at.localeCompare(bt) : bt.localeCompare(at);
      }});
      rows.forEach(function(r) {{ tbody.appendChild(r); }});
      // Re-slice the current page after re-ordering the DOM (paginator lives in
      // the standalone scale-report script; guard in case it did not load).
      if (window.PAGINATORS && window.PAGINATORS[table.id]) window.PAGINATORS[table.id].resort();
    }});
  }});

  // Inventory search
  var searchInput = document.getElementById('invSearch');
  if (searchInput) {{
    searchInput.addEventListener('input', function() {{
      var q = this.value.toLowerCase();
      document.querySelectorAll('.agent-card').forEach(function(card) {{
        var text = card.textContent.toLowerCase();
        card.style.display = text.includes(q) ? '' : 'none';
      }});
    }});
  }}

  // Package list toggle
  window.togglePkgs = function(id, btn) {{
    var el = document.getElementById(id);
    if (!el) return;
    var hidden = el.style.display === 'none';
    el.style.display = hidden ? 'block' : 'none';
    btn.innerHTML = hidden
      ? 'Show fewer &#x25B2;'
      : btn.dataset.orig || btn.innerHTML;
    if (hidden && !btn.dataset.orig) btn.dataset.orig = btn.innerHTML;
  }};

  // Smooth scroll + close mobile sidebar. Tab reveal + robust anchor handling
  // live in the standalone scale-report script so they survive CDN/graph load
  // failures (offline / emailed reports).
  document.querySelectorAll('a[href^="#"]').forEach(function(a) {{
    a.addEventListener('click', function() {{
      var sb = document.getElementById('mainSidebar');
      if (sb) sb.classList.remove('mobile-open');
    }});
  }});

  // Sidebar active section tracking via IntersectionObserver
  var sidebarLinks = document.querySelectorAll('.sidebar-link');
  var sections = document.querySelectorAll('section[id]');
  if (sections.length > 0 && 'IntersectionObserver' in window) {{
    var observer = new IntersectionObserver(function(entries) {{
      entries.forEach(function(entry) {{
        if (entry.isIntersecting) {{
          sidebarLinks.forEach(function(link) {{
            link.classList.remove('active');
            if (link.getAttribute('href') === '#' + entry.target.id) {{
              link.classList.add('active');
            }}
          }});
        }}
      }});
    }}, {{ rootMargin: '-20% 0px -60% 0px', threshold: 0 }});
    sections.forEach(function(sec) {{ observer.observe(sec); }});
  }}
}})();
</script>"""


def _offline_assets_notice() -> str:
    return """
  <div class="offline-assets-banner" style="margin-bottom:16px;padding:12px 14px;border:1px solid #334155;border-radius:10px;background:#111827;color:#cbd5e1">
    <strong style="color:#f8fafc">Offline HTML mode</strong>
    <span style="color:#94a3b8"> — external JavaScript assets were omitted. Static tables, findings, remediation, compliance, inventory, and evidence sections remain available.</span>
  </div>
"""


def _offline_assets_script() -> str:
    return """<script>
(function() {
  function replace(id, title) {
    var el = document.getElementById(id);
    if (!el) return;
    var box = document.createElement('div');
    box.style.cssText = 'min-height:180px;display:flex;align-items:center;justify-content:center;text-align:center;padding:24px;border:1px dashed #334155;border-radius:10px;color:#94a3b8;background:#0f172a';
    box.innerHTML = '<div><strong style="color:#cbd5e1">' + title + '</strong><br>Interactive rendering is disabled in offline HTML mode.</div>';
    el.parentNode.replaceChild(box, el);
  }
  replace('sevChart', 'Severity chart');
  replace('blastChart', 'Blast-radius chart');
  replace('cy', 'Supply-chain graph');
  replace('attackCy', 'Attack-flow graph');
  document.querySelectorAll('.graph-filter-bar,.graph-controls').forEach(function(el) {
    el.style.display = 'none';
  });
  document.querySelectorAll('details').forEach(function(el) {
    el.open = el.open || false;
  });
})();
</script>"""


def _apply_offline_assets_mode(html: str) -> str:
    for tag in _EXTERNAL_SCRIPT_TAGS:
        html = html.replace(tag, "")
    marker = '<div class="container">\n'
    html = html.replace(marker, marker + _offline_assets_notice(), 1)
    script_start = html.find("\n<script>\n(function() {")
    script_end = html.rfind("</script>\n\n</body>")
    if script_start != -1 and script_end != -1:
        html = html[:script_start] + "\n" + _offline_assets_script() + html[script_end + len("</script>") :]
    return html
