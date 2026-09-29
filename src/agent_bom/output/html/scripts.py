"""Embedded JavaScript layers and offline-asset post-processing."""

from __future__ import annotations

from agent_bom.output.html.graph_js_attack_flow import ATTACK_FLOW_GRAPH_JS
from agent_bom.output.html.graph_js_supply_chain import SUPPLY_CHAIN_GRAPH_JS, SUPPLY_CHAIN_SIDEBAR_JS
from agent_bom.output.html.graph_js_supply_chain_tools import SUPPLY_CHAIN_TOOLS_JS

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


SEVERITY_CHART_JS = """\
  // Chart.js: Severity donut
  var sevCtx = document.getElementById('sevChart');
  if (sevCtx && CHART_DATA.sev.data.some(function(v){ return v > 0; })) {
    new Chart(sevCtx, {
      type: 'doughnut',
      data: {
        labels: CHART_DATA.sev.labels,
        datasets: [{
          data: CHART_DATA.sev.data,
          backgroundColor: CHART_DATA.sev.colors,
          borderColor: '#0b1120',
          borderWidth: 3,
          hoverOffset: 8,
        }],
      },
      options: {
        responsive: true,
        cutout: '68%',
        plugins: {
          legend: {
            position: 'bottom',
            labels: {
              color: '#94a3b8',
              font: { size: 11 },
              boxWidth: 12,
              padding: 14,
            },
          },
          tooltip: {
            backgroundColor: '#0f172a',
            borderColor: '#334155',
            borderWidth: 1,
            titleColor: '#e2e8f0',
            bodyColor: '#94a3b8',
            cornerRadius: 8,
            padding: 10,
            callbacks: {
              label: function(ctx) {
                return ' ' + ctx.label + ': ' + ctx.parsed;
              },
            },
          },
        },
      },
    });
  } else if (sevCtx) {
    var p = document.createElement('p');
    p.style.cssText = 'color:#4ade80;text-align:center;padding:50px 0;font-size:.88rem';
    p.innerHTML = '&#x2705; No vulnerabilities';
    sevCtx.parentNode.replaceChild(p, sevCtx);
  }

"""

BLAST_RADIUS_CHART_JS = """\
  // Chart.js: Blast radius bar
  var blastCtx = document.getElementById('blastChart');
  if (blastCtx && CHART_DATA.blast.labels.length > 0) {
    new Chart(blastCtx, {
      type: 'bar',
      data: {
        labels: CHART_DATA.blast.labels,
        datasets: [{
          label: 'Blast Score',
          data: CHART_DATA.blast.scores,
          backgroundColor: CHART_DATA.blast.colors,
          borderRadius: 6,
          borderSkipped: false,
        }],
      },
      options: {
        indexAxis: 'y',
        responsive: true,
        scales: {
          x: {
            min: 0, max: 10,
            grid: { color: '#1e293b' },
            ticks: { color: '#64748b', font: { size: 11 } },
          },
          y: {
            grid: { display: false },
            ticks: { color: '#94a3b8', font: { size: 11 } },
          },
        },
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: '#0f172a',
            borderColor: '#334155',
            borderWidth: 1,
            titleColor: '#e2e8f0',
            bodyColor: '#94a3b8',
            cornerRadius: 8,
            callbacks: {
              label: function(ctx) {
                return ' Score: ' + ctx.parsed.x.toFixed(2);
              },
            },
          },
        },
      },
    });
  } else if (blastCtx) {
    var p2 = document.createElement('p');
    p2.style.cssText = 'color:#4ade80;text-align:center;padding:50px 0;font-size:.88rem';
    p2.innerHTML = '&#x2705; No blast radius data';
    blastCtx.parentNode.replaceChild(p2, blastCtx);
  }

"""

PAGE_INTERACTIONS_JS = """\
  // Table sorting
  document.querySelectorAll('.data-table.sortable th').forEach(function(th) {
    th.addEventListener('click', function() {
      var table = th.closest('table');
      var tbody = table.querySelector('tbody');
      var rows = Array.from(tbody.querySelectorAll('tr'));
      var col = parseInt(th.getAttribute('data-col'));
      var arrow = th.querySelector('.sort-arrow');
      var asc = !arrow.classList.contains('asc');

      table.querySelectorAll('.sort-arrow').forEach(function(a) { a.className = 'sort-arrow'; });
      arrow.className = 'sort-arrow ' + (asc ? 'asc' : 'desc');

      rows.sort(function(a, b) {
        var at = (a.children[col] || {}).textContent || '';
        var bt = (b.children[col] || {}).textContent || '';
        var an = parseFloat(at.replace(/[^\\d.-]/g, ''));
        var bn = parseFloat(bt.replace(/[^\\d.-]/g, ''));
        if (!isNaN(an) && !isNaN(bn)) return asc ? an - bn : bn - an;
        return asc ? at.localeCompare(bt) : bt.localeCompare(at);
      });
      rows.forEach(function(r) { tbody.appendChild(r); });
      // Re-slice the current page after re-ordering the DOM (paginator lives in
      // the standalone scale-report script; guard in case it did not load).
      if (window.PAGINATORS && window.PAGINATORS[table.id]) window.PAGINATORS[table.id].resort();
    });
  });

  // Inventory search
  var searchInput = document.getElementById('invSearch');
  if (searchInput) {
    searchInput.addEventListener('input', function() {
      var q = this.value.toLowerCase();
      document.querySelectorAll('.agent-card').forEach(function(card) {
        var text = card.textContent.toLowerCase();
        card.style.display = text.includes(q) ? '' : 'none';
      });
    });
  }

  // Package list toggle
  window.togglePkgs = function(id, btn) {
    var el = document.getElementById(id);
    if (!el) return;
    var hidden = el.style.display === 'none';
    el.style.display = hidden ? 'block' : 'none';
    btn.innerHTML = hidden
      ? 'Show fewer &#x25B2;'
      : btn.dataset.orig || btn.innerHTML;
    if (hidden && !btn.dataset.orig) btn.dataset.orig = btn.innerHTML;
  };

  // Smooth scroll + close mobile sidebar. Tab reveal + robust anchor handling
  // live in the standalone scale-report script so they survive CDN/graph load
  // failures (offline / emailed reports).
  document.querySelectorAll('a[href^="#"]').forEach(function(a) {
    a.addEventListener('click', function() {
      var sb = document.getElementById('mainSidebar');
      if (sb) sb.classList.remove('mobile-open');
    });
  });

  // Sidebar active section tracking via IntersectionObserver
  var sidebarLinks = document.querySelectorAll('.sidebar-link');
  var sections = document.querySelectorAll('section[id]');
  if (sections.length > 0 && 'IntersectionObserver' in window) {
    var observer = new IntersectionObserver(function(entries) {
      entries.forEach(function(entry) {
        if (entry.isIntersecting) {
          sidebarLinks.forEach(function(link) {
            link.classList.remove('active');
            if (link.getAttribute('href') === '#' + entry.target.id) {
              link.classList.add('active');
            }
          });
        }
      });
    }, { rootMargin: '-20% 0px -60% 0px', threshold: 0 });
    sections.forEach(function(sec) { observer.observe(sec); });
  }
"""

_GRAPH_SCRIPT_BODY = "".join(
    (
        SEVERITY_CHART_JS,
        BLAST_RADIUS_CHART_JS,
        SUPPLY_CHAIN_GRAPH_JS,
        SUPPLY_CHAIN_SIDEBAR_JS,
        SUPPLY_CHAIN_TOOLS_JS,
        ATTACK_FLOW_GRAPH_JS,
        PAGE_INTERACTIONS_JS,
        "})();\n</script>",
    )
)


def render_graph_script(chart_data_json: str, elements_json: str, attack_flow_json: str) -> str:
    """Return the Chart.js + Cytoscape graph/interaction <script> block."""
    injected_data = f"""\
<script>
(function() {{
  // Injected data
  var CHART_DATA = {chart_data_json};
  var GRAPH_ELEMENTS = {elements_json};
  var ATTACK_FLOW = {attack_flow_json};

"""
    return injected_data + _GRAPH_SCRIPT_BODY


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
