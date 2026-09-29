"""Supply-chain graph JavaScript: Cytoscape setup, styles, tooltip and node sidebar."""

from __future__ import annotations

SUPPLY_CHAIN_GRAPH_JS = """\
  // Cytoscape: Supply chain graph with dagre hierarchical layout
  var cyContainer = document.getElementById('cy');
  if (cyContainer && GRAPH_ELEMENTS.length > 0) {
    var cy = cytoscape({
      container: cyContainer,
      elements: GRAPH_ELEMENTS,
      style: [
        {
          selector: 'node[type="provider"]',
          style: {
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
          },
        },
        {
          selector: 'node[type="agent"]',
          style: {
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
          },
        },
        {
          selector: 'node[type="server_clean"]',
          style: {
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
          },
        },
        {
          selector: 'node[type="server_cred"]',
          style: {
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
          },
        },
        {
          selector: 'node[type="server_vuln"]',
          style: {
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
          },
        },
        {
          selector: 'node[type="pkg_vuln"]',
          style: {
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
          },
        },
        {
          selector: 'node[type="cve"][severity="critical"], node[type^="cve_critical"]',
          style: {
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
          },
        },
        {
          selector: 'node[type="cve"][severity="high"], node[type^="cve_high"]',
          style: {
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
          },
        },
        {
          selector: 'node[type="cve"][severity="medium"], node[type="cve"][severity="low"], node[type="cve"][severity="none"], node[type^="cve_medium"], node[type^="cve_low"], node[type^="cve_none"]',
          style: {
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
          },
        },
        {
          selector: 'edge',
          style: {
            'width': 1.8,
            'line-color': '#334155',
            'target-arrow-color': '#475569',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'arrow-scale': 0.8,
          },
        },
        {
          selector: 'edge[type="hosts"]',
          style: {
            'line-color': '#818cf850',
            'target-arrow-color': '#818cf880',
            'line-style': 'dashed',
            'line-dash-pattern': [6, 3],
          },
        },
        {
          selector: 'edge[type="affects"]',
          style: {
            'line-color': '#dc262650',
            'target-arrow-color': '#dc262680',
          },
        },
        {
          selector: '.highlighted',
          style: {
            'border-width': 4,
            'border-color': '#f1f5f9',
            'z-index': 999,
          },
        },
        {
          selector: '.faded',
          style: { 'opacity': 0.08 },
        },
      ],
      layout: {
        name: 'dagre',
        rankDir: 'LR',
        nodeSep: 50,
        rankSep: 80,
        edgeSep: 15,
        padding: 30,
        animate: false,
        fit: true,
      },
      minZoom: 0.15,
      maxZoom: 4,
      wheelSensitivity: 0.3,
      autoungrabify: false,
    });
    cy.ready(function() { cy.fit(cy.elements(), 40); });

    // Tooltip
    var tip = document.getElementById('tip');
    cy.on('mouseover', 'node', function(e) {
      var t = e.target.data('tip');
      if (t) { tip.textContent = t; tip.style.display = 'block'; }
    });
    cy.on('mousemove', function(e) {
      if (tip.style.display === 'block') {
        tip.style.left = (e.originalEvent.clientX + 14) + 'px';
        tip.style.top  = (e.originalEvent.clientY + 14) + 'px';
      }
    });
    cy.on('mouseout', 'node', function() { tip.style.display = 'none'; });

"""

SUPPLY_CHAIN_SIDEBAR_JS = """\
    // Click to highlight + sidebar
    var sidebar = document.getElementById('nodeDetailSidebar');
    var sidebarCloseBtn = document.getElementById('sidebarClose');

    function escHtml(value) {
      return String(value == null ? '' : value).replace(/[&<>"']/g, function(ch) {
        return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch];
      });
    }

    function urlPart(value) {
      return encodeURIComponent(String(value == null ? '' : value));
    }

    function showSidebar(node) {
      var d = node.data();
      var t = d.type || '';
      var isCveNode = t === 'cve' || t.indexOf('cve_')===0;
      var typeLabels = {'provider':'Provider','agent':'Agent','server_clean':'MCP Server','server_cred':'MCP Server','server_vuln':'MCP Server','pkg_vuln':'Package','cve':'Vulnerability'};
      var typeLabel = typeLabels[t] || (isCveNode ? 'Vulnerability' : t);
      var typeColors = {'provider':'#818cf8','agent':'#3b82f6','server_clean':'#10b981','server_cred':'#f59e0b','server_vuln':'#ef4444','pkg_vuln':'#dc2626'};
      var badgeColor = typeColors[t] || (isCveNode ? '#f87171' : '#64748b');

      document.getElementById('sidebarNodeType').textContent = typeLabel;
      document.getElementById('sidebarNodeType').style.borderColor = badgeColor;
      document.getElementById('sidebarNodeType').style.color = badgeColor;
      document.getElementById('sidebarNodeName').textContent = d.label || d.id;

      ['sidebarMeta','sidebarConnected','sidebarCredentials','sidebarCves','sidebarRemediation'].forEach(function(id) {
        document.getElementById(id).innerHTML = '';
      });

      // Connected nodes
      var neighbors = node.neighborhood('node');
      if (neighbors.length > 0) {
        var h = '<div class="sidebar-label">Connected (' + neighbors.length + ')</div><ul class="sidebar-list">';
        neighbors.forEach(function(n) {
          var nt = n.data('type') || '';
          var icon = nt === 'agent' ? '&#x1f916;' : nt.indexOf('server')===0 ? '&#x2699;' : nt === 'pkg_vuln' ? '&#x1f4e6;' : (nt === 'cve' || nt.indexOf('cve_')===0) ? '&#x1f41b;' : '&#x25cf;';
          h += '<li>' + icon + ' ' + escHtml((n.data('label') || n.data('id')).replace('\\n',' ')) + '</li>';
        });
        h += '</ul>';
        document.getElementById('sidebarConnected').innerHTML = h;
      }

      // Agent
      if (t === 'agent') {
        var meta = '';
        if (d.agentType) meta += 'Type: ' + d.agentType + '\\n';
        if (d.discovery_source) meta += 'Source: ' + d.discovery_source + '\\n';
        if (d.configPath) meta += 'Config: ' + d.configPath;
        document.getElementById('sidebarMeta').textContent = meta;
        var s = '<div class="sidebar-label">Statistics</div><ul class="sidebar-list">';
        s += '<li>Servers: ' + (d.serverCount || 0) + '</li>';
        s += '<li>Packages: ' + (d.packageCount || 0) + '</li>';
        if (d.vulnCount) s += '<li style="color:#f87171">Vulnerabilities: ' + d.vulnCount + '</li>';
        s += '</ul>';
        document.getElementById('sidebarRemediation').innerHTML = s;
      }

      // Server
      if (t.indexOf('server_')===0) {
        if (d.command) document.getElementById('sidebarMeta').textContent = d.command;
        var creds = []; try { creds = JSON.parse(d.credentials || '[]'); } catch(e) {}
        if (creds.length > 0) {
          var ch = '<div class="sidebar-label">Credentials (' + creds.length + ')</div><ul class="sidebar-list">';
          creds.forEach(function(c) { ch += '<li>&#x1f511; <span class="sidebar-cred">' + escHtml(c) + '</span></li>'; });
          ch += '</ul>';
          document.getElementById('sidebarCredentials').innerHTML = ch;
        }
        var tools = []; try { tools = JSON.parse(d.toolNames || '[]'); } catch(e) {}
        if (tools.length > 0) {
          var th = '<div class="sidebar-label">MCP Tools (' + tools.length + ')</div><ul class="sidebar-list">';
          tools.forEach(function(tl) { th += '<li>&#x1f527; ' + escHtml(tl) + '</li>'; });
          th += '</ul>';
          document.getElementById('sidebarRemediation').innerHTML = th;
        }
        var ph = '<div class="sidebar-label">Packages</div><ul class="sidebar-list">';
        ph += '<li>Total: ' + (d.packageCount || 0) + '</li>';
        if (d.vulnCount) ph += '<li style="color:#f87171">Vulnerable: ' + d.vulnCount + '</li>';
        ph += '</ul>';
        document.getElementById('sidebarCves').innerHTML = ph;
      }

      // Package
      if (t === 'pkg_vuln') {
        document.getElementById('sidebarMeta').textContent = (d.ecosystem || '') + ' \\u00b7 ' + (d.version || '');
        var vids = []; try { vids = JSON.parse(d.vulnIds || '[]'); } catch(e) {}
        if (vids.length > 0) {
          var vh = '<div class="sidebar-label">CVEs (' + vids.length + ')</div><ul class="sidebar-list">';
          vids.forEach(function(vid) {
            vh += '<li><a class="sidebar-link" href="https://osv.dev/vulnerability/' + urlPart(vid) + '" target="_blank" rel="noopener noreferrer">' + escHtml(vid) + ' &#x2197;</a></li>';
          });
          vh += '</ul>';
          document.getElementById('sidebarCves').innerHTML = vh;
        }
      }

      // CVE
      if (isCveNode) {
        var sev = d.severity || t.replace('cve_', '');
        var mp = [];
        if (sev) mp.push('Severity: ' + sev.toUpperCase());
        if (d.cvssScore) mp.push('CVSS: ' + d.cvssScore);
        document.getElementById('sidebarMeta').textContent = mp.join(' \\u00b7 ');
        if (d.summary) {
          document.getElementById('sidebarCredentials').innerHTML = '<div class="sidebar-label">Summary</div><p style="font-size:.8rem;color:#cbd5e1;margin:0">' + escHtml(d.summary) + '</p>';
        }
        var rh = '<div class="sidebar-label">Remediation</div><ul class="sidebar-list">';
        if (d.fixVersion) {
          rh += '<li style="color:#4ade80">&#x2705; Fix: upgrade to <code>' + escHtml(d.fixVersion) + '</code></li>';
        } else {
          rh += '<li style="color:#f59e0b">&#x26a0; No fix available</li>';
        }
        var lbl = d.label || '';
        rh += '<li><a class="sidebar-link" href="https://osv.dev/vulnerability/' + urlPart(lbl) + '" target="_blank" rel="noopener noreferrer">View on OSV &#x2197;</a></li>';
        rh += '<li><a class="sidebar-link" href="https://nvd.nist.gov/vuln/detail/' + urlPart(lbl) + '" target="_blank" rel="noopener noreferrer">View on NVD &#x2197;</a></li>';
        rh += '</ul>';
        document.getElementById('sidebarRemediation').innerHTML = rh;
      }

      sidebar.classList.add('open');
      sidebar.style.display = 'block';
    }

    function closeSidebar() {
      sidebar.classList.remove('open');
      setTimeout(function() { sidebar.style.display = 'none'; }, 250);
    }

    sidebarCloseBtn.addEventListener('click', closeSidebar);

    cy.on('tap', 'node', function(e) {
      cy.elements().removeClass('faded highlighted');
      var hood = e.target.closedNeighborhood();
      cy.elements().not(hood).addClass('faded');
      e.target.addClass('highlighted');
      showSidebar(e.target);
    });
    cy.on('tap', function(e) {
      if (e.target === cy) {
        cy.elements().removeClass('faded highlighted');
        closeSidebar();
      }
    });

"""
