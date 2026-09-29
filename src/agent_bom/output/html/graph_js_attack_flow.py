"""CVE attack-flow graph JavaScript."""

from __future__ import annotations

ATTACK_FLOW_GRAPH_JS = """\
  // Cytoscape: CVE Attack Flow graph
  var cyAtkContainer = document.getElementById('cyAttack');
  if (cyAtkContainer && ATTACK_FLOW.length > 0) {
    var cyAtk = cytoscape({
      container: cyAtkContainer,
      elements: ATTACK_FLOW,
      style: [
        {
          selector: 'node[type="cve"], node[type^="cve_"]',
          style: {
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
          },
        },
        {
          selector: 'node[type="cve"][severity="critical"], node[type="cve_critical"]',
          style: {
            'background-color': '#7f1d1d',
            'border-color': '#ef4444',
            'border-width': 3,
            'width': 130,
            'height': 38,
            'underlay-color': '#ef4444',
            'underlay-padding': '6px',
            'underlay-opacity': 0.15,
            'underlay-shape': 'ellipse',
          },
        },
        {
          selector: 'node[type="cve"][severity="high"], node[type="cve_high"]',
          style: {
            'background-color': '#9a3412',
            'border-color': '#fb923c',
            'color': '#fed7aa',
            'underlay-color': '#fb923c',
            'underlay-padding': '4px',
            'underlay-opacity': 0.1,
            'underlay-shape': 'ellipse',
          },
        },
        {
          selector: 'node[type="cve"][severity="medium"], node[type="cve"][severity="low"], node[type="cve"][severity="none"], node[type="cve_medium"], node[type="cve_low"], node[type="cve_none"]',
          style: {
            'background-color': '#854d0e',
            'border-color': '#fbbf24',
            'border-width': 1.5,
            'color': '#fef08a',
            'width': 100,
            'height': 28,
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
          selector: 'node[type="server"]',
          style: {
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
          },
        },
        {
          selector: 'node[type="credential"]',
          style: {
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
          },
        },
        {
          selector: 'node[type="tool"]',
          style: {
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
            'font-size': '11px',
            'font-weight': '700',
            'text-valign': 'center',
            'text-halign': 'center',
            'width': 120,
            'height': 38,
            'shape': 'round-rectangle',
            'text-wrap': 'wrap',
            'text-max-width': '105px',
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
          selector: 'edge[type="exploits"]',
          style: {
            'line-color': '#dc2626',
            'target-arrow-color': '#ef4444',
            'width': 2.5,
          },
        },
        {
          selector: 'edge[type="runs_on"]',
          style: {
            'line-color': '#475569',
            'target-arrow-color': '#64748b',
          },
        },
        {
          selector: 'edge[type="exposes"]',
          style: {
            'line-color': '#f59e0b',
            'target-arrow-color': '#fbbf24',
            'line-style': 'dashed',
            'line-dash-pattern': [6, 3],
            'width': 2,
          },
        },
        {
          selector: 'edge[type="reaches"]',
          style: {
            'line-color': '#818cf8',
            'target-arrow-color': '#a5b4fc',
            'line-style': 'dashed',
            'line-dash-pattern': [4, 4],
          },
        },
        {
          selector: 'edge[type="compromises"]',
          style: {
            'line-color': '#ef4444',
            'target-arrow-color': '#f87171',
            'line-style': 'dashed',
            'line-dash-pattern': [8, 4],
            'width': 2.5,
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
        nodeSep: 40,
        rankSep: 100,
        edgeSep: 12,
        padding: 30,
        animate: false,
        fit: true,
      },
      minZoom: 0.15,
      maxZoom: 4,
      wheelSensitivity: 0.3,
    });
    cyAtk.ready(function() { cyAtk.fit(cyAtk.elements(), 40); });

    // Attack flow tooltip
    cyAtk.on('mouseover', 'node', function(e) {
      var t = e.target.data('tip');
      if (t) { tip.textContent = t; tip.style.display = 'block'; }
    });
    cyAtk.on('mousemove', function(e) {
      if (tip.style.display === 'block') {
        tip.style.left = (e.originalEvent.clientX + 14) + 'px';
        tip.style.top  = (e.originalEvent.clientY + 14) + 'px';
      }
    });
    cyAtk.on('mouseout', 'node', function() { tip.style.display = 'none'; });

    // Attack flow click to highlight
    cyAtk.on('tap', 'node', function(e) {
      cyAtk.elements().removeClass('faded highlighted');
      var hood = e.target.closedNeighborhood();
      cyAtk.elements().not(hood).addClass('faded');
      e.target.addClass('highlighted');
    });
    cyAtk.on('tap', function(e) {
      if (e.target === cyAtk) {
        cyAtk.elements().removeClass('faded highlighted');
      }
    });

    // Attack flow controls
    var afZoomIn = document.getElementById('afZoomIn');
    var afZoomOut = document.getElementById('afZoomOut');
    var afFitBtn = document.getElementById('afFitBtn');
    if (afZoomIn) afZoomIn.addEventListener('click', function() {
      cyAtk.zoom({ level: cyAtk.zoom() * 1.3, renderedPosition: { x: cyAtk.width() / 2, y: cyAtk.height() / 2 } });
    });
    if (afZoomOut) afZoomOut.addEventListener('click', function() {
      cyAtk.zoom({ level: cyAtk.zoom() / 1.3, renderedPosition: { x: cyAtk.width() / 2, y: cyAtk.height() / 2 } });
    });
    if (afFitBtn) afFitBtn.addEventListener('click', function() {
      cyAtk.fit(cyAtk.elements(), 40);
    });

    // Animated dash flow on exploit/compromises edges
    var dashOffset = 0;
    function animateAttackEdges() {
      dashOffset = (dashOffset + 0.5) % 24;
      cyAtk.edges('[type="exploits"],[type="compromises"]').forEach(function(edge) {
        edge.style('line-dash-offset', -dashOffset);
      });
      requestAnimationFrame(animateAttackEdges);
    }
    // Only animate if attack edges exist
    if (cyAtk.edges('[type="exploits"],[type="compromises"]').length > 0) {
      // Set dashed style for animation
      cyAtk.edges('[type="exploits"]').style({
        'line-style': 'dashed',
        'line-dash-pattern': [8, 4],
      });
      cyAtk.edges('[type="compromises"]').style({
        'line-style': 'dashed',
        'line-dash-pattern': [10, 5],
      });
      animateAttackEdges();
    }

    // Attack flow node count stats
    var afStats = document.createElement('div');
    afStats.style.cssText = 'position:absolute;bottom:12px;right:12px;background:rgba(15,23,42,.9);border:1px solid #334155;border-radius:8px;padding:8px 14px;font-size:.72rem;color:#64748b;z-index:10;backdrop-filter:blur(8px)';
    var afCounts = {};
    cyAtk.nodes().forEach(function(n) {
      var t = n.data('type') || 'other';
      if (t === 'cve' || t.indexOf('cve_')===0) t = 'cve';
      afCounts[t] = (afCounts[t] || 0) + 1;
    });
    var afParts = [];
    if (afCounts.cve) afParts.push('<span style="color:#f87171">' + afCounts.cve + ' CVEs</span>');
    if (afCounts.pkg_vuln) afParts.push('<span style="color:#dc2626">' + afCounts.pkg_vuln + ' pkgs</span>');
    if (afCounts.server) afParts.push('<span style="color:#64748b">' + afCounts.server + ' servers</span>');
    if (afCounts.credential) afParts.push('<span style="color:#fbbf24">' + afCounts.credential + ' creds</span>');
    if (afCounts.tool) afParts.push('<span style="color:#818cf8">' + afCounts.tool + ' tools</span>');
    if (afCounts.agent) afParts.push('<span style="color:#3b82f6">' + afCounts.agent + ' agents</span>');
    afStats.innerHTML = afParts.join(' &middot; ');
    cyAtkContainer.parentNode.appendChild(afStats);
  }

"""
