"""Supply-chain graph JavaScript: controls, filters, search, context menu, minimap and stats."""

from __future__ import annotations

SUPPLY_CHAIN_TOOLS_JS = """\
    // Graph controls
    document.getElementById('zoomIn').addEventListener('click', function() {
      cy.zoom({ level: cy.zoom() * 1.3, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
    });
    document.getElementById('zoomOut').addEventListener('click', function() {
      cy.zoom({ level: cy.zoom() / 1.3, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
    });
    document.getElementById('fitBtn').addEventListener('click', function() {
      cy.fit(cy.elements(), 40);
    });
    document.getElementById('fullscreenBtn').addEventListener('click', function() {
      var gc = document.querySelector('.graph-container');
      if (!document.fullscreenElement) {
        gc.requestFullscreen().then(function() {
          setTimeout(function() { cy.resize(); cy.fit(cy.elements(), 50); }, 100);
        }).catch(function() {});
      } else {
        document.exitFullscreen();
      }
    });
    document.addEventListener('fullscreenchange', function() {
      if (!document.fullscreenElement) {
        setTimeout(function() { cy.resize(); cy.fit(cy.elements(), 40); }, 100);
      }
    });
    // Graph severity filter
    document.querySelectorAll('.graph-sev-filter').forEach(function(cb) {
      cb.addEventListener('change', function() {
        var checked = Array.from(document.querySelectorAll('.graph-sev-filter:checked')).map(function(c) { return c.value; });
        cy.nodes().forEach(function(n) {
          var t = n.data('type') || '';
          if (t === 'cve' || t.startsWith('cve_')) {
            var sev = n.data('severity') || t.replace('cve_', '');
            if (checked.indexOf(sev) === -1) {
              n.style('display', 'none');
              n.connectedEdges().style('display', 'none');
            } else {
              n.style('display', 'element');
              n.connectedEdges().style('display', 'element');
            }
          }
        });
      });
    });

    // Graph search
    var graphSearchInput = document.getElementById('graphSearch');
    if (graphSearchInput) {
      graphSearchInput.addEventListener('input', function() {
        var q = this.value.toLowerCase();
        if (!q) {
          cy.elements().removeClass('faded highlighted');
          return;
        }
        cy.elements().removeClass('faded highlighted');
        var matched = cy.nodes().filter(function(n) {
          return (n.data('label') || '').toLowerCase().indexOf(q) >= 0;
        });
        if (matched.length > 0) {
          var hood = matched.closedNeighborhood();
          cy.elements().not(hood).addClass('faded');
          matched.addClass('highlighted');
        } else {
          cy.elements().addClass('faded');
        }
      });
    }

    // Context menu (right-click on nodes)
    var ctxMenu = document.createElement('div');
    ctxMenu.className = 'cy-ctx-menu';
    document.body.appendChild(ctxMenu);

    function hideCtxMenu() { ctxMenu.classList.remove('show'); }
    document.addEventListener('click', hideCtxMenu);
    document.addEventListener('scroll', hideCtxMenu);

    cy.on('cxttap', 'node', function(e) {
      e.originalEvent.preventDefault();
      var node = e.target;
      var d = node.data();
      var t = d.type || '';
      var items = [];

      // Focus neighborhood
      items.push({icon:'&#x1f50d;',label:'Focus neighborhood',action:function(){
        cy.elements().removeClass('faded highlighted');
        var hood = node.closedNeighborhood();
        cy.elements().not(hood).addClass('faded');
        node.addClass('highlighted');
        showSidebar(node);
      }});
      // Fit to node
      items.push({icon:'&#x1f4cd;',label:'Zoom to node',action:function(){
        cy.animate({ fit: { eles: node.closedNeighborhood(), padding: 80 }, duration: 400 });
      }});
      // Highlight path to root
      items.push({icon:'&#x2b06;',label:'Trace to root',action:function(){
        cy.elements().removeClass('faded highlighted');
        var path = node.predecessors().union(node);
        cy.elements().not(path).addClass('faded');
        path.nodes().addClass('highlighted');
      }});
      // Highlight downstream
      items.push({icon:'&#x2b07;',label:'Show downstream impact',action:function(){
        cy.elements().removeClass('faded highlighted');
        var downstream = node.successors().union(node);
        cy.elements().not(downstream).addClass('faded');
        downstream.nodes().addClass('highlighted');
      }});

      // Vulnerability node: open in OSV
      if (t === 'cve' || t.indexOf('cve_')===0) {
        var vid = d.label || '';
        items.push({sep:true});
        items.push({icon:'&#x1f517;',label:'Open in OSV',action:function(){
          window.open('https://osv.dev/vulnerability/'+vid, '_blank');
        }});
        items.push({icon:'&#x1f517;',label:'Open in NVD',action:function(){
          window.open('https://nvd.nist.gov/vuln/detail/'+vid, '_blank');
        }});
      }

      // Build menu HTML
      ctxMenu.innerHTML = '';
      items.forEach(function(item) {
        if (item.sep) {
          var sep = document.createElement('div');
          sep.className = 'cy-ctx-sep';
          ctxMenu.appendChild(sep);
        } else {
          var el = document.createElement('div');
          el.className = 'cy-ctx-item';
          el.innerHTML = '<span>'+item.icon+'</span> '+item.label;
          el.addEventListener('click', function(ev) {
            ev.stopPropagation();
            hideCtxMenu();
            item.action();
          });
          ctxMenu.appendChild(el);
        }
      });

      var cx = e.originalEvent.clientX, cy2 = e.originalEvent.clientY;
      ctxMenu.style.left = cx + 'px';
      ctxMenu.style.top = cy2 + 'px';
      ctxMenu.classList.add('show');
    });

    // Minimap — render a small overview of the full graph
    var minimapEl = document.createElement('div');
    minimapEl.className = 'cy-minimap';
    cyContainer.parentNode.appendChild(minimapEl);
    var mmCanvas = document.createElement('canvas');
    mmCanvas.width = 180; mmCanvas.height = 130;
    minimapEl.appendChild(mmCanvas);

    function drawMinimap() {
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
      cy.edges().forEach(function(edge) {
        var sp = edge.sourceEndpoint(), tp = edge.targetEndpoint();
        ctx2d.beginPath();
        ctx2d.moveTo(sp.x * sc + offX, sp.y * sc + offY);
        ctx2d.lineTo(tp.x * sc + offX, tp.y * sc + offY);
        ctx2d.stroke();
      });

      // Draw nodes
      cy.nodes().forEach(function(n) {
        var pos = n.position(); var t = n.data('type') || '';
        var colors = {'provider':'#818cf8','agent':'#3b82f6','server_clean':'#10b981','server_cred':'#f59e0b','server_vuln':'#ef4444','pkg_vuln':'#dc2626'};
        ctx2d.fillStyle = colors[t] || (t === 'cve' || t.indexOf('cve_')===0 ? '#f87171' : '#64748b');
        var nx = pos.x * sc + offX, ny = pos.y * sc + offY;
        ctx2d.beginPath();
        if (t === 'cve' || t.indexOf('cve_')===0) {
          // Diamond
          ctx2d.moveTo(nx, ny - 4); ctx2d.lineTo(nx + 5, ny); ctx2d.lineTo(nx, ny + 4); ctx2d.lineTo(nx - 5, ny);
        } else {
          ctx2d.arc(nx, ny, 3, 0, Math.PI * 2);
        }
        ctx2d.fill();
      });

      // Viewport rectangle
      var ext = cy.extent();
      ctx2d.strokeStyle = '#60a5fa'; ctx2d.lineWidth = 1.5;
      ctx2d.strokeRect(ext.x1 * sc + offX, ext.y1 * sc + offY, ext.w * sc, ext.h * sc);
    }

    cy.on('render viewport', drawMinimap);
    setTimeout(drawMinimap, 500);

    // Click minimap to pan
    mmCanvas.addEventListener('click', function(e) {
      var rect = mmCanvas.getBoundingClientRect();
      var mx = e.clientX - rect.left, my = e.clientY - rect.top;
      var bb = cy.elements().boundingBox();
      if (!bb || bb.w === 0) return;
      var scaleX = 170 / bb.w, scaleY = 120 / bb.h;
      var sc = Math.min(scaleX, scaleY);
      var offX = (180 - bb.w * sc) / 2 - bb.x1 * sc;
      var offY = (130 - bb.h * sc) / 2 - bb.y1 * sc;
      var targetX = (mx - offX) / sc, targetY = (my - offY) / sc;
      cy.animate({ center: { x: targetX, y: targetY }, duration: 300 });
    });

    // Node statistics overlay
    var nodeStats = document.createElement('div');
    nodeStats.style.cssText = 'position:absolute;bottom:12px;right:12px;background:rgba(15,23,42,.9);border:1px solid #334155;border-radius:8px;padding:8px 14px;font-size:.72rem;color:#64748b;z-index:10;backdrop-filter:blur(8px)';
    var nodeCounts = {};
    cy.nodes().forEach(function(n) {
      var t = n.data('type') || 'other';
      if (t === 'cve' || t.indexOf('cve_')===0) t = 'cve';
      else if (t.indexOf('server_')===0) t = 'server';
      nodeCounts[t] = (nodeCounts[t] || 0) + 1;
    });
    var statsHTML = [];
    if (nodeCounts.agent) statsHTML.push('<span style="color:#3b82f6">' + nodeCounts.agent + ' agents</span>');
    if (nodeCounts.server) statsHTML.push('<span style="color:#10b981">' + nodeCounts.server + ' servers</span>');
    if (nodeCounts.pkg_vuln) statsHTML.push('<span style="color:#dc2626">' + nodeCounts.pkg_vuln + ' packages</span>');
    if (nodeCounts.cve) statsHTML.push('<span style="color:#f87171">' + nodeCounts.cve + ' CVEs</span>');
    nodeStats.innerHTML = statsHTML.join(' &middot; ');
    cyContainer.parentNode.appendChild(nodeStats);

  } else if (cyContainer) {
    cyContainer.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;color:#4ade80;font-size:.9rem">&#x2705; No supply chain nodes to display</div>';
  }

  // Findings-table pagination, filtering, and tabs live in the standalone
  // scale-report script (below) so they keep working even if the CDN chart /
  // graph libraries fail to load — the common case for an offline or emailed
  // report. Nothing table/tab related runs here.

"""
