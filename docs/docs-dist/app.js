document.addEventListener('DOMContentLoaded', () => {
  // --------------------------------------------------------------------------
  // 1. Interactive Multi-Agent Network Visualizer
  // --------------------------------------------------------------------------
  const agentDetails = {
    orchestrator: {
      title: "Orchestrator (Manager Agent)",
      model: "gemini-3.1-pro-preview",
      role: "Central entry point. Triages incoming alerts, coordinates complex investigations, and delegates tasks to remote specialists via gRPC.",
      tools: ["Chronicle SOAR Playbooks", "Security Command Center", "Neo4j Graph Queries", "Elasticsearch Grounding (3,405 runbooks)"],
      targets: ["cti", "hunter", "engineer", "tier2"]
    },
    cti: {
      title: "CTI Researcher Specialist",
      model: "gemini-2.5-flash",
      role: "Threat intelligence specialist. Researches threat actors, profiles campaigns, and analyzes malware families dynamically.",
      tools: ["Google Threat Intelligence (VirusTotal API)", "Vertex AI RAG Search"],
      targets: ["orchestrator"]
    },
    hunter: {
      title: "Threat Hunter Specialist",
      model: "gemini-2.5-pro",
      role: "Proactive threat hunter. Scans Chronicle UDM logs for IOCs/TTPs, builds entity timelines, and queries relationships in Neo4j.",
      tools: ["Chronicle UDM Search", "Neo4j Graph traversals", "Threat Intel Caching"],
      targets: ["orchestrator", "cti"]
    },
    engineer: {
      title: "Detection Engineer Specialist",
      model: "gemini-2.5-pro",
      role: "Detection lifecycle manager. Translates discovered threat timelines and TTPs directly into YARA-L SIEM detection rules and validates rules against telemetry.",
      tools: ["Chronicle Rules Engine", "YARA-L Rule Validators"],
      targets: ["orchestrator"]
    },
    tier2: {
      title: "Tier 2 Responder Specialist",
      model: "gemini-2.5-pro",
      role: "Incident responder. Executes containment playbooks, isolates compromised hosts, blocks domains, and coordinates mitigation.",
      tools: ["Chronicle SOAR Playbooks", "Endpoint Isolation API", "Manual Actions"],
      targets: ["orchestrator"]
    }
  };

  const nodes = document.querySelectorAll('.agent-node');
  const links = document.querySelectorAll('.agent-link');
  const infoTitle = document.getElementById('visualizer-info-title');
  const infoModel = document.getElementById('visualizer-info-model');
  const infoRole = document.getElementById('visualizer-info-role');
  const infoTools = document.getElementById('visualizer-info-tools');

  function updateVisualizer(agentId) {
    const data = agentDetails[agentId];
    if (!data) return;

    // Update info pane text
    infoTitle.textContent = data.title;
    infoModel.textContent = `Model: ${data.model}`;
    infoRole.textContent = data.role;

    // Clear and build tools list
    infoTools.innerHTML = '';
    data.tools.forEach(tool => {
      const li = document.createElement('li');
      li.textContent = tool;
      infoTools.appendChild(li);
    });

    // Highlight node circles and links in the SVG
    nodes.forEach(node => {
      const isCurrent = node.getAttribute('data-agent') === agentId;
      node.querySelector('circle').setAttribute('stroke', isCurrent ? 'var(--accent-cyan)' : 'var(--border-glass)');
      node.querySelector('circle').setAttribute('stroke-width', isCurrent ? '3px' : '1.5px');
    });

    links.forEach(link => {
      const source = link.getAttribute('data-source');
      const target = link.getAttribute('data-target');
      const isActive = (source === agentId && data.targets.includes(target)) ||
                       (target === agentId && agentDetails[target].targets.includes(source));

      if (isActive) {
        link.classList.add('active');
      } else {
        link.classList.remove('active');
      }
    });
  }

  // Add click/hover event listeners to nodes
  nodes.forEach(node => {
    const agentId = node.getAttribute('data-agent');
    node.addEventListener('mouseenter', () => updateVisualizer(agentId));
    node.addEventListener('click', (e) => {
      e.preventDefault();
      updateVisualizer(agentId);
    });
  });

  // Initialize with Orchestrator Details
  updateVisualizer('orchestrator');


  // --------------------------------------------------------------------------
  // 2. Search-Hidden-Content (beforematch & tab switcher)
  // --------------------------------------------------------------------------
  const tabContainers = document.querySelectorAll('.code-tab-container');

  tabContainers.forEach(container => {
    const tabButtons = container.querySelectorAll('.code-tab-btn');
    const tabPanels = container.querySelectorAll('.code-tab-panel');

    function switchTab(targetPanelId) {
      tabButtons.forEach(btn => {
        const controls = btn.getAttribute('aria-controls');
        const isSelected = controls === targetPanelId;
        btn.setAttribute('aria-selected', isSelected ? 'true' : 'false');
      });

      tabPanels.forEach(panel => {
        if (panel.id === targetPanelId) {
          // Show matched panel
          panel.removeAttribute('hidden');
        } else {
          // Hide others
          panel.hidden = 'until-found';
        }
      });
    }

    // Tapping on a tab button directly
    tabButtons.forEach(btn => {
      btn.addEventListener('click', () => {
        const panelId = btn.getAttribute('aria-controls');
        switchTab(panelId);
      });
    });

    // CRITICAL: beforematch event delegation
    container.addEventListener('beforematch', (e) => {
      const matchedPanel = e.target.closest('.code-tab-panel');
      if (matchedPanel) {
        switchTab(matchedPanel.id);
      }
    });
  });

  // Fallback for browsers that do NOT support hidden="until-found" (beforematch)
  if (!('onbeforematch' in HTMLElement.prototype)) {
    document.querySelectorAll('.code-tab-panel[hidden="until-found"]').forEach(panel => {
      panel.removeAttribute('hidden');
    });
  }


  // --------------------------------------------------------------------------
  // 3. Scroll-Spy (Intersection Observer for Active Navigation)
  // --------------------------------------------------------------------------
  const sections = document.querySelectorAll('.doc-section');
  const navItems = document.querySelectorAll('.nav-item');

  const observerOptions = {
    root: null,
    rootMargin: '-20% 0px -60% 0px',
    threshold: 0
  };

  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const id = entry.target.getAttribute('id');
        navItems.forEach(item => {
          const href = item.querySelector('a').getAttribute('href').substring(1);
          if (href === id) {
            item.classList.add('active');
          } else {
            item.classList.remove('active');
          }
        });
      }
    });
  }, observerOptions);

  sections.forEach(section => observer.observe(section));


  // --------------------------------------------------------------------------
  // 4. Sidebar Search / Filter
  // --------------------------------------------------------------------------
  const searchInput = document.getElementById('sidebar-search-input');

  if (searchInput) {
    searchInput.addEventListener('input', (e) => {
      const query = e.target.value.toLowerCase().trim();
      navItems.forEach(item => {
        const text = item.querySelector('a').textContent.toLowerCase();
        if (text.includes(query)) {
          item.style.display = 'block';
        } else {
          item.style.display = 'none';
        }
      });

      // Filter groups
      const groups = document.querySelectorAll('.nav-group');
      groups.forEach(group => {
        const visibleItems = group.querySelectorAll('.nav-item[style="display: block;"]').length ||
                             group.querySelectorAll('.nav-item:not([style])').length;
        const title = group.querySelector('.nav-title');
        if (visibleItems === 0) {
          title.style.display = 'none';
        } else {
          title.style.display = 'block';
        }
      });
    });
  }
});
