export const adminHtml = `<!DOCTYPE html>
<html lang="en" class="h-full">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Packablock supply chain registry</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;900&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/d3@7"></script>
    <style>
        :root {
            --bg-base: #0b0f19;
            --bg-surface: #111827;
            --bg-card: #1f2937;
            --border-muted: #374151;
            --text-main: #f9fafb;
            --text-muted: #9ca3af;
            --accent-green: #10b981;
            --accent-green-glow: rgba(16, 185, 129, 0.15);
            --accent-red: #ef4444;
            --accent-red-glow: rgba(239, 68, 68, 0.15);
            --accent-amber: #f59e0b;
            --accent-amber-glow: rgba(245, 158, 11, 0.15);
            --accent-purple: #8b5cf6;
            --accent-purple-glow: rgba(139, 92, 246, 0.15);
            --accent-cyan: #06b6d4;
            --glass-bg: rgba(17, 24, 39, 0.7);
            --header-bg: rgba(11, 15, 25, 0.8);
        }

        :root[data-theme="light"] {
            --bg-base: #f3f4f6;
            --bg-surface: #ffffff;
            --bg-card: #f9fafb;
            --border-muted: #e5e7eb;
            --text-main: #111827;
            --text-muted: #4b5563;
            --accent-green-glow: rgba(16, 185, 129, 0.1);
            --accent-red-glow: rgba(239, 68, 68, 0.1);
            --accent-amber-glow: rgba(245, 158, 11, 0.1);
            --accent-purple-glow: rgba(139, 92, 246, 0.1);
            --glass-bg: rgba(255, 255, 255, 0.75);
            --header-bg: rgba(243, 244, 246, 0.85);
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            background-color: var(--bg-base);
            color: var(--text-main);
            font-family: 'Inter', sans-serif;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            overflow-x: hidden;
            transition: background-color 0.3s ease, color 0.3s ease;
        }

        code, pre, .mono {
            font-family: 'JetBrains Mono', monospace;
        }

        /* Glassmorphism utility */
        .glass-panel {
            background: var(--glass-bg);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border: 1px solid var(--border-muted);
            border-radius: 12px;
            transition: background 0.3s ease, border-color 0.3s ease;
        }

        /* Animation utilities */
        .pulse-green {
            animation: pulse-green-glow 2s infinite alternate;
        }
        @keyframes pulse-green-glow {
            0% { box-shadow: 0 0 5px rgba(16, 185, 129, 0.2); }
            100% { box-shadow: 0 0 20px rgba(16, 185, 129, 0.6); }
        }

        .pulse-green-circle {
            animation: pulse-green-circle-glow 2s infinite alternate;
        }
        @keyframes pulse-green-circle-glow {
            0% { stroke-width: 2px; stroke: rgba(16, 185, 129, 0.7); }
            100% { stroke-width: 5px; stroke: rgba(16, 185, 129, 1); }
        }

        .pulse-red {
            animation: pulse-red-glow 2s infinite alternate;
        }
        @keyframes pulse-red-glow {
            0% { box-shadow: 0 0 5px rgba(239, 68, 68, 0.2); }
            100% { box-shadow: 0 0 20px rgba(239, 68, 68, 0.6); }
        }

        .slide-in {
            animation: slide-in-frames 0.3s cubic-bezier(0.16, 1, 0.3, 1) forwards;
        }
        @keyframes slide-in-frames {
            0% { transform: translateY(10px); opacity: 0; }
            100% { transform: translateY(0); opacity: 1; }
        }

        /* Layout styles */
        header {
            border-bottom: 1px solid var(--border-muted);
            padding: 1rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: var(--header-bg);
            backdrop-filter: blur(8px);
            position: sticky;
            top: 0;
            z-index: 50;
            transition: background 0.3s ease, border-color 0.3s ease;
        }

        .logo {
            font-size: 1.25rem;
            font-weight: 900;
            letter-spacing: -0.025em;
            text-transform: uppercase;
            color: var(--text-main);
            display: flex;
            align-items: center;
            gap: 0.5rem;
            text-decoration: none;
        }

        .logo-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background-color: var(--accent-green);
            display: inline-block;
        }

        .nav-links {
            display: flex;
            gap: 1.5rem;
        }

        .nav-btn {
            background: transparent;
            border: none;
            color: var(--text-muted);
            font-size: 0.875rem;
            font-weight: 500;
            cursor: pointer;
            padding: 0.5rem 0.75rem;
            border-radius: 6px;
            transition: all 0.2s ease;
            text-decoration: none;
        }

        .nav-btn:hover, .nav-btn.active {
            color: var(--text-main);
            background-color: var(--bg-card);
        }

        main {
            flex: 1;
            padding: 2rem;
            max-width: 1400px;
            width: 100%;
            margin: 0 auto;
            display: flex;
            flex-direction: column;
            gap: 2rem;
        }

        /* Cards & Buttons */
        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            padding: 0.625rem 1.25rem;
            font-size: 0.875rem;
            font-weight: 600;
            border-radius: 8px;
            border: none;
            cursor: pointer;
            transition: all 0.2s ease;
            text-decoration: none;
            gap: 0.5rem;
        }

        .btn-primary {
            background-color: var(--accent-green);
            color: #000;
        }
        .btn-primary:hover {
            opacity: 0.9;
            box-shadow: 0 0 15px var(--accent-green-glow);
        }

        .btn-secondary {
            background-color: var(--bg-card);
            color: var(--text-main);
            border: 1px solid var(--border-muted);
        }
        .btn-secondary:hover {
            background-color: var(--border-muted);
        }

        .btn-danger {
            background-color: rgba(239, 68, 68, 0.1);
            color: var(--accent-red);
            border: 1px solid rgba(239, 68, 68, 0.3);
        }
        .btn-danger:hover {
            background-color: var(--accent-red);
            color: #000;
            box-shadow: 0 0 15px var(--accent-red-glow);
        }

        /* Login panel */
        .login-container {
            max-width: 450px;
            width: 100%;
            margin: 10vh auto;
            padding: 2.5rem;
            display: flex;
            flex-direction: column;
            gap: 1.5rem;
        }

        .input-group {
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }

        .input-group label {
            font-size: 0.875rem;
            font-weight: 500;
            color: var(--text-muted);
        }

        .input-field {
            background-color: var(--bg-base);
            border: 1px solid var(--border-muted);
            border-radius: 8px;
            padding: 0.75rem 1rem;
            color: var(--text-main);
            font-family: inherit;
            font-size: 0.9375rem;
            outline: none;
            transition: border 0.2s ease;
        }

        .input-field:focus {
            border-color: var(--accent-green);
        }

        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1.5rem;
        }

        .stat-card {
            padding: 1.5rem;
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }

        .stat-val {
            font-size: 2rem;
            font-weight: 800;
            letter-spacing: -0.025em;
        }

        .stat-lbl {
            font-size: 0.8125rem;
            color: var(--text-muted);
            text-transform: uppercase;
            font-weight: 600;
            letter-spacing: 0.05em;
        }

        /* Project / Card Feed */
        .card-list {
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }

        .list-card {
            padding: 1.5rem;
            display: flex;
            flex-direction: column;
            gap: 1.25rem;
            transition: border-color 0.2s ease;
        }

        .list-card:hover {
            border-color: var(--text-muted);
        }

        .card-header-row {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            flex-wrap: wrap;
            gap: 1rem;
        }

        .card-title-group {
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }

        .badge {
            font-size: 0.75rem;
            font-weight: 700;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            text-transform: uppercase;
            letter-spacing: 0.025em;
            display: inline-flex;
            align-items: center;
            gap: 0.25rem;
        }

        .badge-green { background-color: rgba(16, 185, 129, 0.1); color: var(--accent-green); border: 1px solid rgba(16, 185, 129, 0.2); }
        .badge-red { background-color: rgba(239, 68, 68, 0.1); color: var(--accent-red); border: 1px solid rgba(239, 68, 68, 0.2); }
        .badge-amber { background-color: rgba(245, 158, 11, 0.1); color: var(--accent-amber); border: 1px solid rgba(245, 158, 11, 0.2); }
        .badge-purple { background-color: rgba(139, 92, 246, 0.1); color: var(--accent-purple); border: 1px solid rgba(139, 92, 246, 0.2); }

        .timeline-container {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            overflow-x: auto;
            padding: 0.5rem 0;
        }

        .block-node {
            width: 36px;
            height: 36px;
            border-radius: 8px;
            border: 1px solid var(--border-muted);
            background-color: var(--bg-base);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.75rem;
            font-weight: bold;
            cursor: pointer;
            transition: all 0.2s ease;
            position: relative;
            flex-shrink: 0;
        }

        .block-node:hover {
            border-color: var(--text-main);
            transform: scale(1.1);
        }

        .block-node.verified { border-color: var(--accent-green); color: var(--accent-green); background-color: rgba(16, 185, 129, 0.05); }
        .block-node.tampered { border-color: var(--accent-red); color: var(--accent-red); background-color: rgba(239, 68, 68, 0.05); }

        .timeline-connector {
            height: 2px;
            width: 20px;
            background-color: var(--border-muted);
            flex-shrink: 0;
        }
        .timeline-connector.rollover {
            border-top: 2px dashed var(--accent-amber);
            border-bottom: 2px dashed var(--accent-amber);
            height: 4px;
            width: 24px;
            background-color: transparent;
        }

        /* Modal Overlay */
        .modal-overlay {
            position: fixed;
            inset: 0;
            background-color: rgba(0, 0, 0, 0.75);
            backdrop-filter: blur(4px);
            z-index: 100;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 1.5rem;
            opacity: 0;
            pointer-events: none;
            transition: opacity 0.2s ease;
        }

        .modal-overlay.open {
            opacity: 1;
            pointer-events: auto;
        }

        .modal-panel {
            max-width: 600px;
            width: 100%;
            padding: 2rem;
            display: flex;
            flex-direction: column;
            gap: 1.5rem;
            transform: scale(0.95);
            transition: transform 0.2s cubic-bezier(0.16, 1, 0.3, 1);
        }

        .modal-overlay.open .modal-panel {
            transform: scale(1);
        }

        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        /* Drill-down payload layout */
        .payload-pre {
            background-color: var(--bg-base);
            padding: 1rem;
            border-radius: 8px;
            border: 1px solid var(--border-muted);
            overflow-x: auto;
            font-size: 0.8125rem;
            color: #34d399;
            max-height: 400px;
        }

        .search-row {
            display: flex;
            gap: 1rem;
            align-items: center;
            flex-wrap: wrap;
        }

        .search-field {
            flex: 1;
            min-width: 250px;
        }

        /* Member linking list */
        .link-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0.75rem 1rem;
            border-radius: 8px;
            background-color: rgba(255, 255, 255, 0.02);
            border: 1px solid var(--border-muted);
        }

        /* User Context Dropdown */
        .dropdown {
            position: relative;
            display: inline-block;
        }

        .dropdown-content {
            display: none;
            position: absolute;
            right: 0;
            top: 100%;
            margin-top: 0.5rem;
            min-width: 280px;
            padding: 1.25rem;
            z-index: 100;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5);
        }

        .dropdown.show .dropdown-content {
            display: block;
        }

        .user-details-list {
            list-style: none;
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
            font-size: 0.8125rem;
        }

        .user-details-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-muted);
            padding-bottom: 0.5rem;
        }

        .user-details-item:last-child {
            border-bottom: none;
            padding-bottom: 0;
        }

        .user-details-label {
            color: var(--text-muted);
            font-weight: 500;
        }

        .user-details-value {
            color: var(--text-main);
            font-weight: 600;
        }
    </style>
</head>
<body class="h-full">

    <header id="header-panel" style="display: none;">
        <a href="#" onclick="showPage('projects')" class="logo">
            <span class="logo-dot"></span>
            Packablock <span class="mono" style="color: var(--accent-green); font-size: 0.9rem;">[registry]</span>
        </a>
        <div class="nav-links" style="display: flex; align-items: center; gap: 0.75rem;">
            <button id="nav-projects" onclick="showPage('projects')" class="nav-btn active">My Projects</button>
            <button onclick="toggleTheme()" class="nav-btn" style="display: inline-flex; align-items: center; gap: 0.25rem;">
                <span id="theme-icon">☀️</span> <span id="theme-text">Light Mode</span>
            </button>

            <!-- User Context Dropdown -->
            <div id="user-dropdown" class="dropdown">
                <button onclick="toggleUserDropdown(event)" class="nav-btn" style="display: inline-flex; align-items: center; gap: 0.375rem; border: 1px solid var(--border-muted); border-radius: 8px; padding: 0.375rem 0.75rem; background-color: rgba(255,255,255,0.02);">
                    <span style="font-size: 0.95rem;">👤</span>
                    <span style="font-weight: 600;">Admin</span>
                    <span style="font-size: 0.65rem; opacity: 0.7;">▼</span>
                </button>
                <div class="dropdown-content" style="margin-top: 0.75rem; background-color: var(--bg-surface); border: 1px solid var(--border-muted); border-radius: 12px;">
                    <div style="font-size: 0.75rem; font-weight: 700; text-transform: uppercase; color: var(--accent-green); margin-bottom: 0.75rem; letter-spacing: 0.05em; display: flex; align-items: center; gap: 0.375rem;">
                        <span class="pulse-green" style="width: 6px; height: 6px; border-radius: 50%; background-color: var(--accent-green); display: inline-block;"></span>
                        Active Session Status
                    </div>
                    <ul class="user-details-list">
                        <li class="user-details-item">
                            <span class="user-details-label">Identity</span>
                            <span class="user-details-value">System Admin</span>
                        </li>
                        <li class="user-details-item">
                            <span class="user-details-label">Role Privilege</span>
                            <span class="user-details-value" style="color: var(--accent-purple);">Root / Owner</span>
                        </li>
                        <li class="user-details-item">
                            <span class="user-details-label">Session Token</span>
                            <span id="dropdown-user-token" class="user-details-value mono" style="font-size: 0.75rem;">N/A</span>
                        </li>
                        <li class="user-details-item">
                            <span class="user-details-label">Registry Engine</span>
                            <span class="user-details-value">SQLite + Fastify</span>
                        </li>
                    </ul>
                </div>
            </div>

            <button onclick="logout()" class="nav-btn">Sign Out</button>
        </div>
    </header>

    <main id="app-viewport">
        <!-- Loader / Landing -->
        <div id="loading-view" style="display: flex; justify-content: center; align-items: center; min-height: 50vh;">
            <div class="mono" style="color: var(--accent-green);">Loading registry portal...</div>
        </div>

        <!-- Auth View -->
        <div id="auth-view" class="glass-panel login-container slide-in" style="display: none;">
            <div>
                <h2 style="font-size: 1.5rem; font-weight: 800; letter-spacing: -0.025em; margin-bottom: 0.25rem;">Administrator Login</h2>
                <p style="font-size: 0.875rem; color: var(--text-muted);">Enter token to access supply chain workspace.</p>
            </div>
            <div id="auth-error" class="mono" style="color: var(--accent-red); font-size: 0.8125rem; display: none;"></div>
            <div class="input-group">
                <label for="admin-token">Superuser Access Token</label>
                <input type="password" id="admin-token" class="input-field" placeholder="Enter ADMIN_TOKEN">
            </div>
            <button onclick="login()" class="btn btn-primary">Authenticate Session</button>
        </div>

        <!-- My Projects Hub -->
        <div id="projects-page" class="slide-in" style="display: none; flex-direction: column; gap: 2rem;">
            <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem;">
                <div>
                    <h1 style="font-size: 2rem; font-weight: 900; letter-spacing: -0.025em;">My Projects</h1>
                    <p style="font-size: 0.9375rem; color: var(--text-muted);">Organize and monitor cryptographic ledgers grouped by environment.</p>
                </div>
                <button onclick="openModal('create-project-modal')" class="btn btn-primary">+ Create New Project</button>
            </div>

            <div class="stats-grid">
                <div class="glass-panel stat-card">
                    <span class="stat-lbl">Active Projects</span>
                    <span id="stat-projects-count" class="stat-val">0</span>
                </div>
                <div class="glass-panel stat-card">
                    <span class="stat-lbl">Tracked Repositories</span>
                    <span id="stat-repos-count" class="stat-val">0</span>
                </div>
                <div class="glass-panel stat-card">
                    <span class="stat-lbl">Security Status</span>
                    <span id="stat-status" class="stat-val" style="color: var(--accent-green);">Secured</span>
                </div>
            </div>

            <div id="projects-list" class="card-list">
                <!-- Projects injected here -->
            </div>
        </div>

        <!-- Project Dashboard -->
        <div id="project-dashboard-page" class="slide-in" style="display: none; flex-direction: column; gap: 2rem;">
            <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 1rem;">
                <div>
                    <div style="display: flex; align-items: center; gap: 0.5rem; color: var(--text-muted); font-size: 0.875rem;">
                        <a href="#" onclick="showPage('projects')" style="color: inherit; text-decoration: none;">Projects</a>
                        <span>/</span>
                        <span id="breadcrumb-project-name" style="color: var(--text-main);">Project Name</span>
                    </div>
                    <h1 id="project-title" style="font-size: 2rem; font-weight: 900; letter-spacing: -0.025em; margin-top: 0.25rem;">Project Dashboard</h1>
                </div>
                <div style="display: flex; gap: 0.75rem;">
                    <button onclick="showProjectView('checks')" id="tab-btn-checks" class="btn btn-secondary btn-primary">Checks</button>
                    <button onclick="showProjectView('integrations')" id="tab-btn-integrations" class="btn btn-secondary">Integrations Audit</button>
                    <button onclick="openLinkRepoModal()" class="btn btn-primary">+ Link Repository</button>
                </div>
            </div>

            <!-- Dashboard VIEW 1: CHECKS -->
            <div id="project-view-checks" class="flex-direction: column; gap: 1.5rem;" style="display: flex;">
                <div class="search-row">
                    <input type="text" id="checks-search" class="input-field search-field" placeholder="Filter repositories..." oninput="renderChecks()">
                </div>
                <div id="checks-list" class="card-list">
                    <!-- Check cards injected here -->
                </div>
            </div>

            <!-- Dashboard VIEW 2: INTEGRATIONS -->
            <div id="project-view-integrations" class="flex-direction: column; gap: 1.5rem;" style="display: none;">
                <div>
                    <h3 style="font-size: 1.25rem; font-weight: 700; margin-bottom: 0.25rem;">Client Integration Events</h3>
                    <p style="font-size: 0.875rem; color: var(--text-muted);">Auditing active OIDC runners, developer environments, CLI versioning, and client IPs.</p>
                </div>
                <div class="glass-panel" style="overflow-x: auto; border-radius: 12px;">
                    <table style="width: 100%; border-collapse: collapse; text-align: left; font-size: 0.875rem;">
                        <thead>
                            <tr style="border-bottom: 1px solid var(--border-muted); background-color: rgba(255,255,255,0.01);">
                                <th style="padding: 1rem;">Repository</th>
                                <th style="padding: 1rem;">Client / Version</th>
                                <th style="padding: 1rem;">Platform</th>
                                <th style="padding: 1rem;">Environment</th>
                                <th style="padding: 1rem;">Actor</th>
                                <th style="padding: 1rem;">Client IP</th>
                                <th style="padding: 1rem;">Synchronized At</th>
                            </tr>
                        </thead>
                        <tbody id="integrations-table-body">
                            <!-- Integration rows injected here -->
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- Repository Details / Drilldown -->
        <div id="repo-drilldown-page" class="slide-in" style="display: none; flex-direction: column; gap: 2rem;">
            <div>
                <div style="display: flex; align-items: center; gap: 0.5rem; color: var(--text-muted); font-size: 0.875rem;">
                    <a href="#" onclick="showPage('projects')" style="color: inherit; text-decoration: none;">Projects</a>
                    <span>/</span>
                    <a href="#" id="repo-project-breadcrumb" style="color: inherit; text-decoration: none;">Project</a>
                    <span>/</span>
                    <span id="breadcrumb-repo-path" style="color: var(--text-main);">owner/repo</span>
                </div>
                <h1 id="drilldown-repo-title" style="font-size: 2rem; font-weight: 900; letter-spacing: -0.025em; margin-top: 0.25rem;">Repository Drill-down</h1>
            </div>

            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1.5rem;">
                <!-- Left: Access controls and signatures -->
                <div class="glass-panel" style="padding: 2rem; display: flex; flex-direction: column; gap: 1.5rem;">
                    <div>
                        <h3 style="font-size: 1.125rem; font-weight: 700; margin-bottom: 0.5rem;">Credential Management</h3>
                        <p style="font-size: 0.8125rem; color: var(--text-muted);">Manage zero-trust push access configurations and key pins.</p>
                    </div>

                    <div class="input-group">
                        <label>Active Registration Token</label>
                        <div style="display: flex; gap: 0.5rem;">
                            <input type="text" id="drilldown-token" class="input-field mono" style="flex: 1; background-color: var(--bg-base);" readonly>
                            <button onclick="copyTokenText()" class="btn btn-secondary">Copy</button>
                        </div>
                    </div>

                    <div style="display: flex; justify-content: space-between; align-items: center; padding-top: 0.5rem;">
                        <span style="font-size: 0.9rem; font-weight: 600;">Access Level:</span>
                        <span id="drilldown-tier-badge" class="badge">STANDARD</span>
                    </div>

                    <div style="display: flex; flex-direction: column; gap: 0.75rem; border-top: 1px solid var(--border-muted); padding-top: 1.25rem;">
                        <button id="btn-toggle-tier" class="btn btn-secondary" style="width: 100%;">Toggle Premium Tier</button>
                        <button id="btn-revoke-token" class="btn btn-danger" style="width: 100%;">Revoke push token</button>
                    </div>
                </div>

                <!-- Right: Cryptographic Pinning details -->
                <div class="glass-panel" style="padding: 2rem; display: flex; flex-direction: column; gap: 1.5rem;">
                    <div>
                        <h3 style="font-size: 1.125rem; font-weight: 700; margin-bottom: 0.5rem;">Cryptographic Trust Anchor</h3>
                        <p style="font-size: 0.8125rem; color: var(--text-muted);">Pinned public identity credentials used during signature challenges.</p>
                    </div>

                    <div class="input-group">
                        <label>Verification Status</label>
                        <div>
                            <span id="drilldown-verification-badge" class="badge">none</span>
                        </div>
                    </div>

                    <div class="input-group">
                        <label>Challenge Nonce</label>
                        <input type="text" id="drilldown-nonce" class="input-field mono" style="background-color: var(--bg-base);" readonly>
                    </div>

                    <div class="input-group">
                        <label>Pinned Identity Credentials / Key Signature</label>
                        <textarea id="drilldown-public-key" class="input-field mono" style="height: 120px; font-size: 0.75rem; resize: none; background-color: var(--bg-base);" readonly></textarea>
                    </div>
                </div>
            </div>

            <!-- Bottom: Ledger timeline and archives -->
            <div class="glass-panel" style="padding: 2rem; display: flex; flex-direction: column; gap: 1.5rem;">
                <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem;">
                    <div>
                        <h3 style="font-size: 1.25rem; font-weight: 700; margin-bottom: 0.25rem;">Cryptographic Ledger Audit Trail</h3>
                        <p style="font-size: 0.875rem; color: var(--text-muted);">Drill into individual blocks of the anchoring validation chain.</p>
                    </div>
                    <div style="display: flex; gap: 0.5rem; background-color: var(--bg-base); padding: 0.25rem; border-radius: 8px; border: 1px solid var(--border-muted);">
                        <button onclick="toggleLedgerView('timeline')" id="ledger-tab-timeline" class="btn btn-secondary btn-primary" style="padding: 0.4rem 0.8rem; font-size: 0.8125rem;">Timeline</button>
                        <button onclick="toggleLedgerView('tree')" id="ledger-tab-tree" class="btn btn-secondary" style="padding: 0.4rem 0.8rem; font-size: 0.8125rem;">Trust Tree</button>
                    </div>
                </div>

                <div id="drilldown-timeline-view" style="display: block;">
                    <div id="drilldown-timeline" class="timeline-container">
                        <!-- Detailed nodes list injected here -->
                    </div>
                </div>

                <div id="drilldown-tree-view" style="display: none;">
                    <div id="tree-canvas-container" class="glass-panel" style="background-color: var(--bg-surface); height: 500px; border-radius: 8px; overflow: hidden; border: 1px solid var(--border-muted); position: relative;">
                        <svg id="tree-svg" style="width: 100%; height: 100%; cursor: grab;"></svg>
                        <div id="tree-tooltip" class="glass-panel" style="position: absolute; display: none; background-color: var(--bg-card); border: 1px solid var(--border-muted); border-radius: 8px; padding: 1rem; pointer-events: none; z-index: 10; font-size: 0.8125rem; max-width: 320px; box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.5); color: var(--text-main);"></div>
                    </div>
                </div>

                <div id="drilldown-archives-section" style="display: none; flex-direction: column; gap: 1rem; border-top: 1px solid var(--border-muted); padding-top: 1.5rem;">
                    <h4 style="font-size: 1rem; font-weight: 700;">Rotated Legacy Cold Archives</h4>
                    <div class="glass-panel" style="overflow-x: auto;">
                        <table style="width: 100%; border-collapse: collapse; text-align: left; font-size: 0.875rem;">
                            <thead>
                                <tr style="border-bottom: 1px solid var(--border-muted); background-color: rgba(255,255,255,0.01);">
                                    <th style="padding: 0.75rem 1rem;">Epoch Index</th>
                                    <th style="padding: 0.75rem 1rem;">Block Count</th>
                                    <th style="padding: 0.75rem 1rem;">Legacy Chain Hash</th>
                                    <th style="padding: 0.75rem 1rem;">Archived Timestamp</th>
                                    <th style="padding: 0.75rem 1rem;">Action</th>
                                </tr>
                            </thead>
                            <tbody id="drilldown-archives-body">
                                <!-- Archive rows injected here -->
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </main>

    <!-- Create Project Modal -->
    <div id="create-project-modal" class="modal-overlay">
        <div class="modal-panel glass-panel">
            <div class="modal-header">
                <h3 style="font-size: 1.25rem; font-weight: 700;">Create New Project</h3>
                <button onclick="closeModal('create-project-modal')" class="btn btn-secondary" style="padding: 0.25rem 0.5rem;">✕</button>
            </div>
            <div id="create-project-error" class="mono" style="color: var(--accent-red); font-size: 0.8125rem; display: none;"></div>
            <div class="input-group">
                <label for="project-name-input">Project Name</label>
                <input type="text" id="project-name-input" class="input-field" placeholder="e.g. Production Services">
            </div>
            <div style="display: flex; justify-content: flex-end; gap: 0.75rem;">
                <button onclick="closeModal('create-project-modal')" class="btn btn-secondary">Cancel</button>
                <button onclick="submitCreateProject()" class="btn btn-primary">Create Project</button>
            </div>
        </div>
    </div>

    <!-- Link Repository Modal -->
    <div id="link-repo-modal" class="modal-overlay">
        <div class="modal-panel glass-panel">
            <div class="modal-header">
                <h3 style="font-size: 1.25rem; font-weight: 700;">Link Repository to Project</h3>
                <button onclick="closeModal('link-repo-modal')" class="btn btn-secondary" style="padding: 0.25rem 0.5rem;">✕</button>
            </div>
            <div style="max-height: 300px; overflow-y: auto; display: flex; flex-direction: column; gap: 0.75rem;" id="unlinked-repos-list">
                <!-- List of repos injected here -->
            </div>
            <div style="display: flex; justify-content: flex-end;">
                <button onclick="closeModal('link-repo-modal')" class="btn btn-secondary">Close</button>
            </div>
        </div>
    </div>

    <!-- Block Viewer Modal -->
    <div id="block-viewer-modal" class="modal-overlay">
        <div class="modal-panel glass-panel" style="max-width: 700px;">
            <div class="modal-header">
                <h3 id="block-viewer-title" style="font-size: 1.25rem; font-weight: 700;">Block #0 (Genesis)</h3>
                <button onclick="closeModal('block-viewer-modal')" class="btn btn-secondary" style="padding: 0.25rem 0.5rem;">✕</button>
            </div>
            <div class="input-group">
                <label>Deteministic Meta Hash</label>
                <input type="text" id="block-viewer-hash" class="input-field mono" style="background-color: var(--bg-base);" readonly>
            </div>
            <div class="input-group">
                <label>Block Chain Raw Contents</label>
                <pre id="block-viewer-payload" class="payload-pre"></pre>
            </div>
            <div style="display: flex; justify-content: flex-end;">
                <button onclick="closeModal('block-viewer-modal')" class="btn btn-secondary">Close</button>
            </div>
        </div>
    </div>

    <script>
        // Apply theme immediately from localStorage
        (function() {
            const savedTheme = localStorage.getItem('pb-theme');
            if (savedTheme === 'light') {
                document.documentElement.setAttribute('data-theme', 'light');
            }
        })();

        let currentToken = '';
        let activePage = 'login';
        let projects = [];
        let allRepos = [];
        let currentProjectId = '';
        let currentProjectName = '';
        let selectedRepo = null;
        let activeProjectView = 'checks';

        function toggleTheme() {
            const root = document.documentElement;
            const currentTheme = root.getAttribute('data-theme');
            if (currentTheme === 'light') {
                root.removeAttribute('data-theme');
                localStorage.setItem('pb-theme', 'dark');
                document.getElementById('theme-icon').textContent = '☀️';
                document.getElementById('theme-text').textContent = 'Light Mode';
            } else {
                root.setAttribute('data-theme', 'light');
                localStorage.setItem('pb-theme', 'light');
                document.getElementById('theme-icon').textContent = '🌙';
                document.getElementById('theme-text').textContent = 'Dark Mode';
            }
        }

        function toggleUserDropdown(event) {
            event.stopPropagation();
            const dropdown = document.getElementById('user-dropdown');
            dropdown.classList.toggle('show');
        }

        function updateUserDropdown() {
            const tokenEl = document.getElementById('dropdown-user-token');
            if (tokenEl) {
                if (currentToken) {
                    const masked = currentToken.length <= 12 
                        ? currentToken 
                        : currentToken.substring(0, 8) + '...' + currentToken.substring(currentToken.length - 4);
                    tokenEl.textContent = masked;
                } else {
                    tokenEl.textContent = 'N/A';
                }
            }
        }

        window.addEventListener('click', () => {
            const dropdown = document.getElementById('user-dropdown');
            if (dropdown && dropdown.classList.contains('show')) {
                dropdown.classList.remove('show');
            }
        });

        // Check authentication state on landing
        window.addEventListener('DOMContentLoaded', async () => {
            // Setup theme UI state
            const savedTheme = localStorage.getItem('pb-theme');
            if (savedTheme === 'light') {
                document.getElementById('theme-icon').textContent = '🌙';
                document.getElementById('theme-text').textContent = 'Dark Mode';
            }

            currentToken = getCookie('pb_admin_session');
            if (currentToken) {
                updateUserDropdown();
                document.getElementById('header-panel').style.display = 'flex';
                await loadProjectsData();
                showPage('projects');
            } else {
                document.getElementById('loading-view').style.display = 'none';
                document.getElementById('auth-view').style.display = 'flex';
            }
        });

        function getCookie(name) {
            const value = \`; \${document.cookie}\`;
            const parts = value.split(\`; \${name}=\`);
            if (parts.length === 2) return parts.pop().split(';').shift();
            return '';
        }

        function setCookie(name, value, days) {
            const date = new Date();
            date.setTime(date.getTime() + (days * 24 * 60 * 60 * 1000));
            document.cookie = \`\${name}=\${value};expires=\${date.toUTCString()};path=/\`;
        }

        async function login() {
            const token = document.getElementById('admin-token').value.trim();
            const errDiv = document.getElementById('auth-error');
            errDiv.style.display = 'none';

            if (!token) {
                errDiv.textContent = 'Token cannot be empty.';
                errDiv.style.display = 'block';
                return;
            }

            try {
                const res = await fetch('/api/v1/admin/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ token })
                });

                if (res.ok) {
                    setCookie('pb_admin_session', token, 1);
                    currentToken = token;
                    updateUserDropdown();
                    document.getElementById('header-panel').style.display = 'flex';
                    await loadProjectsData();
                    showPage('projects');
                } else {
                    const data = await res.json();
                    errDiv.textContent = data.message || 'Authentication failed.';
                    errDiv.style.display = 'block';
                }
            } catch (e) {
                errDiv.textContent = 'Error contacting registry server.';
                errDiv.style.display = 'block';
            }
        }

        function logout() {
            setCookie('pb_admin_session', '', -1);
            currentToken = '';
            document.getElementById('header-panel').style.display = 'none';
            showPage('login');
            document.getElementById('admin-token').value = '';
        }

        function showPage(pageId) {
            activePage = pageId;
            document.getElementById('loading-view').style.display = 'none';
            document.getElementById('auth-view').style.display = pageId === 'login' ? 'flex' : 'none';
            document.getElementById('projects-page').style.display = pageId === 'projects' ? 'flex' : 'none';
            document.getElementById('project-dashboard-page').style.display = pageId === 'project-dashboard' ? 'flex' : 'none';
            document.getElementById('repo-drilldown-page').style.display = pageId === 'repo-drilldown' ? 'flex' : 'none';
            
            // Adjust header nav visual indicator
            const navProj = document.getElementById('nav-projects');
            if (navProj) {
                navProj.classList.toggle('active', pageId !== 'login');
            }
        }

        async function loadProjectsData() {
            try {
                const res = await fetch('/api/v1/admin/projects', {
                    headers: { 'Authorization': \`Bearer \${currentToken}\` }
                });
                if (res.status === 401) { logout(); return; }
                const data = await res.json();
                projects = data.projects || [];
                
                const reposRes = await fetch('/api/v1/admin/repos', {
                    headers: { 'Authorization': \`Bearer \${currentToken}\` }
                });
                const reposData = await reposRes.json();
                allRepos = reposData.repos || [];

                renderProjects();
            } catch (e) {
                console.error('Failed to load dashboard metrics.', e);
            }
        }

        function renderProjects() {
            document.getElementById('stat-projects-count').textContent = projects.length;
            document.getElementById('stat-repos-count').textContent = allRepos.length;

            const list = document.getElementById('projects-list');
            list.innerHTML = '';

            if (projects.length === 0) {
                list.innerHTML = \`<div class="mono" style="padding: 2rem; text-align: center; border: 1px dashed var(--border-muted); border-radius: 12px; color: var(--text-muted);">
                    No projects configured. Click "Create New Project" to get started.
                </div>\`;
                return;
            }

            projects.forEach(p => {
                const card = document.createElement('div');
                card.className = 'glass-panel list-card';
                card.innerHTML = \`
                    <div class="card-header-row">
                        <div>
                            <h3 onclick="viewProject('\${p.id}', '\${escapeHtml(p.name)}')" style="font-size: 1.25rem; font-weight: 700; margin-bottom: 0.25rem; cursor: pointer; display: inline-block; transition: color 0.15s ease;" onmouseover="this.style.color='var(--accent-purple)'" onmouseout="this.style.color=''" class="project-title-link">\${escapeHtml(p.name)}</h3>
                            <p style="font-size: 0.8125rem; color: var(--text-muted);">ID: <span class="mono">\${p.id}</span> • Created: \${new Date(p.created_at).toLocaleDateString()}</p>
                        </div>
                        <div style="display: flex; gap: 0.5rem; align-items: center;">
                            <span class="badge badge-purple">\${p.repoCount} linked repos</span>
                            <button onclick="viewProject('\${p.id}', '\${escapeHtml(p.name)}')" class="btn btn-secondary" style="padding: 0.375rem 0.75rem; font-size: 0.8125rem;">Manage</button>
                        </div>
                    </div>
                \`;
                list.appendChild(card);
            });
        }

        async function submitCreateProject() {
            const nameField = document.getElementById('project-name-input');
            const name = nameField.value.trim();
            const errDiv = document.getElementById('create-project-error');
            errDiv.style.display = 'none';

            if (!name) {
                errDiv.textContent = 'Project name is required.';
                errDiv.style.display = 'block';
                return;
            }

            try {
                const res = await fetch('/api/v1/admin/projects', {
                    method: 'POST',
                    headers: { 
                        'Content-Type': 'application/json',
                        'Authorization': \`Bearer \${currentToken}\`
                    },
                    body: JSON.stringify({ name })
                });

                if (res.ok) {
                    nameField.value = '';
                    closeModal('create-project-modal');
                    await loadProjectsData();
                } else {
                    const data = await res.json();
                    errDiv.textContent = data.message || 'Failed to create project.';
                    errDiv.style.display = 'block';
                }
            } catch (e) {
                errDiv.textContent = 'Network error.';
                errDiv.style.display = 'block';
            }
        }

        async function viewProject(id, name) {
            currentProjectId = id;
            currentProjectName = name;
            document.getElementById('breadcrumb-project-name').textContent = name;
            document.getElementById('project-title').textContent = name;

            await loadProjectDashboardDetails();
            showPage('project-dashboard');
            showProjectView('checks');
        }

        let projectRepos = [];
        let projectIntegrations = [];

        async function loadProjectDashboardDetails() {
            try {
                // Fetch checks/repos
                const res = await fetch(\`/api/v1/admin/projects/\${currentProjectId}/checks\`, {
                    headers: { 'Authorization': \`Bearer \${currentToken}\` }
                });
                const data = await res.json();
                projectRepos = data.repos || [];

                // Fetch integrations audit log
                const intRes = await fetch(\`/api/v1/admin/projects/\${currentProjectId}/integrations\`, {
                    headers: { 'Authorization': \`Bearer \${currentToken}\` }
                });
                const intData = await intRes.json();
                projectIntegrations = intData.events || [];

                renderChecks();
                renderIntegrations();
            } catch (e) {
                console.error('Failed to load project dashboard details.', e);
            }
        }

        function showProjectView(viewId) {
            activeProjectView = viewId;
            document.getElementById('project-view-checks').style.display = viewId === 'checks' ? 'flex' : 'none';
            document.getElementById('project-view-integrations').style.display = viewId === 'integrations' ? 'flex' : 'none';
            
            // Adjust tabs active class
            document.getElementById('tab-btn-checks').className = viewId === 'checks' ? 'btn btn-secondary btn-primary' : 'btn btn-secondary';
            document.getElementById('tab-btn-integrations').className = viewId === 'integrations' ? 'btn btn-secondary btn-primary' : 'btn btn-secondary';
        }

        function renderChecks() {
            const list = document.getElementById('checks-list');
            list.innerHTML = '';

            const query = document.getElementById('checks-search').value.toLowerCase().trim();
            const filtered = projectRepos.filter(r => 
                r.owner.toLowerCase().includes(query) || 
                r.repo.toLowerCase().includes(query)
            );

            if (filtered.length === 0) {
                list.innerHTML = \`<div class="mono" style="padding: 2rem; text-align: center; border: 1px dashed var(--border-muted); border-radius: 12px; color: var(--text-muted);">
                    No repositories linked to this project matching query.
                </div>\`;
                return;
            }

            filtered.forEach(r => {
                const card = document.createElement('div');
                card.className = 'glass-panel list-card';

                const tierClass = r.is_premium ? 'badge-purple' : 'badge-green';
                const tierText = r.is_premium ? 'Premium' : 'Standard';

                let statusClass = 'badge-green';
                if (r.verification_status === 'pending') statusClass = 'badge-amber';
                else if (r.verification_status === 'none' && r.is_premium) statusClass = 'badge-red'; // Failed challenge / standard fallback

                // Extract history blocks to draw a visual timeline grid
                let timelineHtml = '<div class="mono" style="color: var(--text-muted); font-size: 0.8125rem;">Empty Ledger</div>';
                if (r.log && r.log.chain_content) {
                    timelineHtml = renderVisualTimeline(r.log.chain_content, r.owner, r.repo);
                }

                card.innerHTML = \`
                    <div class="card-header-row">
                        <div class="card-title-group">
                            <h3 onclick="drilldownRepo('\${r.id}')" style="font-size: 1.125rem; font-weight: 700; cursor: pointer; display: inline-block; transition: color 0.15s ease;" onmouseover="this.style.color='var(--accent-purple)'" onmouseout="this.style.color=''" class="repo-title-link">\${escapeHtml(r.owner)}/\${escapeHtml(r.repo)}</h3>
                            <span class="badge \${tierClass}">\${tierText}</span>
                            <span class="badge \${statusClass}">Status: \${r.verification_status}</span>
                        </div>
                        <button onclick="drilldownRepo('\${r.id}')" class="btn btn-secondary" style="padding: 0.375rem 0.75rem; font-size: 0.8125rem;">Audit & Roll</button>
                    </div>
                    <div class="input-group">
                        <label>Visual Ledger Chain (DAG Blocks)</label>
                        <div class="timeline-container">
                            \${timelineHtml}
                        </div>
                    </div>
                \`;
                list.appendChild(card);
            });
        }

        function renderVisualTimeline(yamlContent, owner, repo) {
            const rawDocs = yamlContent.split(/\\n---\\n/).filter(d => d.trim().length > 0);
            let html = '';
            
            let blockIndex = 0;
            rawDocs.forEach((doc, idx) => {
                // Determine block indices and metadata
                const meta = parseYamlMeta(doc);
                if (meta) {
                    blockIndex = meta.block_index !== undefined ? meta.block_index : blockIndex;
                    
                    const isRollover = meta.genesis_rollover || doc.includes('genesis_rollover: true');
                    if (isRollover && idx > 0) {
                        html += '<div class="timeline-connector rollover"></div>';
                    } else if (idx > 0) {
                        html += '<div class="timeline-connector"></div>';
                    }

                    // Click node triggers full raw YAML modal
                    const escapedDoc = encodeURIComponent(doc);
                    html += \`<div class="block-node verified" onclick="viewBlockDetails('\${blockIndex}', '\${escapedDoc}', '\${meta.meta_hash || ''}')">\${blockIndex}</div>\`;
                }
            });
            return html;
        }

        function parseYamlMeta(doc) {
            try {
                const lines = doc.split('\\n');
                let blockIndex = undefined;
                let hash = '';
                let metaBlockStarted = false;

                for (let line of lines) {
                    if (line.includes('$yaml-chain-meta:')) {
                        metaBlockStarted = true;
                        continue;
                    }
                    if (metaBlockStarted) {
                        if (line.startsWith('  block_index:')) {
                            blockIndex = parseInt(line.replace('  block_index:', '').trim(), 10);
                        }
                        if (line.startsWith('  meta_hash:')) {
                            hash = line.replace('  meta_hash:', '').trim();
                        }
                    }
                }
                return { block_index: blockIndex, meta_hash: hash };
            } catch (e) {
                return null;
            }
        }

        function viewBlockDetails(index, encodedDoc, hash) {
            const doc = decodeURIComponent(encodedDoc);
            document.getElementById('block-viewer-title').textContent = \`Block #\${index} Verification Receipt\`;
            document.getElementById('block-viewer-hash').value = hash || 'N/A';
            document.getElementById('block-viewer-payload').textContent = doc;
            openModal('block-viewer-modal');
        }

        function renderIntegrations() {
            const tbody = document.getElementById('integrations-table-body');
            tbody.innerHTML = '';

            if (projectIntegrations.length === 0) {
                tbody.innerHTML = \`<tr><td colspan="7" class="mono" style="padding: 2rem; text-align: center; color: var(--text-muted);">
                    No client integration event pushes recorded yet for this project.
                </td></tr>\`;
                return;
            }

            projectIntegrations.forEach(ev => {
                const tr = document.createElement('tr');
                tr.style.borderBottom = '1px solid var(--border-muted)';
                
                const isCiBadge = ev.is_ci ? '<span class="badge badge-purple">Pipeline CI</span>' : '<span class="badge badge-green">Local Dev</span>';

                tr.innerHTML = \`
                    <td style="padding: 1rem; font-weight: 600;">\${escapeHtml(ev.owner)}/\${escapeHtml(ev.repo)}</td>
                    <td style="padding: 1rem;" class="mono">\${escapeHtml(ev.client_version || 'unknown')}</td>
                    <td style="padding: 1rem;">\${escapeHtml(ev.os_platform || 'unknown')}</td>
                    <td style="padding: 1rem;">\${escapeHtml(ev.runtime_env || 'BareMetal')} \${isCiBadge}</td>
                    <td style="padding: 1rem;">\${escapeHtml(ev.git_actor || 'unknown')}</td>
                    <td style="padding: 1rem;" class="mono">\${escapeHtml(ev.client_ip || 'unknown')}</td>
                    <td style="padding: 1rem;" class="mono">\${new Date(ev.created_at).toLocaleString()}</td>
                \`;
                tbody.appendChild(tr);
            });
        }

        function openLinkRepoModal() {
            const list = document.getElementById('unlinked-repos-list');
            list.innerHTML = '';

            // Find all registered repositories not linked to ANY project
            const unlinked = allRepos.filter(r => !r.project_id);

            if (unlinked.length === 0) {
                list.innerHTML = \`<div class="mono" style="padding: 1.5rem; text-align: center; color: var(--text-muted);">
                    No unlinked repositories found. Add standard repositories first or register them.
                </div>\`;
                openModal('link-repo-modal');
                return;
            }

            unlinked.forEach(r => {
                const row = document.createElement('div');
                row.className = 'link-row';
                row.innerHTML = \`
                    <div style="font-weight: 600;">\${escapeHtml(r.owner)}/\${escapeHtml(r.repo)}</div>
                    <button onclick="submitLinkRepo('\${r.id}')" class="btn btn-primary" style="padding: 0.375rem 0.75rem; font-size: 0.8125rem;">Link</button>
                \`;
                list.appendChild(row);
            });

            openModal('link-repo-modal');
        }

        async function submitLinkRepo(repoId) {
            try {
                const res = await fetch('/api/v1/admin/projects/link', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': \`Bearer \${currentToken}\`
                    },
                    body: JSON.stringify({
                        repoId: parseInt(repoId, 10),
                        projectId: currentProjectId
                    })
                });

                if (res.ok) {
                    closeModal('link-repo-modal');
                    await loadProjectsData();
                    await loadProjectDashboardDetails();
                } else {
                    alert('Failed to link repository.');
                }
            } catch (e) {
                alert('Network error.');
            }
        }

        async function drilldownRepo(repoId) {
            const repo = projectRepos.find(r => r.id == repoId);
            if (!repo) return;

            selectedRepo = repo;
            document.getElementById('repo-project-breadcrumb').textContent = currentProjectName;
            document.getElementById('repo-project-breadcrumb').onclick = () => viewProject(currentProjectId, currentProjectName);
            document.getElementById('breadcrumb-repo-path').textContent = \`\${repo.owner}/\${repo.repo}\`;
            document.getElementById('drilldown-repo-title').textContent = \`\${repo.owner}/\${repo.repo}\`;

            // Active token and credentials management
            document.getElementById('drilldown-token').value = repo.registration_token;
            
            const tierBadge = document.getElementById('drilldown-tier-badge');
            tierBadge.textContent = repo.is_premium ? 'PREMIUM TIER' : 'STANDARD TIER';
            tierBadge.className = repo.is_premium ? 'badge badge-purple' : 'badge badge-green';

            const statusBadge = document.getElementById('drilldown-verification-badge');
            statusBadge.textContent = repo.verification_status;
            let statusClass = 'badge-green';
            if (repo.verification_status === 'pending') statusClass = 'badge-amber';
            else if (repo.verification_status === 'none' && repo.is_premium) statusClass = 'badge-red';
            statusBadge.className = \`badge \${statusClass}\`;

            document.getElementById('drilldown-nonce').value = repo.challenge_nonce || 'N/A';
            document.getElementById('drilldown-public-key').value = repo.pinned_public_key || 'No verified key pinned.';

            // Setup buttons
            document.getElementById('btn-toggle-tier').onclick = () => toggleRepoPremium(repo.id);
            document.getElementById('btn-revoke-token').onclick = () => revokeToken(repo.id);

            // Reset ledger view to timeline when opening a repository drilldown
            toggleLedgerView('timeline');

            // Draw full vertical audit ledger
            let timelineHtml = '<div class="mono" style="color: var(--text-muted); padding: 1.5rem; text-align: center;">Empty Ledger</div>';
            if (repo.log && repo.log.chain_content) {
                timelineHtml = renderVisualTimeline(repo.log.chain_content, repo.owner, repo.repo);
            }
            document.getElementById('drilldown-timeline').innerHTML = timelineHtml;

            // Load cold archives if premium or rotated
            await loadRepoArchives(repo.id);

            showPage('repo-drilldown');
        }

        async function loadRepoArchives(repoId) {
            const section = document.getElementById('drilldown-archives-section');
            const tbody = document.getElementById('drilldown-archives-body');
            tbody.innerHTML = '';
            section.style.display = 'none';

            try {
                const res = await fetch(\`/api/v1/repo/\${selectedRepo.owner}/\${selectedRepo.repo}/archive\`);
                if (res.ok) {
                    const data = await res.json();
                    const archives = data.archives || [];
                    if (archives.length > 0) {
                        section.style.display = 'flex';
                        archives.forEach(arc => {
                            const tr = document.createElement('tr');
                            tr.style.borderBottom = '1px solid var(--border-muted)';
                            
                            // Click to view raw timeline content of that historical epoch
                            const escapedContent = encodeURIComponent(arc.chainContent);

                            tr.innerHTML = \`
                                <td style="padding: 0.75rem 1rem;" class="mono">Epoch #\${arc.epochIndex}</td>
                                <td style="padding: 0.75rem 1rem;">\${arc.blockCount} blocks</td>
                                <td style="padding: 0.75rem 1rem;" class="mono">\${arc.lastBlockHash.slice(0, 16)}...</td>
                                <td style="padding: 0.75rem 1rem;">\${new Date(arc.archivedAt).toLocaleString()}</td>
                                <td style="padding: 0.75rem 1rem;">
                                    <button onclick="viewHistoricalEpoch('\${arc.epochIndex}', '\${escapedContent}')" class="btn btn-secondary" style="padding: 0.25rem 0.5rem; font-size: 0.75rem;">View Epoch</button>
                                </td>
                            \`;
                            tbody.appendChild(tr);
                        });
                    }
                }
            } catch (e) {
                console.error('Failed to load repo archives.', e);
            }
        }

        function viewHistoricalEpoch(epochIndex, encodedContent) {
            const doc = decodeURIComponent(encodedContent);
            document.getElementById('block-viewer-title').textContent = \`Cold Archive Epoch #\${epochIndex} Chain Ledger\`;
            document.getElementById('block-viewer-hash').value = 'N/A';
            document.getElementById('block-viewer-payload').textContent = doc;
            openModal('block-viewer-modal');
        }

        async function toggleRepoPremium(repoId) {
            try {
                const res = await fetch(\`/api/v1/admin/repo/\${repoId}/toggle-premium\`, {
                    method: 'POST',
                    headers: { 'Authorization': \`Bearer \${currentToken}\` }
                });
                if (res.ok) {
                    await loadProjectsData();
                    await loadProjectDashboardDetails();
                    await drilldownRepo(repoId);
                } else {
                    alert('Action failed.');
                }
            } catch (e) {
                alert('Network error.');
            }
        }

        async function revokeToken(repoId) {
            if (!confirm('Are you absolutely sure you want to revoke this token? Pushes using this token will instantly fail!')) return;

            try {
                const res = await fetch(\`/api/v1/admin/repo/\${repoId}/revoke\`, {
                    method: 'POST',
                    headers: { 'Authorization': \`Bearer \${currentToken}\` }
                });
                if (res.ok) {
                    await loadProjectsData();
                    await loadProjectDashboardDetails();
                    await drilldownRepo(repoId);
                } else {
                    alert('Revocation failed.');
                }
            } catch (e) {
                alert('Network error.');
            }
        }

        function copyTokenText() {
            const token = document.getElementById('drilldown-token');
            token.select();
            token.setSelectionRange(0, 99999);
            navigator.clipboard.writeText(token.value);
            alert('Push registration token copied to clipboard.');
        }

        // Modal triggers
        function openModal(id) {
            document.getElementById(id).classList.add('open');
        }

        function closeModal(id) {
            document.getElementById(id).classList.remove('open');
        }

        function escapeHtml(str) {
            if (!str) return '';
            return str
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#039;");
        }

        function toggleLedgerView(viewType) {
            if (viewType === 'timeline') {
                document.getElementById('drilldown-timeline-view').style.display = 'block';
                document.getElementById('drilldown-tree-view').style.display = 'none';
                document.getElementById('ledger-tab-timeline').className = 'btn btn-secondary btn-primary';
                document.getElementById('ledger-tab-tree').className = 'btn btn-secondary';
            } else {
                document.getElementById('drilldown-timeline-view').style.display = 'none';
                document.getElementById('drilldown-tree-view').style.display = 'block';
                document.getElementById('ledger-tab-timeline').className = 'btn btn-secondary';
                document.getElementById('ledger-tab-tree').className = 'btn btn-secondary btn-primary';
                renderTrustTree();
            }
        }

        async function renderTrustTree() {
            const svg = d3.select("#tree-svg");
            svg.selectAll("*").remove();

            const container = document.getElementById("tree-canvas-container");
            const width = container.clientWidth || 800;
            const height = container.clientHeight || 500;

            const tooltip = d3.select("#tree-tooltip");

            if (!selectedRepo) return;

            svg.append("text")
                .attr("x", width / 2)
                .attr("y", height / 2)
                .attr("text-anchor", "middle")
                .attr("fill", "var(--text-muted)")
                .attr("font-size", "14px")
                .attr("id", "tree-loading-text")
                .text("Loading trust tree graph...");

            try {
                const res = await fetch(\`/api/v1/repo/\${selectedRepo.id}/tree\`, {
                    headers: { 'Authorization': \`Bearer \${currentToken}\` }
                });
                
                if (!res.ok) {
                    throw new Error("Failed to fetch tree data");
                }

                const data = await res.json();
                svg.select("#tree-loading-text").remove();

                if (!data.success || !data.tree) {
                    svg.append("text")
                        .attr("x", width / 2)
                        .attr("y", height / 2)
                        .attr("text-anchor", "middle")
                        .attr("fill", "var(--accent-red)")
                        .text("No trust tree data available.");
                    return;
                }

                const rootData = data.tree;

                const g = svg.append("g").attr("class", "zoom-container");

                const zoom = d3.zoom()
                    .scaleExtent([0.1, 3])
                    .on("zoom", (event) => {
                        g.attr("transform", event.transform);
                    });

                svg.call(zoom);

                const treeLayout = d3.tree().nodeSize([60, 240]);
                const root = d3.hierarchy(rootData);
                treeLayout(root);

                const nodes = root.descendants();
                const links = root.links();

                const initialX = 80;
                const initialY = height / 2;
                svg.call(zoom.transform, d3.zoomIdentity.translate(initialX, initialY).scale(1));

                g.selectAll(".link")
                    .data(links)
                    .enter()
                    .append("path")
                    .attr("class", "link")
                    .attr("fill", "none")
                    .attr("stroke", "var(--border-muted)")
                    .attr("stroke-width", 2)
                    .attr("d", d3.linkHorizontal()
                        .x(d => d.y)
                        .y(d => d.x)
                    );

                const nodeGroup = g.selectAll(".node")
                    .data(nodes)
                    .enter()
                    .append("g")
                    .attr("class", d => \`node node-\${d.data.type}\`)
                    .attr("transform", d => \`translate(\${d.data.y || 0}, \${d.data.x || 0})\`);

                const nodeCircle = nodeGroup.append("circle")
                    .attr("r", 14)
                    .attr("fill", "var(--bg-base)")
                    .attr("stroke-width", 3)
                    .attr("stroke", d => {
                        if (d.data.type === "root") return "var(--accent-green)";
                        if (d.data.type === "rollover") return "var(--accent-purple)";
                        return "var(--accent-cyan)";
                    });

                nodeGroup.each(function(d) {
                    if (d.data.type === "root") {
                        d3.select(this).select("circle")
                            .attr("class", "pulse-green pulse-green-circle")
                            .style("animation", "pulse-green-circle-glow 2s infinite alternate");
                    }
                });

                nodeGroup.append("text")
                    .attr("dy", ".35em")
                    .attr("x", d => d.children ? -20 : 20)
                    .attr("text-anchor", d => d.children ? "end" : "start")
                    .attr("fill", "var(--text-main)")
                    .attr("font-size", "12px")
                    .attr("font-family", "sans-serif")
                    .style("pointer-events", "none")
                    .text(d => {
                        if (d.data.type === "root") return d.data.name;
                        const versionStr = d.data.version ? \` (\${d.data.version})\` : "";
                        return \`Block #\${d.data.block_index}\${versionStr}\`;
                    });

                nodeCircle
                    .style("cursor", "pointer")
                    .on("mouseover", (event, d) => {
                        d3.select(event.currentTarget)
                            .transition()
                            .duration(150)
                            .attr("r", 18);

                        const [x, y] = d3.pointer(event, container);
                        
                        let tooltipContent = "";
                        if (d.data.type === "root") {
                            tooltipContent = \`
                                <div style="font-weight: 700; color: var(--accent-green); margin-bottom: 0.5rem;">Genesis Anchor</div>
                                <div style="word-break: break-all; font-family: monospace; font-size: 0.75rem;">
                                    <strong>Hash:</strong> \${d.data.id}
                                </div>
                            \`;
                        } else {
                            const badge = d.data.identityBadge || "N/A";
                            const timestamp = d.data.timestamp ? new Date(d.data.timestamp).toLocaleString() : "N/A";
                            const typeLabel = d.data.type === "rollover" 
                                ? \`<span class="badge badge-purple" style="font-size: 0.7rem; padding: 0.1rem 0.3rem;">Rollover</span>\` 
                                : \`<span class="badge badge-green" style="font-size: 0.7rem; padding: 0.1rem 0.3rem;">Block</span>\`;

                            tooltipContent = \`
                                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                                    <strong style="color: var(--text-main); font-size: 0.9rem;">Block #\${d.data.block_index}</strong>
                                    \${typeLabel}
                                </div>
                                <div style="display: flex; flex-direction: column; gap: 0.35rem; font-size: 0.75rem; word-break: break-all;">
                                    <div><strong>Version:</strong> <span class="mono">\${d.data.version || "N/A"}</span></div>
                                    <div><strong>Timestamp:</strong> \${timestamp}</div>
                                    <div><strong>Block Hash:</strong> <span class="mono" style="font-size: 0.7rem;">\${d.data.meta_hash || "N/A"}</span></div>
                                    <div><strong>Data Hash:</strong> <span class="mono" style="font-size: 0.7rem;">\${d.data.data_hash || "N/A"}</span></div>
                                    <div><strong>Actor Identity:</strong> <span class="badge badge-amber" style="text-transform: none; font-size: 0.7rem; font-weight: normal; padding: 0.1rem 0.3rem;">\${badge}</span></div>
                                </div>
                            \`;
                        }

                        tooltip.html(tooltipContent)
                            .style("display", "block")
                            .style("left", \`\${x + 15}px\`)
                            .style("top", \`\${y + 15}px\`);
                    })
                    .on("mousemove", (event) => {
                        const [x, y] = d3.pointer(event, container);
                        tooltip
                            .style("left", \`\${x + 15}px\`)
                            .style("top", \`\${y + 15}px\`);
                    })
                    .on("mouseout", (event, d) => {
                        d3.select(event.currentTarget)
                            .transition()
                            .duration(150)
                            .attr("r", 14);

                        tooltip.style("display", "none");
                    });

            } catch (err) {
                console.error(err);
                svg.select("#tree-loading-text").remove();
                svg.append("text")
                    .attr("x", width / 2)
                    .attr("y", height / 2)
                    .attr("text-anchor", "middle")
                    .attr("fill", "var(--accent-red)")
                    .text("Failed to load trust tree.");
            }
        }
    </script>
</body>
</html>`;
