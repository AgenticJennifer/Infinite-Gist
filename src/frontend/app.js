/* ============================================
   Infinite Gist — Single Page Application
   Vanilla JS, hash-based routing
   ============================================ */

const API = '/api/v1';

/* ===== State ===== */
const state = {
  token: localStorage.getItem('token') || null,
  currentUser: null,
  currentRoute: '',
  filters: {},
};

/* ===== API Client ===== */
async function api(path, options = {}) {
  const headers = { 'Content-Type': 'application/json', ...options.headers };
  if (state.token) headers['Authorization'] = `Bearer ${state.token}`;
  const res = await fetch(`${API}${path}`, { ...options, headers });
  if (res.status === 401) { state.token = null; localStorage.removeItem('token'); router.navigate('/login'); }
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || `HTTP ${res.status}`);
  }
  return res.json();
}

function apiUrl(path, params) {
  const url = new URL(`${API}${path}`, location.origin);
  if (params) Object.entries(params).filter(([,v]) => v !== undefined && v !== '').forEach(([k, v]) => url.searchParams.set(k, v));
  return url.pathname + url.search;
}

/* ===== Toast ===== */
function toast(msg, type = 'info') {
  const container = document.getElementById('toast-container');
  const el = document.createElement('div');
  el.className = `toast toast-${type}`;
  el.textContent = msg;
  container.appendChild(el);
  setTimeout(() => { el.style.opacity = '0'; el.style.transition = 'opacity 200ms'; setTimeout(() => el.remove(), 200); }, 3000);
}

/* ===== Modal ===== */
function showModal(title, bodyHtml, actions) {
  const backdrop = document.createElement('div');
  backdrop.className = 'modal-backdrop';
  backdrop.innerHTML = `
    <div class="modal">
      <h2>${title}</h2>
      ${bodyHtml}
      <div class="modal-actions">${actions}</div>
    </div>`;
  backdrop.addEventListener('click', (e) => { if (e.target === backdrop) backdrop.remove(); });
  document.body.appendChild(backdrop);
  return backdrop;
}

/* ===== Confirm Dialog ===== */
function confirmDialog(msg) {
  return new Promise((resolve) => {
    const m = showModal('Confirm', `<p style="margin-bottom:var(--space-4)">${msg}</p>`,
      `<button class="btn btn-secondary" data-cancel>Cancel</button>
       <button class="btn btn-danger" data-confirm>Confirm</button>`);
    m.querySelector('[data-confirm]').onclick = () => { m.remove(); resolve(true); };
    m.querySelector('[data-cancel]').onclick = () => { m.remove(); resolve(false); };
  });
}

/* ===== Render Helpers ===== */
function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  if (attrs) Object.entries(attrs).forEach(([k, v]) => {
    if (k === 'className') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2).toLowerCase(), v);
    else el.setAttribute(k, v);
  });
  children.forEach(c => { if (c) el.append(typeof c === 'string' ? document.createTextNode(c) : c); });
  return el;
}

function severityBadge(sev) {
  const s = (sev || 'low').toLowerCase();
  return `<span class="badge badge-${s}"><span class="severity-dot dot-${s}"></span>${sev}</span>`;
}

function confidenceBar(val) {
  const pct = Math.round((val || 0) * 100);
  const color = pct >= 75 ? 'var(--color-critical)' : pct >= 50 ? 'var(--color-warning)' : 'var(--color-low)';
  return `<div class="confidence-bar"><div class="confidence-fill" style="width:${pct}%;background:${color}"></div></div> <span style="font-size:var(--fs-xs);color:var(--color-text-secondary)">${pct}%</span>`;
}

function spinner() {
  const d = document.createElement('div');
  d.style.cssText = 'display:flex;justify-content:center;padding:3rem';
  d.innerHTML = '<div class="spinner"></div>';
  return d;
}

function errorMsg(msg) {
  const d = document.createElement('div');
  d.style.cssText = 'padding:1rem;color:var(--color-error);text-align:center';
  d.textContent = msg || 'Something went wrong';
  return d;
}

function emptyState(icon, title, desc) {
  const d = document.createElement('div');
  d.className = 'empty-state';
  d.innerHTML = `<i data-lucide="${icon}" style="width:48px;height:48px;opacity:0.4"></i><h3>${title}</h3><p>${desc || ''}</p>`;
  return d;
}

function formatDate(d) {
  if (!d) return '—';
  return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

/* ===== Sidebar ===== */
function renderSidebar() {
  const links = [
    { href: '/dashboard', icon: 'layout-dashboard', label: 'Dashboard' },
    { href: '/findings', icon: 'search', label: 'Findings' },
    { href: '/correlations', icon: 'share-2', label: 'Correlations' },
    { href: '/schedules', icon: 'clock', label: 'Schedules' },
    { href: '/policies', icon: 'shield', label: 'Policies' },
    { href: '/digests', icon: 'file-text', label: 'Digests' },
    { href: '/trends', icon: 'trending-up', label: 'Trends' },
  ];
  const nav = links.map(l => {
    const a = document.createElement('a');
    a.className = 'nav-item';
    a.href = `#${l.href}`;
    a.innerHTML = `<i data-lucide="${l.icon}"></i> ${l.label}`;
    if (state.currentRoute === l.href) a.classList.add('active');
    return a;
  });
  const sidebar = document.createElement('aside');
  sidebar.className = 'sidebar';
  sidebar.innerHTML = `
    <div class="sidebar-header">
      <h1>Infinite Gist</h1>
      <div class="sub">Security Monitoring</div>
    </div>
    <nav class="sidebar-nav"></nav>
    <div class="sidebar-footer">Signed in</div>`;
  const navContainer = sidebar.querySelector('.sidebar-nav');
  nav.forEach(n => navContainer.appendChild(n));
  return sidebar;
}

/* ===== Screen Renderers ===== */

/* --- Login Screen --- */
function renderLogin() {
  const page = document.createElement('div');
  page.className = 'login-page';
  page.innerHTML = `
    <div class="login-card">
      <h1>Infinite Gist</h1>
      <p>Continuous Gist leak detection and remediation</p>
      <a href="${API}/auth/github/login" class="btn btn-primary" style="width:100%;justify-content:center">
        <i data-lucide="github" style="width:18px;height:18px"></i> Sign in with GitHub
      </a>
    </div>`;
  return page;
}

/* --- Dashboard Screen --- */
async function renderDashboard() {
  const page = document.createElement('div');
  page.innerHTML = `<div class="page-header"><h1>Dashboard</h1><p>Security posture overview</p></div>`;
  const content = document.createElement('div');

  try {
    const [stats, summary, trends] = await Promise.all([
      api('/gists/findings/stats').catch(() => null),
      api('/trends/summary').catch(() => null),
      api('/trends/?days=30').catch(() => null),
    ]);

    // Stats cards
    const statsGrid = document.createElement('div');
    statsGrid.className = 'stats-grid';

    if (stats) {
      statsGrid.innerHTML = `
        <div class="stat-card"><div class="stat-value">${stats.total_findings || 0}</div><div class="stat-label">Total Findings</div></div>
        <div class="stat-card"><div class="stat-value">${stats.by_severity?.critical || 0}</div><div class="stat-label" style="color:var(--color-critical)">Critical</div></div>
        <div class="stat-card"><div class="stat-value">${stats.by_severity?.high || 0}</div><div class="stat-label" style="color:var(--color-high)">High</div></div>
        <div class="stat-card"><div class="stat-value">${stats.by_severity?.medium || 0}</div><div class="stat-label" style="color:var(--color-medium)">Medium</div></div>
        <div class="stat-card"><div class="stat-value">${stats.by_severity?.low || 0}</div><div class="stat-label" style="color:var(--color-low)">Low</div></div>
        <div class="stat-card"><div class="stat-value">${stats.average_confidence ? Math.round(stats.average_confidence * 100) + '%' : '—'}</div><div class="stat-label">Avg Confidence</div></div>`;
    }

    // Posture summary
    let postureHtml = '';
    if (summary) {
      const trend = summary.posture_trend || summary.trend || 'unknown';
      const trendIcon = trend === 'improving' ? 'trending-up' : trend === 'degrading' ? 'trending-down' : 'minus';
      const trendColor = trend === 'improving' ? 'var(--color-success)' : trend === 'degrading' ? 'var(--color-error)' : 'var(--color-text-secondary)';
      postureHtml = `
        <div class="card" style="margin-bottom:var(--space-5)">
          <div class="card-header">Posture Summary</div>
          <div style="display:flex;align-items:center;gap:var(--space-4)">
            <i data-lucide="${trendIcon}" style="width:32px;height:32px;color:${trendColor}"></i>
            <div><div style="font-size:var(--fs-lg);font-weight:600;text-transform:capitalize">${trend}</div>
            <div style="font-size:var(--fs-sm);color:var(--color-text-secondary)">${summary.message || ''}</div></div>
          </div>
        </div>`;
    }

    // Trend sparkline
    let chartHtml = '';
    if (trends && trends.length > 0) {
      const max = Math.max(...trends.map(t => t.total_findings), 1);
      const w = 600, h = 150, pad = 20;
      const xStep = (w - pad * 2) / (trends.length - 1 || 1);
      const pts = trends.map((t, i) => `${pad + i * xStep},${h - pad - (t.total_findings / max) * (h - pad * 2)}`).join(' ');
      chartHtml = `
        <div class="chart-container">
          <div class="card-header">Findings — Last 30 Days</div>
          <svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="xMidYMid meet">
            <polyline points="${pts}" fill="none" stroke="var(--color-accent)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
            ${trends.map((t, i) => `<circle cx="${pad + i * xStep}" cy="${h - pad - (t.total_findings / max) * (h - pad * 2)}" r="2" fill="var(--color-accent)"/>`).join('')}
          </svg>
        </div>`;
    }

    content.appendChild(statsGrid);
    if (postureHtml) content.insertAdjacentHTML('beforeend', postureHtml);
    if (chartHtml) content.insertAdjacentHTML('beforeend', chartHtml);

    if (!stats && !summary && !trends) {
      content.appendChild(emptyState('search', 'No data yet', 'Run your first scan to see findings.'));
    }

  } catch (e) {
    content.appendChild(emptyState('alert-circle', 'Could not load dashboard', e.message));
  }

  page.appendChild(content);
  return page;
}

/* --- Findings List Screen --- */
async function renderFindings() {
  const page = document.createElement('div');
  page.innerHTML = `<div class="page-header"><h1>Findings</h1><p>All detected secrets and suspicious content</p></div>`;

  const toolbar = document.createElement('div');
  toolbar.className = 'toolbar';
  toolbar.innerHTML = `
    <select class="form-select" id="sev-filter">
      <option value="">All Severities</option>
      <option value="critical">Critical</option>
      <option value="high">High</option>
      <option value="medium">Medium</option>
      <option value="low">Low</option>
    </select>
    <button class="btn btn-primary btn-sm" id="apply-filter"><i data-lucide="filter" style="width:14px;height:14px"></i> Filter</button>`;

  const tableContainer = document.createElement('div');
  tableContainer.className = 'table-container';
  const content = document.createElement('div');
  content.appendChild(toolbar);
  content.appendChild(tableContainer);
  page.appendChild(content);

  let sortCol = 'detected_at';
  let sortDir = 'desc';

  async function loadFindings() {
    tableContainer.innerHTML = '';
    tableContainer.appendChild(spinner());
    const sev = toolbar.querySelector('#sev-filter').value;
    const params = { skip: '0', limit: '100', severity: sev || undefined };
    try {
      const data = await api(`/gists/findings?${new URLSearchParams(Object.fromEntries(Object.entries(params).filter(([,v]) => v)))}`);
      tableContainer.innerHTML = '';

      if (!data || data.length === 0) {
        tableContainer.appendChild(emptyState('search', 'No findings', 'No secrets detected yet. Try running a scan.'));
        return;
      }

      // Sort
      data.sort((a, b) => {
        let va = a[sortCol], vb = b[sortCol];
        if (sortCol === 'confidence') { va = va || 0; vb = vb || 0; }
        if (typeof va === 'string') return sortDir === 'asc' ? va.localeCompare(vb) : vb.localeCompare(va);
        return sortDir === 'asc' ? (va || 0) - (vb || 0) : (vb || 0) - (va || 0);
      });

      const table = document.createElement('table');
      const sortIcon = (col) => sortCol === col ? (sortDir === 'asc' ? ' ▲' : ' ▼') : '';
      table.innerHTML = `
        <thead>
          <tr>
            <th class="sortable" data-col="severity">Severity${sortIcon('severity')}</th>
            <th class="sortable" data-col="secret_type">Type${sortIcon('secret_type')}</th>
            <th class="sortable" data-col="file_path">File${sortIcon('file_path')}</th>
            <th class="sortable" data-col="confidence">Confidence${sortIcon('confidence')}</th>
            <th class="sortable" data-col="status">Status${sortIcon('status')}</th>
            <th class="sortable" data-col="detected_at">Detected${sortIcon('detected_at')}</th>
          </tr>
        </thead>
        <tbody></tbody>`;

      const tbody = table.querySelector('tbody');
      data.forEach(f => {
        const tr = document.createElement('tr');
        tr.className = 'clickable';
        tr.style.cursor = 'pointer';
        tr.innerHTML = `
          <td>${severityBadge(f.severity)}</td>
          <td style="font-family:var(--font-mono);font-size:var(--fs-xs)">${f.secret_type || '—'}</td>
          <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:var(--fs-xs)">${f.file_path || '—'}</td>
          <td>${confidenceBar(f.confidence)}</td>
          <td><span class="badge badge-${f.status === 'open' || f.status === 'new' ? 'warning' : f.status === 'false_positive' ? 'low' : 'success'}">${f.status || 'new'}</span></td>
          <td style="font-size:var(--fs-xs);white-space:nowrap">${formatDate(f.detected_at)}</td>`;
        tr.onclick = () => router.navigate(`/findings/${f.id}`);
        tbody.appendChild(tr);
      });

      tableContainer.appendChild(table);

      // Sort handlers
      table.querySelectorAll('th.sortable').forEach(th => {
        th.onclick = () => {
          const col = th.dataset.col;
          if (sortCol === col) sortDir = sortDir === 'asc' ? 'desc' : 'asc';
          else { sortCol = col; sortDir = 'asc'; }
          loadFindings();
        };
      });
    } catch (e) {
      tableContainer.innerHTML = '';
      tableContainer.appendChild(errorMsg(e.message));
    }
  }

  toolbar.querySelector('#apply-filter').onclick = loadFindings;
  toolbar.querySelector('#sev-filter').onchange = loadFindings;

  // Also try to preset filter from URL
  const urlParams = new URLSearchParams(location.hash.split('?')[1] || '');
  const presetSev = urlParams.get('severity');
  if (presetSev) {
    toolbar.querySelector('#sev-filter').value = presetSev;
  }

  loadFindings();
  return page;
}

/* --- Finding Detail Screen --- */
async function renderFindingDetail(id) {
  const page = document.createElement('div');
  page.innerHTML = `<div class="page-header"><h1>Finding #${id}</h1><p>Full details and actions</p></div>`;
  const content = document.createElement('div');
  content.appendChild(spinner());
  page.appendChild(content);

  try {
    const [finding, correlations] = await Promise.all([
      api(`/gists/findings/${id}`),
      api(`/gists/findings/${id}/correlations`).catch(() => []),
    ]);

    content.innerHTML = '';

    // Detail grid
    const detailGrid = document.createElement('div');
    detailGrid.className = 'detail-grid';
    detailGrid.innerHTML = `
      <div class="card">
        <div class="detail-field"><div class="detail-label">Severity</div><div class="detail-value">${severityBadge(finding.severity)}</div></div>
        <div class="detail-field"><div class="detail-label">Status</div><div class="detail-value"><span class="badge badge-${finding.status === 'open' || finding.status === 'new' ? 'warning' : finding.status === 'false_positive' ? 'low' : 'success'}">${finding.status || 'new'}</span></div></div>
      </div>
      <div class="card">
        <div class="detail-field"><div class="detail-label">Secret Type</div><div class="detail-value" style="font-family:var(--font-mono);font-size:var(--fs-sm)">${finding.secret_type || '—'}</div></div>
        <div class="detail-field"><div class="detail-label">Confidence</div><div class="detail-value">${confidenceBar(finding.confidence)}</div></div>
      </div>
      <div class="card">
        <div class="detail-field"><div class="detail-label">File Path</div><div class="detail-value" style="font-family:var(--font-mono);font-size:var(--fs-xs)">${finding.file_path || '—'}</div></div>
        <div class="detail-field"><div class="detail-label">Line Range</div><div class="detail-value">${finding.line_start || '?'} — ${finding.line_end || '?'}</div></div>
      </div>
      <div class="card">
        <div class="detail-field"><div class="detail-label">Detected</div><div class="detail-value" style="font-size:var(--fs-sm)">${formatDate(finding.detected_at)}</div></div>
        <div class="detail-field"><div class="detail-label">Gist ID</div><div class="detail-value" style="font-family:var(--font-mono);font-size:var(--fs-xs)">${finding.gist_id}</div></div>
      </div>`;
    content.appendChild(detailGrid);

    // Content snippet
    if (finding.content_snippet) {
      const snippetCard = document.createElement('div');
      snippetCard.className = 'card';
      snippetCard.style.marginBottom = 'var(--space-5)';
      snippetCard.innerHTML = `<div class="card-header">Content Snippet</div><div class="detail-value mono">${finding.content_snippet}</div>`;
      content.appendChild(snippetCard);
    }

    if (finding.masked_value) {
      const maskedCard = document.createElement('div');
      maskedCard.className = 'card';
      maskedCard.style.marginBottom = 'var(--space-5)';
      maskedCard.innerHTML = `<div class="card-header">Masked Evidence</div><div class="detail-value mono">${finding.masked_value}</div>`;
      content.appendChild(maskedCard);
    }

    // Actions
    const actionsCard = document.createElement('div');
    actionsCard.className = 'card';
    actionsCard.style.marginBottom = 'var(--space-5)';
    actionsCard.innerHTML = `<div class="card-header">Actions</div><div style="display:flex;gap:var(--space-3);flex-wrap:wrap">`;

    const statusBtn = document.createElement('button');
    statusBtn.className = 'btn btn-secondary btn-sm';
    statusBtn.innerHTML = '<i data-lucide="toggle-left" style="width:14px;height:14px"></i> Toggle Status';
    statusBtn.onclick = async () => {
      const newStatus = finding.status === 'open' ? 'resolved' : 'open';
      try { await api(`/gists/findings/${id}/status?new_status=${newStatus}`, { method: 'PUT' }); toast('Status updated', 'success'); renderFindingDetail(id).then(r => content.replaceWith(r)); }
      catch (e) { toast(e.message, 'error'); }
    };
    actionsCard.querySelector('div').appendChild(statusBtn);

    const fpBtn = document.createElement('button');
    fpBtn.className = 'btn btn-secondary btn-sm';
    fpBtn.innerHTML = '<i data-lucide="x-circle" style="width:14px;height:14px"></i> Mark False Positive';
    fpBtn.onclick = async () => {
      if (!await confirmDialog('Mark this finding as false positive?')) return;
      try { await api(`/gists/findings/${id}/ignore`, { method: 'PUT' }); toast('Marked as false positive', 'success'); renderFindingDetail(id).then(r => content.replaceWith(r)); }
      catch (e) { toast(e.message, 'error'); }
    };
    actionsCard.querySelector('div').appendChild(fpBtn);

    // Remediation buttons
    const remediateBtn = (action, label) => {
      const btn = document.createElement('button');
      btn.className = 'btn btn-danger btn-sm';
      btn.innerHTML = `<i data-lucide="shield-off" style="width:14px;height:14px"></i> ${label}`;
      btn.onclick = async () => {
        if (!await confirmDialog(`${label} — are you sure?`)) return;
        try { await api(`/remediation/${action}`, { method: 'POST', body: JSON.stringify({ finding_id: id }) }); toast(`${label} initiated`, 'success'); }
        catch (e) { toast(e.message, 'error'); }
      };
      return btn;
    };
    actionsCard.querySelector('div').appendChild(remediateBtn('make-private', 'Make Private'));
    actionsCard.querySelector('div').appendChild(remediateBtn('delete', 'Delete Gist'));
    actionsCard.querySelector('div').appendChild(remediateBtn('rotate', 'Rotate Secret'));

    content.appendChild(actionsCard);

    // Correlations
    if (correlations && correlations.length > 0) {
      const corrSection = document.createElement('div');
      corrSection.className = 'section';
      corrSection.innerHTML = `<div class="section-title">Correlations (${correlations.length})</div>`;
      const corrTable = document.createElement('div');
      corrTable.className = 'table-container';
      corrTable.innerHTML = `<table>
        <thead><tr><th>Value Hash</th><th>Findings</th><th>Severity</th><th>Type</th><th>Gist IDs</th><th>First Detected</th></tr></thead>
        <tbody>${correlations.map(c => `<tr>
          <td style="font-family:var(--font-mono);font-size:var(--fs-xs)">${c.value_hash?.slice(0, 16) || '—'}…</td>
          <td>${c.finding_count}</td>
          <td>${severityBadge(c.severity)}</td>
          <td>${c.secret_type || '—'}</td>
          <td>${(c.gist_ids || []).join(', ')}</td>
          <td style="font-size:var(--fs-xs)">${formatDate(c.first_detected)}</td>
        </tr>`).join('')}</tbody>
      </table>`;
      corrSection.appendChild(corrTable);
      content.appendChild(corrSection);
    }

  } catch (e) {
    content.innerHTML = '';
    content.appendChild(errorMsg(e.message));
  }

  return page;
}

/* --- Correlations Screen --- */
async function renderCorrelations() {
  const page = document.createElement('div');
  page.innerHTML = `<div class="page-header"><h1>Correlations</h1><p>Cross-Gist pattern analysis</p></div>`;
  const content = document.createElement('div');
  content.appendChild(spinner());
  page.appendChild(content);

  try {
    const [groups, insights] = await Promise.all([
      api('/gists/correlations'),
      api('/gists/correlations/insights').catch(() => null),
    ]);

    content.innerHTML = '';

    // Insights cards
    if (insights) {
      const insightGrid = document.createElement('div');
      insightGrid.className = 'stats-grid';
      insightGrid.innerHTML = `
        <div class="stat-card"><div class="stat-value">${insights.total_correlated_findings || 0}</div><div class="stat-label">Correlated Findings</div></div>
        <div class="stat-card"><div class="stat-value">${Object.keys(insights.dominant_secret_types || {}).length || 0}</div><div class="stat-label">Secret Types</div></div>
        <div class="stat-card"><div class="stat-value">${Object.keys(insights.multi_gist_patterns || {}).length || 0}</div><div class="stat-label">Cross-Gist Patterns</div></div>`;
      content.appendChild(insightGrid);
    }

    if (!groups || groups.length === 0) {
      content.appendChild(emptyState('share-2', 'No correlations found', 'Correlations appear when the same secret appears across multiple Gists.'));
      return page;
    }

    const tc = document.createElement('div');
    tc.className = 'table-container';
    tc.style.marginTop = 'var(--space-4)';
    tc.innerHTML = `<table>
      <thead><tr><th>Value Hash</th><th>Findings</th><th>Severity</th><th>Type</th><th>Gist IDs</th><th>Range</th></tr></thead>
      <tbody>${groups.map(g => `<tr>
        <td style="font-family:var(--font-mono);font-size:var(--fs-xs)">${g.value_hash?.slice(0, 16) || '—'}…</td>
        <td>${g.finding_count}</td>
        <td>${severityBadge(g.severity)}</td>
        <td>${g.secret_type || '—'}</td>
        <td>${(g.gist_ids || []).join(', ')}</td>
        <td style="font-size:var(--fs-xs)">${formatDate(g.first_detected)} — ${formatDate(g.last_detected)}</td>
      </tr>`).join('')}</tbody>
    </table>`;
    content.appendChild(tc);

  } catch (e) {
    content.innerHTML = '';
    content.appendChild(errorMsg(e.message));
  }

  return page;
}

/* --- Schedules Screen --- */
async function renderSchedules() {
  const page = document.createElement('div');
  page.innerHTML = `<div class="page-header"><h1>Schedules</h1><p>Periodic scan scheduling</p></div>`;
  const toolbar = document.createElement('div');
  toolbar.className = 'toolbar';
  const createBtn = document.createElement('button');
  createBtn.className = 'btn btn-primary btn-sm';
  createBtn.innerHTML = '<i data-lucide="plus" style="width:14px;height:14px"></i> New Schedule';
  toolbar.appendChild(createBtn);

  const tableContainer = document.createElement('div');
  tableContainer.className = 'table-container';
  page.appendChild(toolbar);
  page.appendChild(tableContainer);

  async function loadSchedules() {
    tableContainer.innerHTML = '';
    tableContainer.appendChild(spinner());
    try {
      const data = await api('/schedules/');
      tableContainer.innerHTML = '';
      if (!data || data.length === 0) {
        tableContainer.appendChild(emptyState('clock', 'No schedules', 'Create a schedule for periodic scanning.'));
        return;
      }
      const table = document.createElement('table');
      table.innerHTML = `<thead><tr><th>ID</th><th>Name</th><th>Interval</th><th>Target</th><th>Enabled</th><th>Actions</th></tr></thead><tbody></tbody>`;
      const tbody = table.querySelector('tbody');
      data.forEach(s => {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${s.id}</td><td>${s.name || '—'}</td><td>${s.interval || s.schedule_type || '—'}</td><td>${s.target || s.github_account_id || '—'}</td>
          <td><span class="badge badge-${s.enabled ? 'success' : 'low'}">${s.enabled ? 'Active' : 'Disabled'}</span></td>
          <td><button class="btn btn-ghost btn-sm" data-edit="${s.id}"><i data-lucide="edit" style="width:14px;height:14px"></i></button>
          <button class="btn btn-ghost btn-sm" data-delete="${s.id}"><i data-lucide="trash-2" style="width:14px;height:14px"></i></button></td>`;
        tr.querySelector('[data-edit]').onclick = () => editSchedule(s);
        tr.querySelector('[data-delete]').onclick = async () => {
          if (!await confirmDialog(`Delete schedule #${s.id}?`)) return;
          try { await api(`/schedules/${s.id}`, { method: 'DELETE' }); toast('Schedule deleted', 'success'); loadSchedules(); }
          catch (e) { toast(e.message, 'error'); }
        };
        tbody.appendChild(tr);
      });
      tableContainer.appendChild(table);
    } catch (e) {
      tableContainer.innerHTML = '';
      tableContainer.appendChild(errorMsg(e.message));
    }
  }

  createBtn.onclick = () => editSchedule(null);
  loadSchedules();
  return page;

  function editSchedule(s) {
    const isNew = !s;
    const bodyHtml = `
      <div class="form-group"><label class="form-label">Name</label><input class="form-input" id="sched-name" value="${s ? (s.name || '') : ''}" placeholder="e.g. Weekly scan"></div>
      <div class="form-group"><label class="form-label">Interval</label>
        <select class="form-select" id="sched-interval">
          <option value="daily" ${s && s.interval === 'daily' ? 'selected' : ''}>Daily</option>
          <option value="weekly" ${!s || s.interval === 'weekly' ? 'selected' : ''}>Weekly</option>
          <option value="custom" ${s && s.interval === 'custom' ? 'selected' : ''}>Custom (cron)</option>
        </select></div>
      <div class="form-group"><label class="form-label">GitHub Account ID</label><input class="form-input" id="sched-target" value="${s ? (s.github_account_id || s.target || '') : ''}" placeholder="Account ID"></div>`;
    const m = showModal(isNew ? 'Create Schedule' : 'Edit Schedule', bodyHtml,
      `<button class="btn btn-secondary" data-cancel>Cancel</button>
       <button class="btn btn-primary" data-save>${isNew ? 'Create' : 'Save'}</button>`);
    m.querySelector('[data-cancel]').onclick = () => m.remove();
    m.querySelector('[data-save]').onclick = async () => {
      const body = { name: m.querySelector('#sched-name').value, interval: m.querySelector('#sched-interval').value, github_account_id: parseInt(m.querySelector('#sched-target').value) || 1 };
      try {
        if (isNew) { await api('/schedules/', { method: 'POST', body: JSON.stringify(body) }); toast('Schedule created', 'success'); }
        else { await api(`/schedules/${s.id}`, { method: 'PUT', body: JSON.stringify(body) }); toast('Schedule updated', 'success'); }
        m.remove(); loadSchedules();
      } catch (e) { toast(e.message, 'error'); }
    };
  }
}

/* --- Policies Screen --- */
async function renderPolicies() {
  const page = document.createElement('div');
  page.innerHTML = `<div class="page-header"><h1>Policies</h1><p>Account security and notification settings</p></div>`;
  const content = document.createElement('div');
  content.appendChild(spinner());
  page.appendChild(content);

  try {
    const data = await api('/policies/');
    content.innerHTML = '';

    const form = document.createElement('form');
    form.onsubmit = (e) => e.preventDefault();

    // Build form from policy fields
    const fields = [
      { key: 'notify_critical', label: 'Notify on Critical Findings', type: 'checkbox' },
      { key: 'notify_high', label: 'Notify on High Findings', type: 'checkbox' },
      { key: 'auto_remediate_critical', label: 'Auto-remediate Critical', type: 'checkbox', desc: 'Opt-in only' },
      { key: 'digest_frequency', label: 'Digest Frequency', type: 'select', options: ['daily', 'weekly', 'never'] },
      { key: 'max_findings_per_gist', label: 'Max Findings per Gist', type: 'number' },
    ];

    fields.forEach(f => {
      const val = data[f.key] !== undefined ? data[f.key] : (f.type === 'checkbox' ? false : '');
      const g = document.createElement('div');
      g.className = 'form-group';
      if (f.type === 'checkbox') {
        g.innerHTML = `<label class="form-label" style="display:flex;align-items:center;gap:var(--space-3);cursor:pointer">
          <input type="checkbox" ${val ? 'checked' : ''} id="pol-${f.key}" style="width:18px;height:18px"> ${f.label}
          ${f.desc ? `<span style="font-weight:400;color:var(--color-text-secondary)">— ${f.desc}</span>` : ''}
        </label>`;
      } else if (f.type === 'select') {
        g.innerHTML = `<label class="form-label">${f.label}</label>
          <select class="form-select" id="pol-${f.key}">${(f.options || []).map(o => `<option value="${o}" ${val === o ? 'selected' : ''}>${o}</option>`).join('')}</select>`;
      } else {
        g.innerHTML = `<label class="form-label">${f.label}</label><input class="form-input" type="${f.type}" id="pol-${f.key}" value="${val}">`;
      }
      form.appendChild(g);
    });

    const saveBtn = document.createElement('button');
    saveBtn.className = 'btn btn-primary';
    saveBtn.innerHTML = '<i data-lucide="save" style="width:16px;height:16px"></i> Save Policies';
    saveBtn.onclick = async () => {
      const body = {};
      fields.forEach(f => {
        const el = document.getElementById(`pol-${f.key}`);
        body[f.key] = f.type === 'checkbox' ? el.checked : f.type === 'number' ? parseInt(el.value) || 0 : el.value;
      });
      try { await api('/policies/', { method: 'PUT', body: JSON.stringify(body) }); toast('Policies saved', 'success'); }
      catch (e) { toast(e.message, 'error'); }
    };
    form.appendChild(saveBtn);
    content.appendChild(form);

  } catch (e) {
    content.innerHTML = '';
    content.appendChild(errorMsg(e.message));
  }

  return page;
}

/* --- Digests Screen --- */
async function renderDigests() {
  const page = document.createElement('div');
  page.innerHTML = `<div class="page-header"><h1>Digests</h1><p>Generated security digest reports</p></div>`;
  const toolbar = document.createElement('div');
  toolbar.className = 'toolbar';
  const genBtn = document.createElement('button');
  genBtn.className = 'btn btn-primary btn-sm';
  genBtn.innerHTML = '<i data-lucide="refresh-cw" style="width:14px;height:14px"></i> Generate Now';
  toolbar.appendChild(genBtn);

  const tableContainer = document.createElement('div');
  tableContainer.className = 'table-container';
  page.appendChild(toolbar);
  page.appendChild(tableContainer);

  async function load() {
    tableContainer.innerHTML = '';
    tableContainer.appendChild(spinner());
    try {
      const data = await api('/digests/');
      tableContainer.innerHTML = '';
      if (!data || data.length === 0) {
        tableContainer.appendChild(emptyState('file-text', 'No digests', 'Generate your first digest report.'));
        return;
      }
      const table = document.createElement('table');
      table.innerHTML = `<thead><tr><th>ID</th><th>Type</th><th>Period</th><th>Created</th><th>Status</th></tr></thead><tbody>
        ${data.map(d => `<tr>
          <td>${d.id}</td>
          <td>${d.digest_type || d.type || '—'}</td>
          <td>${d.period || '—'}</td>
          <td style="font-size:var(--fs-xs)">${formatDate(d.created_at || d.created)}</td>
          <td><span class="badge badge-${d.status === 'generated' ? 'success' : 'warning'}">${d.status || '—'}</span></td>
        </tr>`).join('')}</tbody></table>`;
      tableContainer.appendChild(table);
    } catch (e) {
      tableContainer.innerHTML = '';
      tableContainer.appendChild(errorMsg(e.message));
    }
  }

  genBtn.onclick = async () => {
    try { await api('/digests/generate', { method: 'POST' }); toast('Digest generation started', 'success'); load(); }
    catch (e) { toast(e.message, 'error'); }
  };

  load();
  return page;
}

/* --- Trends Screen --- */
async function renderTrends() {
  const page = document.createElement('div');
  page.innerHTML = `<div class="page-header"><h1>Trends</h1><p>Security posture over time</p></div>`;
  const content = document.createElement('div');
  content.appendChild(spinner());
  page.appendChild(content);

  try {
    const [trends, summary] = await Promise.all([
      api('/trends/?days=30'),
      api('/trends/summary').catch(() => null),
    ]);

    content.innerHTML = '';

    if (summary) {
      const sGrid = document.createElement('div');
      sGrid.className = 'stats-grid';
      const items = [
        { label: 'Total Findings (avg)', val: summary.avg_total_findings ?? '—' },
        { label: 'Critical (avg)', val: summary.avg_critical ?? '—' },
        { label: 'High (avg)', val: summary.avg_high ?? '—' },
        { label: 'Remediated (avg)', val: summary.avg_remediated ?? '—' },
      ];
      items.forEach(i => {
        sGrid.innerHTML += `<div class="stat-card"><div class="stat-value">${i.val}</div><div class="stat-label">${i.label}</div></div>`;
      });
      content.appendChild(sGrid);
    }

    if (trends && trends.length > 0) {
      const max = Math.max(...trends.map(t => t.total_findings), 1);
      const w = 700, h = 200, pad = 30;
      const xStep = (w - pad * 2) / (trends.length - 1 || 1);
      const pts = trends.map((t, i) => `${pad + i * xStep},${h - pad - (t.total_findings / max) * (h - pad * 2)}`).join(' ');
      const critPts = trends.map((t, i) => `${pad + i * xStep},${h - pad - ((t.critical_findings || 0) / Math.max(max, 1)) * (h - pad * 2)}`).join(' ');

      content.innerHTML += `
        <div class="chart-container">
          <div class="card-header">Findings Over Time (30 days)</div>
          <svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="xMidYMid meet">
            <polyline points="${pts}" fill="none" stroke="var(--color-accent)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
            <polyline points="${critPts}" fill="none" stroke="var(--color-critical)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" stroke-dasharray="4,4"/>
            <text x="${pad}" y="${h - pad + 16}" font-size="10" fill="var(--color-text-secondary)">0</text>
            <text x="${w - pad - 40}" y="${h - pad + 16}" font-size="10" fill="var(--color-text-secondary)">${trends.length}d ago</text>
          </svg>
          <div style="display:flex;gap:var(--space-4);margin-top:var(--space-2);font-size:var(--fs-xs);color:var(--color-text-secondary)">
            <span style="display:flex;align-items:center;gap:var(--space-1)"><span style="display:inline-block;width:16px;height:2px;background:var(--color-accent)"></span> Total</span>
            <span style="display:flex;align-items:center;gap:var(--space-1)"><span style="display:inline-block;width:16px;height:2px;background:var(--color-critical)"></span> Critical</span>
          </div>
        </div>`;

      // Data table
      const tc = document.createElement('div');
      tc.className = 'table-container';
      tc.innerHTML = `<table>
        <thead><tr><th>Date</th><th>Total</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Remediated</th></tr></thead>
        <tbody>${trends.map(t => `<tr>
          <td style="font-size:var(--fs-xs);white-space:nowrap">${formatDate(t.date)}</td>
          <td>${t.total_findings || 0}</td>
          <td style="color:var(--color-critical)">${t.critical_findings || 0}</td>
          <td style="color:var(--color-high)">${t.high_findings || 0}</td>
          <td style="color:var(--color-medium)">${t.medium_findings || 0}</td>
          <td style="color:var(--color-low)">${t.low_findings || 0}</td>
          <td>${t.remediated_count || 0}</td>
        </tr>`).join('')}</tbody>
      </table>`;
      content.appendChild(tc);
    } else {
      content.appendChild(emptyState('trending-up', 'No trend data', 'Data appears after scans have been running for a few days.'));
    }

  } catch (e) {
    content.innerHTML = '';
    content.appendChild(errorMsg(e.message));
  }

  return page;
}

/* ===== Router ===== */
const router = {
  navigate(hash) {
    location.hash = hash;
  },
  async handle() {
    const hash = location.hash.slice(1) || '/dashboard';
    state.currentRoute = hash.split('?')[0];
    const app = document.getElementById('app');

    // Check auth
    if (!state.token && !hash.startsWith('/login')) {
      this.navigate('/login');
      return;
    }

    app.innerHTML = '';
    let content;

    try {
      // Login page (no sidebar)
      if (hash.startsWith('/login')) {
        content = renderLogin();
        app.appendChild(content);
        lucide.createIcons();
        return;
      }

      // Extract param from route like /findings/123
      const findingMatch = hash.match(/^\/findings\/(\d+)/);

      // Build layout with sidebar
      const layout = document.createElement('div');
      layout.className = 'app-layout';

      // Hamburger
      const hamburger = document.createElement('button');
      hamburger.className = 'hamburger';
      hamburger.innerHTML = '<i data-lucide="menu" style="width:20px;height:20px"></i>';
      hamburger.onclick = () => {
        document.querySelector('.sidebar')?.classList.toggle('open');
        document.querySelector('.sidebar-overlay')?.classList.toggle('open');
      };
      layout.appendChild(hamburger);

      const overlay = document.createElement('div');
      overlay.className = 'sidebar-overlay';
      overlay.onclick = () => {
        overlay.classList.remove('open');
        document.querySelector('.sidebar')?.classList.remove('open');
      };
      layout.appendChild(overlay);

      const sidebar = renderSidebar();
      layout.appendChild(sidebar);

      const main = document.createElement('main');
      main.className = 'main-content';

      // Route
      if (hash === '/dashboard' || hash === '/' || hash === '') {
        main.appendChild(await renderDashboard());
      } else if (hash === '/findings' || hash.startsWith('/findings?')) {
        main.appendChild(await renderFindings());
      } else if (findingMatch) {
        main.appendChild(await renderFindingDetail(parseInt(findingMatch[1])));
      } else if (hash === '/correlations') {
        main.appendChild(await renderCorrelations());
      } else if (hash === '/schedules') {
        main.appendChild(await renderSchedules());
      } else if (hash === '/policies') {
        main.appendChild(await renderPolicies());
      } else if (hash === '/digests') {
        main.appendChild(await renderDigests());
      } else if (hash === '/trends') {
        main.appendChild(await renderTrends());
      } else {
        main.innerHTML = `<div class="page-header"><h1>404</h1><p>Page not found</p></div>`;
      }

      layout.appendChild(main);
      app.appendChild(layout);
    } catch (e) {
      if (content) app.appendChild(content);
      else {
        const el = document.createElement('div');
        el.style.cssText = 'padding:2rem;text-align:center;color:var(--color-error)';
        el.textContent = `Error: ${e.message}`;
        app.appendChild(el);
      }
    }

    // Initialize Lucide icons
    lucide.createIcons();
  }
};

/* ===== Init ===== */
window.addEventListener('hashchange', () => router.handle());
window.addEventListener('load', () => {
  // Check for token in URL (from OAuth redirect)
  const hashParams = new URLSearchParams(location.hash.replace('#', ''));
  const tokenFromHash = hashParams.get('access_token') || hashParams.get('token');
  if (tokenFromHash) {
    state.token = tokenFromHash;
    localStorage.setItem('token', tokenFromHash);
    // Clean URL
    history.replaceState(null, '', '/');
  }
  router.handle();
});
