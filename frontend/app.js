/*
 * OpenAuthority
 * Copyright (C) 2026 CaramelFox Networks LLC
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

// DOM helpers
const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];

// State
let certPage = 1, certTotalPages = 1, certSearch = '';
let auditPage = 1, auditTotalPages = 1;
const loadedPartials = new Set(['home']);

// Tab titles for SEO/UX
const tabTitles = {
  home: 'OpenAuthority',
  upload: 'Enroll CA | OpenAuthority',
  certificates: 'Trust Store | OpenAuthority',
  audit: 'Audit Log | OpenAuthority',
  export: 'Export | OpenAuthority',
  faq: 'FAQ | OpenAuthority',
  about: 'About | OpenAuthority'
};

// Valid tabs for routing
const validTabs = ['home', 'upload', 'certificates', 'audit', 'export', 'faq', 'about'];

// Platform detection
function detectPlatform() {
  const ua = navigator.userAgent.toLowerCase();
  if (/iphone|ipad|ipod/.test(ua)) return 'ios';
  if (/macintosh|mac os x/.test(ua) && 'ontouchend' in document) return 'ios';
  if (/macintosh|mac os x/.test(ua)) return 'macos';
  if (/android/.test(ua)) return 'android';
  if (/windows/.test(ua)) return 'windows';
  if (/linux/.test(ua)) return 'linux';
  return 'unknown';
}

function highlightRecommendedDownload() {
  $$('.download-card').forEach(c => {
    c.classList.remove('recommended');
    c.querySelector('.badge')?.remove();
  });

  const platform = detectPlatform();
  let id, name;

  switch (platform) {
    case 'ios':
    case 'macos':
      id = 'dl-mobileconfig';
      name = 'your device';
      break;
    case 'android':
      id = 'dl-zip';
      name = 'Android';
      break;
    case 'windows':
      id = 'dl-zip';
      name = 'Windows';
      break;
    case 'linux':
      id = 'dl-pem';
      name = 'Linux';
      break;
    default:
      return;
  }

  const card = $('#' + id);
  if (card) {
    card.classList.add('recommended');
    const badge = document.createElement('span');
    badge.className = 'badge';
    badge.textContent = 'Recommended';
    card.insertBefore(badge, card.firstChild);
  }

  const txt = $('#recommendedText');
  if (txt) txt.textContent = `We detected ${name}. The recommended format is highlighted.`;
}

// Lazy load partials
async function loadPartial(name) {
  if (loadedPartials.has(name)) return true;

  const container = $('#' + name);
  if (!container) return false;

  container.innerHTML = '<div class="loading"><div class="spinner"></div>Loading...</div>';

  try {
    const res = await fetch(`partials/${name}.html`);
    if (!res.ok) throw new Error('Failed to load');
    container.innerHTML = await res.text();
    loadedPartials.add(name);
    initPartial(name);
    return true;
  } catch (e) {
    container.innerHTML = '<div class="empty-state"><p>Failed to load content.</p></div>';
    return false;
  }
}

// Initialize partial-specific functionality
function initPartial(name) {
  switch (name) {
    case 'upload':
      initUpload();
      break;
    case 'certificates':
      loadCertificates();
      break;
    case 'audit':
      loadAuditLog();
      break;
    case 'export':
      highlightRecommendedDownload();
      initPlatformTabs();
      break;
    case 'faq':
      initFaq();
      break;
  }
}

// ============================================
// ROUTING (Hash-based)
// ============================================

function getTabFromHash() {
  const hash = window.location.hash.slice(1) || 'home';
  return validTabs.includes(hash) ? hash : 'home';
}

function initRouter() {
  // Handle initial page load
  const initialTab = getTabFromHash();
  switchTab(initialTab);

  // Handle browser back/forward buttons
  window.addEventListener('hashchange', () => {
    const tab = getTabFromHash();
    switchTab(tab);
  });
}

// Tab switching with routing
async function switchTab(tabName) {
  // Validate tab name
  if (!validTabs.includes(tabName)) {
    tabName = 'home';
  }

  // Update URL hash (without triggering hashchange if already correct)
  const targetHash = tabName === 'home' ? '' : tabName;
  const currentHash = window.location.hash.slice(1);

  if (currentHash !== targetHash) {
    // Use replaceState to avoid polluting history on programmatic switches
    const newUrl = tabName === 'home' 
      ? window.location.pathname + window.location.search
      : '#' + tabName;
    history.replaceState({ tab: tabName }, '', newUrl);
  }

  // Update page title
  document.title = tabTitles[tabName] || 'OpenAuthority';

  // Scroll to top
  window.scrollTo(0, 0);

  // Update tab UI
  $$('.tab').forEach(t => t.classList.remove('active'));
  $$('.tab-content').forEach(c => c.classList.remove('active'));

  $(`[data-tab="${tabName}"]`)?.classList.add('active');

  const container = $('#' + tabName);
  if (container) {
    container.classList.add('active');
    await loadPartial(tabName);
  }
}

// ============================================
// EVENT DELEGATION
// ============================================

document.addEventListener('click', e => {
  // Tab buttons
  if (e.target.matches('.tab')) {
    e.preventDefault();
    const tabName = e.target.dataset.tab;
    // Use pushState for user-initiated navigation (enables back button)
    const newUrl = tabName === 'home' ? window.location.pathname : '#' + tabName;
    history.pushState({ tab: tabName }, '', newUrl);
    switchTab(tabName);
    return;
  }

  // Switch tab links/buttons
  const switchEl = e.target.closest('[data-switch-tab]');
  if (switchEl) {
    e.preventDefault();
    const tabName = switchEl.dataset.switchTab;
    // Use pushState for user-initiated navigation
    const newUrl = tabName === 'home' ? window.location.pathname : '#' + tabName;
    history.pushState({ tab: tabName }, '', newUrl);
    switchTab(tabName);
    return;
  }

  // Platform tabs
  const platformTab = e.target.closest('.platform-tab');
  if (platformTab) {
    $$('.platform-tab').forEach(t => t.classList.remove('active'));
    $$('.platform-content').forEach(c => c.classList.remove('active'));
    platformTab.classList.add('active');
    $(`.platform-content[data-platform="${platformTab.dataset.platform}"]`)?.classList.add('active');
    return;
  }

  // FAQ accordion
  const faqQ = e.target.closest('.faq-question');
  if (faqQ) {
    const item = faqQ.parentElement;
    const wasOpen = item.classList.contains('open');
    $$('.faq-item').forEach(i => i.classList.remove('open'));
    if (!wasOpen) item.classList.add('open');
    return;
  }

  // Cert item click
  const certItem = e.target.closest('.cert-item[data-id]');
  if (certItem) {
    openCertModal(certItem.dataset.id);
    return;
  }

  // Modal close
  if (e.target.matches('.modal-overlay') || e.target.matches('#modalCloseBtn')) {
    closeCertModal();
    return;
  }

  // Verify audit button
  if (e.target.matches('#verifyAuditBtn')) {
    verifyAuditLog();
    return;
  }

  // Cert search button
  if (e.target.matches('#certSearchBtn')) {
    searchCertificates();
    return;
  }
});

document.addEventListener('keydown', e => {
  if (e.key === 'Escape') closeCertModal();
});

document.addEventListener('keypress', e => {
  if (e.key === 'Enter' && e.target.matches('#certSearch')) searchCertificates();
});

// ============================================
// UPLOAD FUNCTIONALITY
// ============================================

function initUpload() {
  const dropZone = $('#dropZone');
  const fileInput = $('#certFile');
  const submitBtn = $('#submitBtn');
  const form = $('#uploadForm');
  const msg = $('#message');

  if (!dropZone) return;

  dropZone.addEventListener('click', () => fileInput.click());

  dropZone.addEventListener('dragover', e => {
    e.preventDefault();
    dropZone.classList.add('dragover');
  });

  dropZone.addEventListener('dragleave', () => {
    dropZone.classList.remove('dragover');
  });

  dropZone.addEventListener('drop', e => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    if (e.dataTransfer.files.length) {
      fileInput.files = e.dataTransfer.files;
      updateFileDisplay();
    }
  });

  fileInput.addEventListener('change', updateFileDisplay);

  function updateFileDisplay() {
    if (fileInput.files.length) {
      dropZone.querySelector('.upload-title').textContent = fileInput.files[0].name;
      dropZone.querySelector('.upload-hint').textContent = 'Ready to upload';
      submitBtn.disabled = false;
    }
  }

  form.addEventListener('submit', async e => {
    e.preventDefault();
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<div class="spinner" style="margin-right:.5rem"></div>Verifying...';
    msg.innerHTML = '';

    const fd = new FormData();
    fd.append('certificate', fileInput.files[0]);

    try {
      const res = await fetch('/api/upload', { method: 'POST', body: fd });
      const data = await res.json();

      msg.innerHTML = res.ok
        ? `<div class="message message-success"><svg class="icon"><use href="#i-check"/></svg><span>${data.message}</span></div>`
        : `<div class="message message-error"><svg class="icon"><use href="#i-x"/></svg><span>${data.error}</span></div>`;

      if (res.ok) {
        fileInput.value = '';
        dropZone.querySelector('.upload-title').textContent = 'Drop your CA certificate here';
        dropZone.querySelector('.upload-hint').textContent = 'or click to browse';
      }
    } catch (err) {
      msg.innerHTML = `<div class="message message-error"><span>Upload failed: ${err.message}</span></div>`;
    }

    submitBtn.disabled = false;
    submitBtn.textContent = 'Verify & Upload Certificate';
  });
}

function initPlatformTabs() {
  /* Already handled by event delegation */
}

function initFaq() {
  /* Already handled by event delegation */
}

// ============================================
// UTILITY FUNCTIONS
// ============================================

function extractCN(subject) {
  const m = subject.match(/CN=([^,]+)/);
  return m ? m[1] : subject;
}

// ============================================
// CERTIFICATES
// ============================================

function searchCertificates() {
  certSearch = $('#certSearch')?.value || '';
  certPage = 1;
  loadCertificates();
}

async function loadCertificates() {
  const list = $('#certList');
  if (!list) return;

  list.innerHTML = '<div class="loading"><div class="spinner"></div>Loading...</div>';

  try {
    const params = new URLSearchParams({ page: certPage, limit: 10 });
    if (certSearch) params.append('search', certSearch);

    const res = await fetch('/api/certificates?' + params);
    const data = await res.json();

    certTotalPages = data.pagination.totalPages;

    if (!data.certificates.length) {
      list.innerHTML = '<div class="empty-state"><p>No certificates found.</p></div>';
      $('#certPagination').innerHTML = '';
      return;
    }

    list.innerHTML = data.certificates.map(c => {
      let statusDisplay = c.status, statusClass = c.status;

      if (c.status === 'probationary') {
        const end = new Date(new Date(c.created_at).getTime() + 7 * 24 * 60 * 60 * 1000);
        const days = Math.ceil((end - Date.now()) / (24 * 60 * 60 * 1000));
        statusDisplay = `Probationary • ${days}d left`;
      } else if (c.status === 'active') {
        statusDisplay = 'Active';
      }

      return `<div class="cert-item" data-id="${c.id}" title="Click to view details">
        <div class="cert-header">
          <div>
            <div class="cert-name">${extractCN(c.subject)}</div>
            <div class="cert-subject">${c.subject}</div>
          </div>
          <span class="status-badge status-${statusClass}">${statusDisplay}</span>
        </div>
        <div class="cert-meta">
          <div class="cert-meta-item"><svg class="icon-sm"><use href="#i-cal"/></svg>Valid: ${new Date(c.not_before).toLocaleDateString()} – ${new Date(c.not_after).toLocaleDateString()}</div>
          <div class="cert-meta-item"><svg class="icon-sm"><use href="#i-refresh"/></svg>Verified: ${new Date(c.last_check_at).toLocaleString()}</div>
        </div>
        <div class="cert-constraints">
          <div class="cert-constraints-label">Name Constraints</div>
          <div class="constraint-tags">
            ${c.name_constraints_dns.map(d => '<span class="constraint-tag">DNS: ' + d + '</span>').join('')}
            ${c.name_constraints_ip.map(ip => '<span class="constraint-tag">IP: ' + ip + '</span>').join('')}
          </div>
        </div>
        <div class="fingerprint"><strong>SHA-512:</strong> ${c.fingerprint_sha512}</div>
      </div>`;
    }).join('');

    renderPagination('certPagination', certPage, certTotalPages, p => {
      certPage = p;
      loadCertificates();
    });
  } catch (e) {
    list.innerHTML = '<div class="empty-state"><p>Failed to load certificates.</p></div>';
  }
}

// ============================================
// AUDIT LOG
// ============================================

async function loadAuditLog() {
  const log = $('#auditLog');
  if (!log) return;

  log.innerHTML = '<div class="loading"><div class="spinner"></div>Loading...</div>';

  try {
    const res = await fetch(`/api/audit?page=${auditPage}&limit=10`);
    const data = await res.json();

    auditTotalPages = data.pagination.totalPages;

    if (!data.logs.length) {
      log.innerHTML = '<div class="empty-state"><p>No verification logs yet.</p></div>';
      $('#auditPagination').innerHTML = '';
      return;
    }

    log.innerHTML = '<div class="table-wrapper"><table class="audit-table"><thead><tr><th>Time</th><th>Subject</th><th>Type</th><th>Target</th><th>Result</th><th>Leaf Hash</th></tr></thead><tbody>' +
      data.logs.map(l => `<tr>
        <td>${new Date(l.checked_at).toLocaleString()}</td>
        <td>${extractCN(l.subject)}</td>
        <td>${l.check_type.toUpperCase()}</td>
        <td style="font-family:var(--font-mono);font-size:.75rem">${l.target}</td>
        <td>${l.success ? '<span style="color:var(--success)">✓ Passed</span>' : '<span style="color:var(--danger)">✗ Failed</span>'}</td>
        <td style="font-family:var(--font-mono);font-size:.625rem">${l.leaf_hash ? l.leaf_hash.substring(0, 12) + '...' : 'N/A'}</td>
      </tr>`).join('') + '</tbody></table></div>';

    renderPagination('auditPagination', auditPage, auditTotalPages, p => {
      auditPage = p;
      loadAuditLog();
    });
  } catch (e) {
    log.innerHTML = '<div class="empty-state"><p>Failed to load audit log.</p></div>';
  }
}

async function verifyAuditLog() {
  const div = $('#auditVerifyResult');
  if (!div) return;

  div.innerHTML = '<div class="loading"><div class="spinner"></div>Verifying integrity...</div>';

  try {
    const res = await fetch('/api/audit/verify');
    const data = await res.json();

    if (data.valid) {
      let details = `<strong>${data.localIntegrity.entriesVerified}/${data.localIntegrity.totalEntries}</strong> entries verified`;

      if (data.merkleTree.currentTreeSize > 0) {
        details += ` • Merkle root: <code>${data.merkleTree.computedRoot?.substring(0, 12)}...</code>`;
      }

      if (data.externalAnchors.rekor.total > 0) {
        details += ` • <strong>${data.externalAnchors.rekor.verified}/${data.externalAnchors.rekor.total}</strong> Rekor anchors confirmed`;
      }

      div.innerHTML = `<div class="message message-success">
        <svg class="icon"><use href="#i-check"/></svg>
        <div>
          <div style="font-weight:600;margin-bottom:.25rem">${data.summary}</div>
          <div style="font-size:.875rem;opacity:.9">${details}</div>
          ${data.externalAnchors.rekor.results.length > 0 ? 
            `<div style="margin-top:.5rem;font-size:.75rem">
              ${data.externalAnchors.rekor.results.map(r => 
                `<a href="${r.searchUrl}" target="_blank" rel="noopener" style="color:inherit;margin-right:1rem">
                  ${r.valid ? '✓' : '✗'} Rekor: ${r.uuid.substring(0, 16)}...
                </a>`
              ).join('')}
            </div>` : ''}
        </div>
      </div>`;
    } else {
      const errorMsg = data.localIntegrity.error || data.merkleTree.error || 'Unknown error';
      div.innerHTML = `<div class="message message-error">
        <svg class="icon"><use href="#i-x"/></svg>
        <div>
          <div style="font-weight:600;margin-bottom:.25rem">${data.summary}</div>
          <div style="font-size:.875rem">${errorMsg}</div>
        </div>
      </div>`;
    }
  } catch (e) {
    div.innerHTML = `<div class="message message-error"><span>Verification failed: ${e.message}</span></div>`;
  }
}

// ============================================
// PAGINATION
// ============================================

function renderPagination(id, current, total, onChange) {
  const el = $('#' + id);
  if (!el || total <= 1) {
    if (el) el.innerHTML = '';
    return;
  }

  let html = `<button class="pagination-btn"${current === 1 ? ' disabled' : ''}>← Prev</button>`;

  const max = 5;
  let start = Math.max(1, current - Math.floor(max / 2));
  let end = Math.min(total, start + max - 1);

  if (end - start < max - 1) {
    start = Math.max(1, end - max + 1);
  }

  if (start > 1) html += '<span class="pagination-info">...</span>';

  for (let i = start; i <= end; i++) {
    html += `<button class="pagination-btn${i === current ? ' active' : ''}">${i}</button>`;
  }

  if (end < total) html += '<span class="pagination-info">...</span>';

  html += `<button class="pagination-btn"${current === total ? ' disabled' : ''}>Next →</button>`;
  html += `<span class="pagination-info">Page ${current} of ${total}</span>`;

  el.innerHTML = html;

  el.querySelectorAll('.pagination-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      if (btn.disabled) return;
      const t = btn.textContent;
      if (t === '← Prev') onChange(current - 1);
      else if (t === 'Next →') onChange(current + 1);
      else onChange(parseInt(t));
    });
  });
}

// ============================================
// MODAL
// ============================================

function openCertModal(id) {
  $('#certModal').style.display = 'flex';
  document.body.style.overflow = 'hidden';
  loadCertificateDetails(id);
}

function closeCertModal() {
  $('#certModal').style.display = 'none';
  document.body.style.overflow = '';
}

async function loadCertificateDetails(id) {
  const content = $('#modalContent');
  const title = $('#modalCertName');

  content.innerHTML = '<div class="loading"><div class="spinner"></div>Loading certificate details...</div>';

  try {
    const res = await fetch(`/api/certificate/${id}`);
    if (!res.ok) throw new Error('Failed to load certificate');

    const c = await res.json();
    title.textContent = extractCN(c.subject);

    const needed = 28;
    const vProg = Math.min(100, (c.total_successful_verifications / needed) * 100);
    const days = Math.floor((Date.now() - new Date(c.created_at).getTime()) / (24 * 60 * 60 * 1000));
    const dProg = Math.min(100, (days / 7) * 100);
    const eligible = c.eligibility_status?.eligible_for_export || c.status === 'active';

    content.innerHTML = `
      <div class="detail-grid">
        <div class="detail-item"><div class="detail-label">Status</div><div class="detail-value"><span class="status-badge status-${c.status}">${c.status}</span></div></div>
        <div class="detail-item"><div class="detail-label">First Seen</div><div class="detail-value">${new Date(c.created_at).toLocaleString()}</div></div>
        <div class="detail-item"><div class="detail-label">Last Verified</div><div class="detail-value">${new Date(c.last_check_at).toLocaleString()}</div></div>
        <div class="detail-item"><div class="detail-label">Next Verification</div><div class="detail-value">${c.next_verification ? new Date(c.next_verification).toLocaleString() : 'Pending'}</div></div>
        <div class="detail-item"><div class="detail-label">Valid From</div><div class="detail-value">${new Date(c.not_before).toLocaleDateString()}</div></div>
        <div class="detail-item"><div class="detail-label">Valid Until</div><div class="detail-value">${new Date(c.not_after).toLocaleDateString()}</div></div>
      </div>
      ${c.status === 'probationary' ? `
        <div class="eligibility-box${eligible ? ' eligible' : ''}">
          <div class="eligibility-title">${eligible ? '✓ Eligible for Promotion' : '⏳ Promotion Progress'}</div>
          <div class="eligibility-details">
            <strong>Time requirement:</strong> ${days}/7 days (${Math.round(dProg)}%)<br>
            <strong>Verification requirement:</strong> ${c.total_successful_verifications}/${needed} checks (${Math.round(vProg)}%)
          </div>
          <div class="progress-bar"><div class="progress-fill" style="width:${Math.min(dProg, vProg)}%"></div></div>
        </div>
      ` : ''}
      <div class="cert-constraints mb-15">
        <div class="cert-constraints-label">Name Constraints</div>
        <div class="constraint-tags">
          ${c.name_constraints_dns.map(d => '<span class="constraint-tag">DNS: ' + d + '</span>').join('')}
          ${c.name_constraints_ip.map(ip => '<span class="constraint-tag">IP: ' + ip + '</span>').join('')}
        </div>
      </div>
      <div class="detail-item mb-15"><div class="detail-label">Subject</div><div class="detail-value mono">${c.subject}</div></div>
      <div class="detail-item mb-15"><div class="detail-label">SHA-512 Fingerprint</div><div class="detail-value mono">${c.fingerprint_sha512}</div></div>
      <div class="modal-section-title">Verification History</div>
      <div class="table-wrapper">
        <table class="cert-audit-table">
          <thead><tr><th>Time</th><th>Type</th><th>Target</th><th>Result</th></tr></thead>
          <tbody id="certAuditBody"><tr><td colspan="4" style="text-align:center;color:var(--text-secondary)">Loading...</td></tr></tbody>
        </table>
      </div>`;

    loadCertificateAudit(id);
  } catch (e) {
    content.innerHTML = `<div class="message message-error"><span>Failed to load certificate: ${e.message}</span></div>`;
  }
}

async function loadCertificateAudit(id) {
  const tbody = $('#certAuditBody');
  if (!tbody) return;

  try {
    const res = await fetch(`/api/certificate/${id}/audit`);
    if (!res.ok) throw new Error('Failed to load audit');

    const data = await res.json();

    if (!data.logs?.length) {
      tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:var(--text-secondary)">No verification history yet</td></tr>';
      return;
    }

    tbody.innerHTML = data.logs.slice(0, 20).map(l => `
      <tr>
        <td>${new Date(l.checked_at).toLocaleString()}</td>
        <td>${l.check_type.toUpperCase()}</td>
        <td style="font-family:var(--font-mono);font-size:.6875rem">${l.target}</td>
        <td>${l.success ? '<span style="color:var(--success)">✓ Passed</span>' : '<span style="color:var(--danger)">✗ Failed</span>'}</td>
      </tr>
    `).join('');
  } catch (e) {
    tbody.innerHTML = '<tr><td colspan="4" style="color:var(--danger)">Failed to load audit history</td></tr>';
  }
}

// ============================================
// INITIALIZATION
// ============================================

document.addEventListener('DOMContentLoaded', () => {
  initRouter();
  highlightRecommendedDownload();
});
