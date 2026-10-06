'use strict';
/* Password Reuse Risk Analyzer - front end.
   Security notes: all dynamic content is inserted with textContent / DOM APIs (never innerHTML),
   every state-changing request carries the per-run CSRF token, and passwords are only ever sent
   to this same local server. */

const $ = (selector, root = document) => root.querySelector(selector);
const csrf = $('meta[name="csrf-token"]').content;
const tone = (level) => level.toLowerCase();

function h(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value === false || value == null) continue;
    if (key === 'class') node.className = value;
    else if (key.startsWith('on')) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value === true ? '' : value);
  }
  for (const child of children.flat()) {
    if (child === false || child == null) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

async function api(path, { method = 'GET', json, form, signal } = {}) {
  const headers = {};
  let body;
  if (method !== 'GET') headers['X-CSRF-Token'] = csrf;
  if (json !== undefined) { headers['Content-Type'] = 'application/json'; body = JSON.stringify(json); }
  else if (form) body = form;
  const response = await fetch(path, { method, headers, body, signal });
  if (response.status === 204) return null;
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
  return data;
}

function say(element, text, kind = '') { element.textContent = text; element.className = `message ${kind}`.trim(); }
const debounce = (fn, ms) => { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; };
const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;

/* ------------------------------------------------------------------ live strength / reuse feedback */
function liveChecker({ password, sensitivity, mfa, box, meter, text, tips, excludeId = () => null }) {
  let controller;
  const run = debounce(async () => {
    if (!password.value) { box.hidden = true; return; }
    controller?.abort();
    controller = new AbortController();
    try {
      const r = await api('/api/check', {
        method: 'POST', signal: controller.signal,
        json: { password: password.value, sensitivity: sensitivity.value, mfa: mfa.checked, exclude_id: excludeId() },
      });
      const s = r.strength;
      box.hidden = false;
      meter.style.width = `${Math.max(6, s.score)}%`;
      meter.className = s.score >= 80 ? 't-low' : s.score >= 60 ? 't-medium' : s.score >= 40 ? 't-high' : '';
      const ann = s.ann_estimate;
      text.textContent = ann
        ? `Rule-based: ${s.label} · ${s.score}/100 | ANN: ${ann.label} · ${ann.score}/100 (${ann.confidence}% confidence)`
        : `Rule-based: ${s.label} · ${s.score}/100 | ANN model unavailable`;
      tips.replaceChildren(...[
        r.reused && h('li', { class: 'alert-line' }, `Already used for: ${r.reused_on.join(', ')}`),
        r.similar && h('li', { class: 'alert-line' }, `Looks like the password for: ${r.similar_to.join(', ')}`),
        ...s.suggestions.slice(0, 3).map((tip) => h('li', {}, tip)),
      ].filter(Boolean));
    } catch (error) {
      if (error.name !== 'AbortError') { box.hidden = false; text.textContent = error.message; tips.replaceChildren(); }
    }
  }, 450);
  [password, sensitivity, mfa].forEach((el) => el.addEventListener(el === password ? 'input' : 'change', run));
  return run;
}

/* ------------------------------------------------------------------ password generator */
function randomInt(max) {
  const limit = Math.floor(0x100000000 / max) * max;
  const buffer = new Uint32Array(1);
  do { crypto.getRandomValues(buffer); } while (buffer[0] >= limit);
  return buffer[0] % max;
}
function generatePassword(length = 20) {
  const sets = ['abcdefghijkmnopqrstuvwxyz', 'ABCDEFGHJKLMNPQRSTUVWXYZ', '23456789', '!@#$%^&*-_=+?'];
  const all = sets.join('');
  const chars = sets.map((set) => set[randomInt(set.length)]);
  while (chars.length < length) chars.push(all[randomInt(all.length)]);
  for (let i = chars.length - 1; i > 0; i--) { const j = randomInt(i + 1); [chars[i], chars[j]] = [chars[j], chars[i]]; }
  return chars.join('');
}

/* ------------------------------------------------------------------ dialogs */
function confirmDialog({ title, text, okText = 'Confirm', requireText = null }) {
  const dialog = $('#confirm-dialog'), input = $('#c-type'), ok = $('#c-ok');
  $('#c-title').textContent = title; $('#c-text').textContent = text; ok.textContent = okText;
  $('#c-type-wrap').hidden = !requireText; input.value = '';
  return new Promise((resolve) => {
    const done = (value) => { dialog.close(); cleanup(); resolve(value); };
    const submit = (event) => { event.preventDefault(); if (!requireText || input.value === requireText) done(true); else input.focus(); };
    const cancel = () => done(false);
    const cleanup = () => { $('#confirm-form').removeEventListener('submit', submit); $('#c-cancel').removeEventListener('click', cancel); dialog.removeEventListener('cancel', cancel); };
    $('#confirm-form').addEventListener('submit', submit);
    $('#c-cancel').addEventListener('click', cancel);
    dialog.addEventListener('cancel', cancel);
    dialog.showModal();
  });
}

/* ------------------------------------------------------------------ rendering */
let data = null;
const filters = { q: '', level: 'all', sort: 'risk' };

function renderStatus(status) {
  $('#status-chips').replaceChildren(
    h('li', { class: status.breach_check ? 'warn' : 'ok' },
      status.breach_check ? 'Breach check ON: sends a 5-character hash prefix to HIBP' : 'Offline: nothing leaves this device'),
    h('li', { class: 'ok' }, 'scrypt + HMAC fingerprints'),
    h('li', { class: status.passphrase_protected ? 'ok' : 'warn' }, status.passphrase_protected ? 'Master passphrase active' : 'No master passphrase (optional)'),
  );
}

function renderSummary({ summary }) {
  const health = summary.health;
  const gauge = $('#gauge');
  gauge.style.setProperty('--pct', health ? health.score : 0);
  gauge.className = `gauge ${health ? (health.score >= 80 ? 't-low' : health.score >= 65 ? 't-medium' : health.score >= 50 ? 't-high' : 't-critical') : ''}`;
  $('#health-score').textContent = health ? health.score : '–';
  $('#health-grade').textContent = health ? `GRADE ${health.grade}` : '';
  $('#accounts').textContent = summary.accounts;
  $('#reused').textContent = summary.reused_accounts;
  $('#similar').textContent = summary.similar_accounts;
  $('#weak').textContent = summary.weak_accounts;
  $('#stale').textContent = summary.stale_accounts;
  $('#stale-days').textContent = data.settings.stale_days;
  $('#mfa').textContent = summary.mfa_coverage == null ? '–' : `${summary.mfa_coverage}%`;
}

function renderRecommendations({ recommendations }) {
  $('#recs').replaceChildren(...(recommendations.length
    ? recommendations.map((r) => h('li', { class: `p${r.priority}` }, h('strong', {}, r.title), h('span', {}, r.detail)))
    : [h('li', { class: 'empty' }, data.summary.accounts ? 'Nothing urgent. Keep passwords unique and enable two-factor authentication.' : 'Add an account to get personalised recommendations.')]));
}

function renderAlerts({ reuse_groups: reuse, similar_groups: similar }) {
  const cards = [
    ...reuse.map((g) => h('article', { class: `alert ${tone(g.level)}` },
      h('span', { class: `badge ${tone(g.level)}` }, `${g.level} · ${g.score}/100`),
      h('h3', {}, g.platforms.join(' ↔ ')),
      h('p', {}, `One password protects ${plural(g.platforms.length, 'account')}. ${g.factors.slice(1).map((f) => f.label).join('; ')}${g.factors.length > 1 ? '.' : ''}`))),
    ...similar.map((g) => h('article', { class: `alert ${tone(g.level)}` },
      h('span', { class: `badge ${tone(g.level)}` }, `Look-alike · ${g.score}/100`),
      h('h3', {}, g.platforms.join(' ≈ ')),
      h('p', {}, 'Different passwords built on the same base word. Attackers try obvious variations like a new year or symbol.'))),
  ];
  $('#alerts').replaceChildren(...(cards.length ? cards : [h('p', { class: 'empty' }, 'No reuse found yet. Add account records to check them.')]));
}

function renderGraph({ graph }) {
  const svg = $('#graph'), NS = 'http://www.w3.org/2000/svg';
  const make = (tag, attrs = {}, text) => { const el = document.createElementNS(NS, tag); for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v); if (text) el.textContent = text; return el; };
  svg.replaceChildren();
  if (!graph.nodes.length) { svg.append(make('text', { x: 380, y: 190 }, 'Add accounts to see how they connect.')); return; }
  const cx = 380, cy = 190, rx = 270, ry = 130, n = graph.nodes.length, spot = {};
  graph.nodes.forEach((node, i) => {
    const angle = (2 * Math.PI * i) / n - Math.PI / 2;
    spot[node.id] = [n === 1 ? cx : cx + rx * Math.cos(angle), n === 1 ? cy : cy + ry * Math.sin(angle)];
  });
  graph.edges.forEach((e) => svg.append(make('line', { class: `edge ${e.type}`, x1: spot[e.source][0], y1: spot[e.source][1], x2: spot[e.target][0], y2: spot[e.target][1] })));
  graph.nodes.forEach((node) => {
    const [x, y] = spot[node.id];
    const g = make('g');
    const circle = make('circle', { class: `node ${tone(node.level)}${node.linked ? '' : ' faded'}`, cx: x, cy: y, r: 11 });
    circle.append(make('title', {}, `${node.label} - ${node.level} risk`));
    g.append(circle, make('text', { x, y: y + (y > cy ? 28 : -18) }, node.short.length > 18 ? `${node.short.slice(0, 17)}…` : node.short));
    svg.append(g);
  });
}

function visibleEntries() {
  const q = filters.q.trim().toLowerCase();
  const order = { risk: (a, b) => b.risk_score - a.risk_score || a.label.localeCompare(b.label),
    name: (a, b) => a.label.localeCompare(b.label),
    age: (a, b) => b.password_age_days - a.password_age_days,
    strength: (a, b) => (a.strength ? a.strength.score : 101) - (b.strength ? b.strength.score : 101) };
  return data.entries
    .filter((e) => (filters.level === 'all' || e.risk_level === filters.level) && (!q || e.label.toLowerCase().includes(q)))
    .sort(order[filters.sort]);
}

function describeAge(days) { return days < 1 ? 'Changed today' : days < 60 ? `Changed ${plural(days, 'day')} ago` : `Changed ${Math.round(days / 30)} months ago`; }

function renderTable() {
  const rows = visibleEntries();
  $('#entries').replaceChildren(...(rows.length ? rows.map((e) => h('tr', {},
    h('td', {}, h('strong', {}, e.platform), e.legacy && h('span', { class: 'tag', title: 'Created by the old version: re-enter its password with Update to upgrade it.' }, 'legacy'), e.username && h('small', {}, e.username)),
    h('td', {}, e.sensitivity.charAt(0).toUpperCase() + e.sensitivity.slice(1)),
    h('td', {}, h('span', { 'aria-label': e.mfa_enabled ? '2FA on' : '2FA off' }, e.mfa_enabled ? '✓' : '—')),
    h('td', {}, e.strength ? `${e.strength.label} · ${e.strength.score}` : 'Unknown', h('small', {}, describeAge(e.password_age_days), e.stale && ' ⚠')),
    h('td', {}, e.risk_factors.length
      ? h('details', {}, h('summary', {}, h('span', { class: `badge ${tone(e.risk_level)}` }, `${e.risk_level} · ${e.risk_score}/100`)),
          h('ul', {}, e.risk_factors.map((f) => h('li', {}, `${f.label} (${f.points > 0 ? '+' : ''}${f.points})`))))
      : h('span', { class: `badge ${tone(e.risk_level)}` }, `${e.risk_level} · ${e.risk_score}/100`)),
    h('td', {}, e.reused_with.length || e.similar_with.length
      ? [e.reused_with.length ? h('small', {}, `Same: ${e.reused_with.join(', ')}`) : null, e.similar_with.length ? h('small', {}, `Similar: ${e.similar_with.join(', ')}`) : null]
      : '—'),
    h('td', {}, h('button', { class: 'link', type: 'button', onclick: () => openEdit(e) }, 'Update'),
      h('button', { class: 'link del', type: 'button', onclick: () => removeEntry(e) }, 'Delete'))))
    : [h('tr', {}, h('td', { colspan: 7, class: 'empty' }, data.entries.length ? 'No records match the filter.' : 'No local records.'))]));
}

function renderAll() { renderSummary(data); renderRecommendations(data); renderAlerts(data); renderGraph(data); renderTable(); }
async function loadDashboard() { data = await api('/api/dashboard'); renderAll(); }

/* ------------------------------------------------------------------ actions */
async function removeEntry(entry) {
  if (!(await confirmDialog({ title: `Delete ${entry.label}?`, text: 'This removes the record from this app only. It does not change the password on the real service.', okText: 'Delete' }))) return;
  try { await api(`/api/entries/${entry.id}`, { method: 'DELETE' }); say($('#table-message'), `Deleted ${entry.label}.`, 'success'); await loadDashboard(); }
  catch (error) { say($('#table-message'), error.message, 'error'); }
}

let editing = null, editCheck;
function openEdit(entry) {
  editing = entry;
  $('#edit-title').textContent = `Update ${entry.label}`;
  $('#e-platform').value = entry.platform; $('#e-username').value = entry.username;
  $('#e-sensitivity').value = entry.sensitivity; $('#e-mfa').checked = entry.mfa_enabled;
  $('#e-password').value = ''; $('#e-live').hidden = true; say($('#e-message'), '');
  $('#edit-dialog').showModal();
}

/* ------------------------------------------------------------------ wiring */
const form = $('#entry-form');
const addCheck = liveChecker({ password: $('#f-password'), sensitivity: $('#f-sensitivity'), mfa: $('#f-mfa'),
  box: $('#f-live'), meter: $('#f-meter'), text: $('#f-strength-text'), tips: $('#f-tips') });
editCheck = liveChecker({ password: $('#e-password'), sensitivity: $('#e-sensitivity'), mfa: $('#e-mfa'),
  box: $('#e-live'), meter: $('#e-meter'), text: $('#e-strength-text'), tips: $('#e-tips'), excludeId: () => editing && editing.id });

let sensitivityTouched = false;
$('#f-sensitivity').addEventListener('change', () => { sensitivityTouched = true; });
$('#f-platform').addEventListener('input', debounce(async (event) => {
  if (sensitivityTouched || event.target.value.trim().length < 2) return;
  try { $('#f-sensitivity').value = (await api(`/api/suggest?platform=${encodeURIComponent(event.target.value)}`)).sensitivity; addCheck(); } catch { /* optional nicety */ }
}, 300));

$('#toggle-pw').addEventListener('click', (event) => {
  const field = $('#f-password'), show = field.type === 'password';
  field.type = show ? 'text' : 'password'; event.target.textContent = show ? 'Hide' : 'Show'; event.target.setAttribute('aria-pressed', String(show));
});
$('#gen-pw').addEventListener('click', async () => {
  const value = generatePassword(20), field = $('#f-password');
  field.value = value; field.type = 'text'; $('#toggle-pw').textContent = 'Hide'; $('#toggle-pw').setAttribute('aria-pressed', 'true');
  addCheck();
  let copied = false;
  try { await navigator.clipboard.writeText(value); copied = true; } catch { /* clipboard may be unavailable */ }
  say($('#form-message'), copied ? 'Generated and copied. Save it in your password manager, then set it on the real service.' : 'Generated. Copy it into your password manager.', 'success');
});

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const button = $('button[type=submit]', form); button.disabled = true;
  say($('#form-message'), 'Checking…');
  try {
    const r = await api('/api/entries', { method: 'POST', json: {
      platform: $('#f-platform').value, username: $('#f-username').value, password: $('#f-password').value,
      sensitivity: $('#f-sensitivity').value, mfa: $('#f-mfa').checked } });
    say($('#form-message'), r.message, r.reused || r.similar || r.breach_count ? 'warning' : r.strength.score < 40 ? 'warning' : 'success');
    form.reset(); sensitivityTouched = false; $('#f-live').hidden = true; $('#f-password').type = 'password';
    $('#toggle-pw').textContent = 'Show'; $('#toggle-pw').setAttribute('aria-pressed', 'false');
    await loadDashboard();
  } catch (error) { say($('#form-message'), error.message, 'error'); }
  finally { button.disabled = false; }
});

$('#edit-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const payload = { platform: $('#e-platform').value, username: $('#e-username').value, sensitivity: $('#e-sensitivity').value, mfa: $('#e-mfa').checked };
  if ($('#e-password').value) payload.password = $('#e-password').value;
  try {
    const r = await api(`/api/entries/${editing.id}`, { method: 'PUT', json: payload });
    $('#edit-dialog').close(); say($('#table-message'), r.message, r.reused || r.similar ? 'warning' : 'success'); await loadDashboard();
  } catch (error) { say($('#e-message'), error.message, 'error'); }
});
$('#e-cancel').addEventListener('click', () => $('#edit-dialog').close());

$('#q').addEventListener('input', (e) => { filters.q = e.target.value; renderTable(); });
$('#level').addEventListener('change', (e) => { filters.level = e.target.value; renderTable(); });
$('#sort').addEventListener('change', (e) => { filters.sort = e.target.value; renderTable(); });

$('#import-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const file = $('#import-file').files[0]; if (!file) return;
  const button = $('button', event.target); button.disabled = true;
  say($('#tools-message'), 'Fingerprinting passwords locally - large files can take a minute…');
  try {
    const body = new FormData(); body.append('file', file);
    const r = await api('/api/import', { method: 'POST', form: body });
    say($('#tools-message'), `Imported ${plural(r.imported, 'account')}; skipped ${r.skipped_duplicates} duplicate(s) and ${r.skipped_invalid} invalid row(s). ${r.note} Now delete the CSV file from your computer.`, 'success');
    event.target.reset(); await loadDashboard();
  } catch (error) { say($('#tools-message'), error.message, 'error'); }
  finally { button.disabled = false; }
});

$('#erase-all').addEventListener('click', async () => {
  if (!(await confirmDialog({ title: 'Erase every record?', text: 'All account records on this device will be deleted. This cannot be undone.', okText: 'Erase all', requireText: 'ERASE' }))) return;
  try { const r = await api('/api/entries', { method: 'DELETE', json: { confirm: 'ERASE' } }); say($('#tools-message'), `Erased ${plural(r.deleted, 'record')}.`, 'success'); await loadDashboard(); }
  catch (error) { say($('#tools-message'), error.message, 'error'); }
});

Promise.all([api('/api/status').then(renderStatus), loadDashboard()])
  .catch((error) => say($('#form-message'), `Could not load data: ${error.message}`, 'error'));
