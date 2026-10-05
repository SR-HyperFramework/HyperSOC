'use strict';
const $ = id => document.getElementById(id);
const state = { user: null, csrf: '', incidents: [], incidentId: null, view: 'incidents', selection: 0 };
const node = (tag, text = '', className = '') => { const item = document.createElement(tag); item.textContent = text; if (className) item.className = className; return item; };
const displayTime = value => value ? new Date(value).toLocaleString() : 'Not recorded';
function notice(text = '', error = false) { $('notice').textContent = text; $('notice').className = error ? 'error' : ''; }
async function api(path, options = {}) {
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  if (state.csrf && options.method && options.method !== 'GET') headers['X-SOC-CSRF'] = state.csrf;
  const response = await fetch(path, { ...options, headers, credentials: 'same-origin' });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (response.status === 401 && path !== '/api/v1/auth/login') showLogin();
    const detail = typeof payload.detail === 'string' ? payload.detail : `Request failed (${response.status})`;
    throw new Error(detail);
  }
  return payload;
}
function showLogin() { $('login-panel').hidden = false; $('workspace').hidden = true; $('logout').hidden = true; $('account').textContent = ''; }
function canWrite() { return state.user && state.user.role !== 'viewer'; }
function button(text, action, disabled = false, primary = false) {
  const element = node('button', text, primary ? 'primary' : ''); element.type = 'button'; element.disabled = disabled;
  element.addEventListener('click', async () => {
    if (element.disabled) return;
    element.disabled = true; notice();
    try { await action(); } catch (error) { notice(error.message, true); } finally { element.disabled = disabled; }
  });
  return element;
}
function badge(text, kind = '') { return node('span', text, `badge ${kind}`); }
function section(title, collapsed = false) {
  const container = node(collapsed ? 'details' : 'section', '', 'surface');
  container.append(node(collapsed ? 'summary' : 'h2', title)); return container;
}
function list(parent, values, empty = 'No records available.') {
  if (!values.length) { parent.append(node('p', empty, 'muted')); return; }
  const ul = node('ul'); for (const value of values) ul.append(node('li', value)); parent.append(ul);
}
function json(parent, value) { parent.append(node('pre', JSON.stringify(value, null, 2))); }
async function initialize() {
  try {
    const user = await api('/api/v1/auth/me'); state.user = user; state.csrf = user.csrf_token || '';
    $('account').textContent = `${user.username} (${user.role})`;
    $('login-panel').hidden = true; $('workspace').hidden = false; $('logout').hidden = !user.authenticated;
    await refresh();
  } catch (error) { showLogin(); if (error.message !== 'Authentication required') notice(error.message, true); }
}
async function refresh() {
  const summary = await api('/api/v1/dashboard/summary'); $('summary').replaceChildren();
  for (const [key, label] of [['open_incidents', 'open incidents'], ['critical_incidents', 'critical'], ['alerts_last_24h', 'alerts in 24 hours']]) {
    const value = node('span'); value.append(node('strong', String(summary[key])), document.createTextNode(label)); $('summary').append(value);
  }
  if (state.view === 'incidents') await loadIncidents();
  else if (state.view === 'hub') await loadEntities();
  else await loadWorkflows();
}
async function loadIncidents() {
  const filter = $('status-filter').value;
  state.incidents = await api('/api/v1/incidents?limit=100' + (filter ? '&status=' + encodeURIComponent(filter) : ''));
  $('incident-list').replaceChildren();
  if (!state.incidents.length) $('incident-list').append(node('p', 'No incidents match this view. Forward alerts from a connected source or choose another status.', 'muted'));
  for (const incident of state.incidents) {
    const item = button('', () => loadCase(incident.id)); item.className = `incident ${incident.severity}`;
    item.setAttribute('aria-pressed', String(state.incidentId === incident.id));
    item.append(node('strong', incident.title), node('small', `${incident.severity} / ${incident.status}`), node('small', `${incident.alert_count} alerts / ${displayTime(incident.last_seen)}`));
    $('incident-list').append(item);
  }
}
async function loadCase(id) {
  const selection = ++state.selection; state.incidentId = id; notice('Loading incident evidence…');
  const [incident, runs, context, actions] = await Promise.all([
    api(`/api/v1/incidents/${id}`), api(`/api/v1/incidents/${id}/investigations?limit=1`),
    api(`/api/v1/hub/incidents/${id}/context`), api(`/api/v1/incidents/${id}/actions`)
  ]);
  const alerts = await Promise.all(incident.alert_ids.slice(0, 30).map(alertId => api(`/api/v1/alerts/${alertId}`)));
  if (selection !== state.selection) return;
  const run = runs[0]; const target = $('case'); target.replaceChildren();
  const header = node('div', '', 'case-header'); const heading = node('div'); heading.append(node('h1', incident.title));
  const badges = node('div', '', 'badges'); badges.append(badge(incident.severity, incident.severity), badge(incident.status), badge(`${incident.alert_count} alerts`)); heading.append(badges);
  heading.append(node('p', `${incident.primary_host || 'Unknown asset'} / ${incident.primary_user || 'Unknown identity'} / ${incident.primary_src_ip || 'No source IP'}`, 'muted'));
  header.append(heading, button('Run investigation', async () => { await api(`/api/v1/incidents/${id}/investigations`, { method: 'POST' }); await loadCase(id); }, !canWrite(), true)); target.append(header);
  const columns = node('div', '', 'columns'); const findings = section('Findings'); const review = section('Analyst decision'); columns.append(findings, review); target.append(columns);
  if (!run) {
    findings.append(node('p', 'No investigation report is available yet. The automation worker will process this incident, or an analyst can run an investigation.', 'muted'));
    review.append(node('p', 'A report is required before recording a decision.', 'muted'));
  } else {
    findings.append(badge(run.report.classification.replaceAll('_', ' ')), node('p', `${run.status} / ${displayTime(run.created_at)}`, 'muted'));
    if (!run.report.findings.length) findings.append(node('p', 'No supported findings were reported.', 'muted'));
    for (const finding of run.report.findings) {
      const li = node('p', finding.claim, 'finding');
      for (const evidenceId of finding.evidence_ids) li.append(button(evidenceId, () => {
        const evidence = document.getElementById(`evidence-${evidenceId}`); if (evidence) { evidence.closest('details').open = true; evidence.scrollIntoView({ block: 'center' }); evidence.focus(); }
      })); findings.append(li);
    }
    findings.append(node('h3', 'Gaps')); list(findings, run.report.gaps, 'No gaps listed.');
    findings.append(node('h3', 'Next steps')); list(findings, run.report.next_steps, 'No next steps listed.');
    renderReview(review, run, id);
  }
  const evidence = section('Source evidence', true); target.append(evidence);
  if (run) {
    for (const item of run.evidence) {
      const entry = node('div', '', 'evidence-item'); entry.id = `evidence-${item.id}`; entry.tabIndex = -1;
      entry.append(node('strong', `${item.id}: ${item.source}`), node('small', `${item.source_ref} / ${displayTime(item.observed_at || item.collected_at)}`));
      let content = item.content; try { content = JSON.stringify(JSON.parse(content), null, 2); } catch (_) { /* plain text evidence */ }
      entry.append(node('pre', content)); evidence.append(entry);
    }
  } else evidence.append(node('p', 'The evidence ledger will appear after investigation.', 'muted'));
  const timeline = section('Linked alert timeline', true); target.append(timeline);
  for (const alert of alerts.sort((a,b) => a.timestamp.localeCompare(b.timestamp))) {
    const item = node('div', '', 'evidence-item'); item.append(node('strong', alert.rule_description || 'Detection'), node('small', `${displayTime(alert.timestamp)} / ${alert.source} / ${alert.id}`));
    if (alert.process_command_line) item.append(node('pre', alert.process_command_line)); timeline.append(item);
  }
  if (incident.alert_ids.length > 30) timeline.append(node('p', 'Showing the first 30 linked alerts. The incident retains all alert references.', 'muted'));
  const internal = section('Internal context', true); target.append(internal); internal.append(node('h3', 'Coverage gaps')); list(internal, context.gaps, 'No coverage gaps recorded.');
  for (const [name, items] of [['Assets', context.assets], ['Identities', context.identities]]) { internal.append(node('h3', name)); if (items.length) json(internal, items); else internal.append(node('p', `No ${name.toLowerCase()} inventory available.`, 'muted')); }
  internal.append(node('h3', 'Historical incidents')); if (context.historical_incidents.length) json(internal, context.historical_incidents); else internal.append(node('p', 'No matching historical incident found.', 'muted'));
  internal.append(node('h3', 'Behavior analysis')); json(internal, context.analytics);
  const graph = section('Entity relationships', true); target.append(graph); renderGraph(graph, context.graph);
  const responses = section('Response approval'); target.append(responses); renderResponses(responses, incident, run, actions);
  await loadIncidents(); notice('Incident evidence loaded.');
}
function renderReview(parent, run, incidentId) {
  if (run.status !== 'PENDING_REVIEW') {
    parent.append(badge(run.final_classification || 'Reviewed', 'context'), node('p', `${run.reviewed_by} / ${displayTime(run.reviewed_at)}`));
    if (run.reviewer_notes) parent.append(node('p', run.reviewer_notes)); return;
  }
  parent.append(node('p', 'Confirm or correct the conclusion after reviewing the cited evidence. This decision does not execute a response.', 'muted'));
  const form = node('form', '', 'form-grid'); const label = node('label', 'Conclusion'); const select = node('select'); select.setAttribute('aria-label', 'Analyst conclusion');
  for (const value of ['true_positive', 'false_positive', 'needs_investigation', 'unknown']) { const option = node('option', value.replaceAll('_', ' ')); option.value = value; select.append(option); } select.value = run.report.classification;
  label.append(select); form.append(label); const notesLabel = node('label', 'Decision notes', 'full'); const notes = node('textarea'); notes.maxLength = 2000; notes.setAttribute('aria-label', 'Decision notes'); notesLabel.append(notes); form.append(notesLabel);
  const save = node('button', 'Save analyst decision', 'primary'); save.type = 'submit'; save.disabled = !canWrite(); form.append(save); parent.append(form);
  form.addEventListener('submit', async event => {
    event.preventDefault(); save.disabled = true;
    try { await api(`/api/v1/investigations/${run.id}/review`, { method: 'POST', body: JSON.stringify({ reviewed_by: state.user.username, classification: select.value, notes: notes.value }) }); await loadCase(incidentId); notice('Analyst decision saved.'); }
    catch (error) { notice(error.message, true); save.disabled = !canWrite(); }
  });
}
function renderResponses(parent, incident, run, actions) {
  parent.append(node('p', 'Request a scoped response, approve it, then explicitly execute it. Execution results identify whether the provider simulated or dispatched the action.', 'muted'));
  const reviewedTP = run && run.status !== 'PENDING_REVIEW' && run.final_classification === 'true_positive';
  for (const action of actions) {
    const row = node('div', '', 'response-row'); row.append(node('strong', `${action.type} ${action.target}`), badge(action.status), node('p', action.reason));
    if (action.approved_by) row.append(node('small', `Approved by ${action.approved_by} at ${displayTime(action.approved_at)}`));
    const controls = node('div', '', 'button-row');
    if (action.status === 'PENDING') {
      controls.append(button('Approve response', async () => { await api(`/api/v1/actions/${action.id}/approve`, { method: 'POST', body: JSON.stringify({ approved_by: state.user.username }) }); await loadCase(incident.id); }, !canWrite() || !reviewedTP));
      controls.append(button('Reject response', async () => { await api(`/api/v1/actions/${action.id}/reject`, { method: 'POST', body: JSON.stringify({ rejected_by: state.user.username, reason: 'Analyst rejected the proposed response.' }) }); await loadCase(incident.id); }, !canWrite()));
      if (!reviewedTP) row.append(node('p', 'The latest investigation needs an analyst-confirmed true-positive conclusion before approval.', 'muted'));
    }
    if (action.status === 'APPROVED') controls.append(button('Execute approved response', async () => { await api(`/api/v1/actions/${action.id}/execute`, { method: 'POST' }); await loadCase(incident.id); }, !canWrite() || !reviewedTP, true));
    row.append(controls);
    if (action.execution_result) {
      const mode = action.execution_result.metadata && action.execution_result.metadata.execution_mode;
      if (mode === 'offline') row.append(node('p', 'Offline simulation. No firewall change was made.', 'muted'));
      if (mode === 'wazuh' && !action.execution_result.metadata.containment_verified) {
        row.append(node('p', 'Command delivery is recorded. Confirm endpoint containment with a response telemetry evidence ID.', 'muted'));
        const verification = node('form', '', 'form-grid');
        const evidenceLabel = node('label', 'Response evidence IDs (comma separated)'); const evidenceId = node('input'); evidenceId.required = true; evidenceId.setAttribute('aria-label', 'Response evidence IDs'); evidenceLabel.append(evidenceId);
        const notesLabel = node('label', 'Verification notes'); const notes = node('input'); notes.required = true; notes.maxLength = 2000; notes.setAttribute('aria-label', 'Verification notes'); notesLabel.append(notes);
        const save = node('button', 'Verify endpoint containment'); save.type = 'submit'; save.disabled = !canWrite(); verification.append(evidenceLabel, notesLabel, save); row.append(verification);
        verification.addEventListener('submit', async event => {
          event.preventDefault(); save.disabled = true;
          try { await api(`/api/v1/actions/${action.id}/verify`, { method: 'POST', body: JSON.stringify({ evidence_ids: evidenceId.value.split(',').map(value => value.trim()).filter(Boolean), notes: notes.value }) }); await loadCase(incident.id); }
          catch (error) { notice(error.message, true); save.disabled = !canWrite(); }
        });
      }
      json(row, action.execution_result);
    }
    parent.append(row);
  }
  const form = node('form', '', 'form-grid'); const ipLabel = node('label', 'IP address to block'); const ip = node('input'); ip.value = incident.primary_src_ip || ''; ip.required = true; ip.maxLength = 512; ip.setAttribute('aria-label', 'IP address to block'); ipLabel.append(ip);
  const reasonLabel = node('label', 'Response reason'); const reason = node('input'); reason.required = true; reason.maxLength = 2000; reason.setAttribute('aria-label', 'Response reason'); reasonLabel.append(reason);
  const save = node('button', 'Request BLOCK_IP'); save.type = 'submit'; save.disabled = !canWrite(); form.append(ipLabel, reasonLabel, save); parent.append(node('h3', 'New response request'), form);
  form.addEventListener('submit', async event => {
    event.preventDefault(); save.disabled = true;
    try { await api(`/api/v1/incidents/${incident.id}/actions`, { method: 'POST', body: JSON.stringify({ type: 'BLOCK_IP', target: ip.value, reason: reason.value, requested_by: state.user.username }) }); await loadCase(incident.id); }
    catch (error) { notice(error.message, true); save.disabled = !canWrite(); }
  });
}
function renderGraph(parent, graph) {
  if (!graph.nodes.length) { parent.append(node('p', 'No recorded relationships are available for this entity.', 'muted')); return; }
  const namespace = 'http://www.w3.org/2000/svg'; const svg = document.createElementNS(namespace, 'svg'); svg.classList.add('graph'); svg.setAttribute('viewBox', '0 0 900 450'); svg.setAttribute('role', 'img'); svg.setAttribute('aria-label', 'Observed entity relationship graph');
  const title = document.createElementNS(namespace, 'title'); title.textContent = 'Observed entity relationships'; svg.append(title);
  const visible = graph.nodes.slice(0, 25); const positions = new Map();
  visible.forEach((entity, index) => { positions.set(entity.id, index === 0 ? [95, 225] : [250 + Math.floor((index - 1) / 6) * 175, 45 + ((index - 1) % 6) * 70]); });
  for (const edge of graph.edges) {
    const a = positions.get(edge.source_id), b = positions.get(edge.target_id); if (!a || !b) continue;
    const line = document.createElementNS(namespace, 'line'); line.setAttribute('x1', a[0]); line.setAttribute('y1', a[1]); line.setAttribute('x2', b[0]); line.setAttribute('y2', b[1]); svg.append(line);
  }
  visible.forEach((entity, index) => {
    const [x,y] = positions.get(entity.id); const circle = document.createElementNS(namespace, 'circle'); circle.setAttribute('cx', x); circle.setAttribute('cy', y); circle.setAttribute('r', index === 0 ? 25 : 16); if (index === 0) circle.classList.add('root');
    const label = document.createElementNS(namespace, 'text'); label.setAttribute('x', x); label.setAttribute('y', y + 31); label.setAttribute('text-anchor', 'middle'); label.textContent = entity.label.length > 24 ? entity.label.slice(0,21) + '…' : entity.label;
    const description = document.createElementNS(namespace, 'title'); description.textContent = `${entity.kind}: ${entity.label}`; circle.append(description); svg.append(circle, label);
  }); parent.append(svg);
  const edges = node('ul', '', 'edge-list'); const names = new Map(graph.nodes.map(entity => [entity.id, entity.label]));
  for (const edge of graph.edges.slice(0,50)) edges.append(node('li', `${names.get(edge.source_id) || edge.source_id} → ${edge.relation.replaceAll('_', ' ')} → ${names.get(edge.target_id) || edge.target_id} [${edge.source_ref}]`)); parent.append(edges);
  if (graph.truncated) parent.append(node('p', 'The query reached its relationship budget. This graph may omit additional relationships.', 'muted'));
  if (graph.nodes.length > 25) parent.append(node('p', 'The drawing shows the first 25 nodes. Returned relationship references are listed below it.', 'muted'));
}
async function loadEntities() {
  const kind = $('entity-kind').value; const entities = await api('/api/v1/hub/entities?limit=100' + (kind ? '&kind=' + encodeURIComponent(kind) : ''));
  $('entity-list').replaceChildren();
  if (!entities.length) $('entity-list').append(node('p', 'No entities are available. Ingest security evidence or import inventory into the Hub.', 'muted'));
  for (const entity of entities) {
    const item = button('', async () => { const graph = await api(`/api/v1/hub/entities/${entity.id}/graph`); $('entity-graph').replaceChildren(); $('entity-graph').append(node('h3', entity.label), node('p', `${entity.kind} / ${entity.source} / ${displayTime(entity.observed_at)}`, 'muted')); renderGraph($('entity-graph'), graph); json($('entity-graph'), entity.attributes); });
    item.className = 'entity-button'; item.append(node('strong', entity.label), node('small', `${entity.kind} / ${entity.source}`)); $('entity-list').append(item);
  }
}
async function loadWorkflows() {
  const jobs = await api('/api/v1/workflows?limit=100'); $('workflow-list').replaceChildren();
  if (!jobs.length) $('workflow-list').append(node('p', 'No automation jobs exist yet. New ingested alerts are queued when automation is enabled.', 'muted'));
  const stages = ['understanding','internal_context','enrichment','correlation','conclusion','analyst_review'];
  for (const job of jobs) {
    const row = node('article', '', 'workflow'); const heading = node('header'); heading.append(node('strong', `Alert ${job.alert_id.slice(0,8)}`), badge(job.status)); row.append(heading, node('p', `Attempts: ${job.attempts} / Updated: ${displayTime(job.updated_at)}`, 'muted'));
    const steps = node('ol', '', 'stages'); const current = stages.indexOf(job.stage);
    stages.forEach((stage,index) => steps.append(node('li', stage.replaceAll('_',' '), index < current ? 'done' : index === current ? 'current' : ''))); row.append(steps);
    if (job.error) row.append(node('p', job.error));
    if (['FAILED','RETRY'].includes(job.status)) row.append(button('Retry processing', async () => { await api(`/api/v1/workflows/${job.id}/retry`, { method: 'POST' }); await loadWorkflows(); }, !canWrite()));
    const detail = node('details'); detail.append(node('summary', 'Processing evidence')); json(detail, job.output); row.append(detail); $('workflow-list').append(row);
  }
}
document.querySelectorAll('[data-view]').forEach(item => item.addEventListener('click', async () => {
  state.view = item.dataset.view; document.querySelectorAll('[data-view]').forEach(tab => tab.setAttribute('aria-pressed', String(tab === item)));
  for (const view of ['incidents','hub','workflows']) $(`${view}-view`).hidden = view !== state.view;
  try { await refresh(); } catch (error) { notice(error.message, true); }
}));
$('refresh').addEventListener('click', async () => { try { await refresh(); if (state.incidentId && state.view === 'incidents') await loadCase(state.incidentId); } catch (error) { notice(error.message, true); } });
$('status-filter').addEventListener('change', () => loadIncidents().catch(error => notice(error.message, true)));
$('entity-kind').addEventListener('change', () => loadEntities().catch(error => notice(error.message, true)));
$('login-form').addEventListener('submit', async event => {
  event.preventDefault(); const submit = event.currentTarget.querySelector('button'); submit.disabled = true;
  try { const result = await api('/api/v1/auth/login', { method: 'POST', body: JSON.stringify({ username: $('username').value, password: $('password').value }) }); state.csrf = result.csrf_token; $('password').value = ''; notice(); await initialize(); }
  catch (error) { notice(error.message, true); } finally { submit.disabled = false; }
});
$('logout').addEventListener('click', async () => { try { await api('/api/v1/auth/logout', { method: 'POST' }); state.user = null; state.csrf = ''; showLogin(); notice('Signed out.'); } catch (error) { notice(error.message, true); } });
initialize();
