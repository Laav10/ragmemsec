(() => {
  'use strict';

  const $ = id => document.getElementById(id);
  const state = { data: null, view: 'overview', selected: null, busy: false, error: '', pendingIdentity: null };
  const viewNames = { overview: 'Overview', requests: 'Requests', documents: 'Documents', memory: 'Saved context', activity: 'Activity' };
  const pageCopy = {
    overview: ['Access workspace', 'Manage access requests, supporting documents and their authorization status in one place.'],
    requests: ['Requests', 'Review decisions and the status of requests submitted in this workspace.'],
    documents: ['Documents', 'Manage the supporting document available to your next access request.'],
    memory: ['Saved context', 'Inspect notes that can inform later requests in this workspace.'],
    activity: ['Activity', 'A chronological record of requests and workspace changes.']
  };
  const el = (tag, className, value) => { const node = document.createElement(tag); if (className) node.className = className; if (value !== undefined) node.textContent = String(value); return node; };
  const append = (parent, ...children) => { children.forEach(child => parent.append(child)); return parent; };
  const text = (value, fallback = '—') => value === null || value === undefined || value === '' ? fallback : String(value);
  const initials = name => String(name || '').split(/\s+/).slice(0, 2).map(word => word[0] || '').join('').toUpperCase();
  const titleCase = word => String(word || '').replaceAll('_', ' ').replace(/\b\w/g, match => match.toUpperCase());
  const current = () => state.data || {};
  const selectedIdentity = () => (current().principals || []).find(person => person.member_id === current().selected_member_id);
  const history = () => current().history || [];
  const latest = () => history().at(-1);

  async function api(path, body = {}) {
    const response = await fetch('/api/live/' + path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    let value;
    try { value = await response.json(); } catch { throw new Error('The workspace returned an unreadable response.'); }
    if (!response.ok) throw new Error(value.error || 'The request could not be completed.');
    return value;
  }

  async function action(path, body = {}) {
    if (state.busy) return false;
    state.busy = true;
    state.error = '';
    renderNotice();
    setBusy(true);
    try {
      state.data = await api(path, body);
      if (path === 'request') state.selected = latest()?.sequence || null;
      if (path === 'identity' || path === 'reset') state.selected = null;
      render();
      return true;
    } catch (error) {
      state.error = error.message || String(error);
      renderNotice();
      return false;
    } finally {
      state.busy = false;
      setBusy(false);
    }
  }

  function setBusy(busy) {
    const active = Boolean(current().active);
    for (const id of ['newRequestButton', 'submitRequest', 'manageDocumentButton', 'formDocumentButton', 'confirmIdentity', 'confirmClear', 'confirmReset']) $(id).disabled = busy || !active;
    $('identitySelect').disabled = busy || !active;
    $('submitRequest').textContent = busy ? 'Processing request…' : 'Submit request  →';
    $('connectionLabel').textContent = busy ? (active ? 'Processing request' : 'Connecting to workspace') : active ? 'Workspace connected' : state.error ? 'Workspace unavailable' : 'Connecting to workspace';
    document.querySelector('.live-dot').classList.toggle('is-offline', !busy && !active && Boolean(state.error));
  }

  function renderNotice() {
    const node = $('notice');
    node.hidden = !state.error;
    node.replaceChildren();
    if (!state.error) return;
    node.append(el('span', 'notice-message', state.error));
    if (!current().active) {
      const retry = el('button', 'notice-retry', 'Retry connection');
      retry.type = 'button';
      retry.addEventListener('click', () => action('start'));
      node.append(retry);
    }
  }

  function setView(view) {
    if (!viewNames[view]) return;
    state.view = view;
    for (const key of Object.keys(viewNames)) $('view-' + key).hidden = key !== view;
    document.querySelectorAll('[data-view]').forEach(node => node.classList.toggle('active', node.dataset.view === view));
    $('breadcrumbView').textContent = viewNames[view];
    $('pageTitle').textContent = pageCopy[view][0];
    $('pageDescription').textContent = pageCopy[view][1];
    $('pageScroll').scrollTop = 0;
  }

  function status(trace) {
    if (trace.errors?.length || !trace.parsed_decision) return ['Needs review', 'error'];
    const result = trace.tool_result || {};
    if (result.granted === true || result.exported === true) return ['Authorized', 'approved'];
    if (result.status === 'requires_approval') return ['Approval needed', 'pending'];
    if (result.status === 'denied') return ['Denied', 'denied'];
    return ['Checked', 'checked'];
  }

  function pill(label, tone) { return el('span', 'status-pill ' + tone, label); }
  function requestTitle(trace) { return trace.operation === 'export' ? 'Data export' : 'Database access'; }
  function resourceTitle(trace) {
    const args = trace.tool_call?.arguments || {};
    if (trace.operation === 'export') return titleCase(args.sensitivity || 'Sensitive') + ' · Client Vault';
    return titleCase(args.database || 'Production') + ' database · Project Orion';
  }
  function stamp(value) { const date = new Date(value || Date.now()); return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString([], { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' }); }
  function shortId(trace) { return String(trace.query_id || ('REQ-' + trace.sequence)).toUpperCase(); }

  function empty(icon, heading, detail, buttonText, handler) {
    const box = el('div', 'empty-state');
    append(box, el('div', 'empty-icon', icon), el('strong', '', heading), el('p', '', detail));
    if (buttonText) { const button = el('button', 'secondary-button', buttonText); button.type = 'button'; button.addEventListener('click', handler); box.append(button); }
    return box;
  }

  function requestTable(items) {
    if (!items.length) return empty('▤', 'No requests yet', 'Submit a request to see its decision and authorization status here.', 'Create a request', openRequest);
    const table = el('table', 'request-table');
    const head = el('thead');
    const heading = el('tr');
    ['Request', 'Submitted', 'Status'].forEach(label => heading.append(el('th', '', label)));
    head.append(heading);
    const body = el('tbody');
    [...items].reverse().forEach(trace => {
      const row = el('tr', trace.sequence === state.selected ? 'selected' : '');
      row.tabIndex = 0;
      row.setAttribute('role', 'button');
      row.setAttribute('aria-label', 'View ' + requestTitle(trace) + ' details');
      const name = el('td');
      append(name, el('span', 'request-name', requestTitle(trace)), el('span', 'request-secondary', resourceTitle(trace)), el('span', 'request-id', shortId(trace)));
      append(row, name, el('td', '', stamp(trace.timestamp)), el('td'));
      row.lastChild.append(pill(...status(trace)));
      row.addEventListener('click', () => selectRequest(trace.sequence));
      row.addEventListener('keydown', event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); selectRequest(trace.sequence); } });
      body.append(row);
    });
    append(table, head, body);
    return table;
  }

  function documentRow(name, detail, active = false) {
    const row = el('div', 'document-row');
    const words = el('div', 'document-row-text');
    append(words, el('strong', '', name), el('small', '', detail));
    append(row, el('span', 'file-icon', 'MD'), words);
    if (active) row.append(pill('Active', 'approved'));
    return row;
  }

  function renderDocuments() {
    const kind = current().attachment_kind;
    const overview = $('overviewDocuments');
    overview.replaceChildren(kind ? documentRow(kind === 'setup' ? 'setup_guide.md' : 'migration_reference.md', 'Available for the next access request', true) : el('div', 'quiet-empty', 'No supporting document selected.'));
    const list = $('documentList');
    list.replaceChildren();
    if (kind) list.append(documentRow(kind === 'setup' ? 'setup_guide.md' : 'migration_reference.md', 'Currently available to the workspace', true));
    else list.append(empty('▧', 'No document selected', 'Attach an available document when you need to provide supporting context.', 'Manage document', () => $('documentDialog').showModal()));
    $('formDocumentName').textContent = kind === 'setup' ? 'setup_guide.md' : kind === 'reference' ? 'migration_reference.md' : 'No document attached';
    document.querySelector('.remove-option').hidden = !kind;
  }

  function renderMemory() {
    const list = $('memoryList');
    list.replaceChildren();
    const items = current().memories || [];
    $('navMemoryCount').textContent = items.length;
    $('clearDerivedButton').hidden = !items.some(item => item.attacker_derived);
    if (!items.length) { list.append(empty('◷', 'No saved context', 'Notes produced during a request will appear here when the memory writer stores them.')); return; }
    items.forEach(item => {
      const row = el('div', 'memory-row');
      const main = el('div', 'memory-row-text');
      append(main, el('strong', '', titleCase(item.memory_type || 'Saved note')), el('small', '', `Saved ${stamp(item.created_at)} · ${item.source_ids?.length || 0} source references`), el('p', '', item.text));
      const remove = el('button', 'secondary-button', 'Remove');
      remove.type = 'button';
      remove.addEventListener('click', () => { if (confirm('Remove this saved note from the current workspace?')) action('memory/delete', { memory_id: item.id }); });
      append(row, el('span', 'activity-marker', '◷'), main, remove);
      list.append(row);
    });
  }

  function renderActivity() {
    const list = $('activityList');
    list.replaceChildren();
    const entries = [
      ...history().map(trace => ({ sequence: trace.sequence, kind: 'request', value: trace })),
      ...(current().events || []).map(event => ({ sequence: event.sequence, kind: 'event', value: event }))
    ].sort((a, b) => b.sequence - a.sequence);
    if (!entries.length) { list.append(empty('≡', 'No activity yet', 'Requests and document changes will be recorded here.')); return; }
    entries.forEach(entry => {
      const row = el('div', 'activity-row');
      const main = el('div', 'activity-row-text');
      let heading, detail;
      if (entry.kind === 'request') {
        heading = requestTitle(entry.value) + ' · ' + status(entry.value)[0];
        detail = shortId(entry.value) + ' · ' + resourceTitle(entry.value);
      } else {
        const event = entry.value;
        heading = ({ attachment_added: 'Document attached', attachment_removed: 'Document removed', derived_memory_cleared: 'Document-derived notes cleared', memory_deleted: 'Saved note removed' })[event.kind] || 'Workspace updated';
        detail = event.attachment_kind === 'setup' ? 'setup_guide.md' : event.attachment_kind === 'reference' ? 'migration_reference.md' : 'Current workspace';
      }
      append(main, el('strong', '', heading), el('small', '', detail));
      append(row, el('span', 'activity-marker', entry.kind === 'request' ? '↗' : '•'), main);
      if (entry.kind === 'request') { const open = el('button', 'text-button', 'Details →'); open.type = 'button'; open.addEventListener('click', () => selectRequest(entry.value.sequence)); row.append(open); }
      list.append(row);
    });
  }

  function fact(label, value) { const line = el('div'); append(line, el('dt', '', label), el('dd', '', text(value))); return line; }
  function inspectorSection(heading, content) { const section = el('section', 'inspector-section'); append(section, el('h4', '', heading), content); return section; }
  function renderInspector() {
    const body = $('inspectorBody');
    body.replaceChildren();
    const trace = history().find(item => item.sequence === state.selected);
    if (!trace) {
      $('inspectorTitle').textContent = 'Request details';
      const box = el('div', 'inspector-empty');
      append(box, el('div', 'empty-icon', '▤'), el('strong', '', 'Select a request'), el('p', '', 'Authorization details and retrieved context will appear here.'));
      body.append(box);
      return;
    }
    $('inspectorTitle').textContent = 'Request details';
    const headline = el('div', 'inspector-headline');
    append(headline, el('small', '', shortId(trace)), el('h3', '', requestTitle(trace)), pill(...status(trace)));
    body.append(headline);
    const identity = (current().principals || []).find(item => item.member_id === trace.member_id);
    const info = el('dl', 'detail-list');
    append(info, fact('Member', identity?.display_name || trace.member_id), fact('Member ID', trace.member_id), fact('Resource', resourceTitle(trace)), fact('Submitted', stamp(trace.timestamp)), fact('Approval ID', trace.tool_call?.arguments?.approval_id || 'Not supplied'));
    body.append(inspectorSection('Request', info));
    const decision = el('div', 'decision-box');
    append(decision, el('strong', '', 'Model proposal: ' + titleCase(trace.parsed_decision?.decision || 'unavailable')), el('p', '', trace.parsed_decision?.answer || trace.parsed_decision?.reason || (trace.errors?.length ? 'The model could not complete this request.' : 'No decision was returned.')));
    const outcome = el('dl', 'detail-list');
    const tool = trace.tool_result || {};
    append(outcome, fact('Tool', trace.tool_call?.tool_name || 'Not proposed'), fact('Authorization', titleCase(tool.status || 'Not run')), fact('Effect', tool.granted === true || tool.exported === true ? 'Permitted by simulator' : 'No protected change'));
    const result = el('div'); append(result, decision, outcome);
    if (trace.parsed_decision?.decision === 'allowed' && tool.status === 'requires_approval') result.append(el('div', 'inspector-warning', 'The model proposed allowing this request, but the authorization service required approval. No protected effect occurred.'));
    if (tool.reason === 'requester_mismatch') result.append(el('div', 'inspector-warning', 'The proposed tool call named a different member and was blocked by the session identity guard.'));
    body.append(inspectorSection('Decision & authorization', result));
    const tags = el('div', 'inspector-tags');
    const docs = trace.retrieved_documents || [];
    const memories = trace.retrieved_memories || [];
    docs.forEach(doc => tags.append(el('span', 'inspector-tag', doc.title || doc.record_id || 'Document')));
    memories.forEach(() => tags.append(el('span', 'inspector-tag', 'Saved note')));
    if (!docs.length && !memories.length) tags.append(el('span', 'inspector-tag', 'No context retrieved'));
    body.append(inspectorSection('Context used', tags));
    const note = trace.memory_write_result?.stored ? 'A note was saved for later requests.' : 'No new note was saved.';
    body.append(inspectorSection('Continuity', el('div', 'decision-box', note)));
    if (trace.errors?.length) body.append(inspectorSection('Error', el('div', 'inspector-warning', trace.errors.join(' · '))));
  }

  function selectRequest(sequence) { state.selected = sequence; renderRequests(); renderInspector(); $('inspectorBody').scrollTop = 0; $('inspector').classList.add('open'); }
  function renderRequests() {
    $('overviewRequests').replaceChildren(requestTable(history().slice(-5)));
    $('allRequests').replaceChildren(requestTable(history()));
    $('navRequestCount').textContent = history().length;
    $('requestTotal').textContent = history().length + (history().length === 1 ? ' request' : ' requests');
  }

  function renderIdentity() {
    const members = current().principals || [];
    const person = selectedIdentity();
    const picker = $('identitySelect');
    picker.replaceChildren(...members.map(member => { const option = el('option', '', member.display_name + ' · ' + member.member_id); option.value = member.member_id; return option; }));
    picker.value = current().selected_member_id || '';
    const name = person?.display_name || 'Select member';
    const role = titleCase(person?.role || 'Member');
    for (const id of ['identityName', 'profileName', 'formIdentity']) $(id).textContent = name;
    for (const id of ['identityAvatar', 'profileAvatar', 'formAvatar']) $(id).textContent = initials(name);
    $('identityRole').textContent = role;
    $('profileRole').textContent = role;
    $('profileMemberId').textContent = person?.member_id || '—';
    $('profileWorkspace').textContent = person?.administrator ? 'Administrator member' : 'Member session';
  }

  function render() {
    renderNotice();
    renderIdentity();
    renderRequests();
    renderDocuments();
    renderMemory();
    renderActivity();
    renderInspector();
    $('workspaceShort').textContent = current().session_id ? current().session_id.slice(0, 8).toUpperCase() : 'WORKSPACE';
    $('metricRequests').textContent = history().length;
    $('metricPending').textContent = history().filter(trace => status(trace)[1] === 'pending').length;
    $('metricAuthorized').textContent = current().authorized_effects || 0;
    $('modelLabel').textContent = current().model_id || 'Qwen 3 8B';
    setView(state.view);
  }

  function openRequest() { if (!current().active) return; $('requestDialog').showModal(); $('message').focus(); }
  function setOperation() {
    const exportType = $('operation').value === 'export';
    $('resource').replaceChildren(...(exportType ? [['sensitive', 'Sensitive data'], ['non_sensitive', 'Non-sensitive data']] : [['production', 'Production database'], ['development', 'Development database']]).map(([value, label]) => { const option = el('option', '', label); option.value = value; return option; }));
  }

  document.querySelectorAll('[data-view]').forEach(node => node.addEventListener('click', () => setView(node.dataset.view)));
  $('newRequestButton').addEventListener('click', openRequest);
  $('closeRequest').addEventListener('click', () => $('requestDialog').close());
  $('cancelRequest').addEventListener('click', () => $('requestDialog').close());
  $('operation').addEventListener('change', setOperation);
  $('requestForm').addEventListener('submit', async event => {
    event.preventDefault();
    const payload = { operation: $('operation').value, message: $('message').value.trim(), approval_id: $('approval').value.trim() || null, use_scenario_prompt: false };
    if (!payload.message) { $('message').focus(); return; }
    if (payload.operation === 'export') payload.sensitivity = $('resource').value;
    else payload.database = $('resource').value;
    const success = await action('request', payload);
    if (success) { $('requestDialog').close(); $('requestForm').reset(); setOperation(); setView('requests'); $('inspector').classList.add('open'); }
  });
  $('manageDocumentButton').addEventListener('click', () => $('documentDialog').showModal());
  $('formDocumentButton').addEventListener('click', () => $('documentDialog').showModal());
  $('closeDocument').addEventListener('click', () => $('documentDialog').close());
  document.querySelectorAll('[data-document]').forEach(node => node.addEventListener('click', async () => { const kind = node.dataset.document; const result = kind === 'remove' ? await action('attachment', { present: false }) : await action('attachment', { present: true, kind }); if (result) $('documentDialog').close(); }));
  $('identitySelect').addEventListener('change', event => { const selected = event.target.value; if (selected === current().selected_member_id) return; state.pendingIdentity = selected; $('identityDialog').showModal(); });
  $('cancelIdentity').addEventListener('click', () => { $('identitySelect').value = current().selected_member_id || ''; state.pendingIdentity = null; $('identityDialog').close(); });
  $('confirmIdentity').addEventListener('click', async () => { const success = await action('identity', { member_id: state.pendingIdentity }); if (success) { state.pendingIdentity = null; $('identityDialog').close(); setView('overview'); $('inspector').classList.remove('open'); } });
  $('clearDerivedButton').addEventListener('click', () => $('clearDialog').showModal());
  $('cancelClear').addEventListener('click', () => $('clearDialog').close());
  $('confirmClear').addEventListener('click', async () => { if (await action('ablate')) $('clearDialog').close(); });
  $('resetWorkspaceButton').addEventListener('click', () => $('resetDialog').showModal());
  $('cancelReset').addEventListener('click', () => $('resetDialog').close());
  $('confirmReset').addEventListener('click', async () => { if (await action('reset')) { $('resetDialog').close(); setView('overview'); $('inspector').classList.remove('open'); } });
  $('closeInspector').addEventListener('click', () => $('inspector').classList.remove('open'));
  $('exportActivityButton').addEventListener('click', () => {
    const data = current();
    const blob = new Blob([JSON.stringify({ session_id: data.session_id, member_id: data.selected_member_id, model_id: data.model_id, history: data.history || [], events: data.events || [] }, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = el('a'); link.href = url; link.download = 'ragmemsec-activity-' + String(data.session_id || 'workspace').slice(0, 8) + '.json'; document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
  setOperation();
  render();
  action('start');
})();
