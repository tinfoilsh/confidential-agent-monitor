// Layout for the dashboard view. Owner actions and policy semantics stay in owner.js.
import * as owner from './owner.js';
import { icons } from './dashboard-icons.js';

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const q = (v) => esc(JSON.stringify(v));
export const icon = (name) => Object.hasOwn(icons, name) ? icons[name] : icons.accounts;
export const sections = {
  activity: ['Activity', 'Review requests and follow what your agents are doing.'],
  agents: ['Agents', 'Manage sandboxes, devices, and the actions they can take.'],
  accounts: ['Connections', 'Connect services and control how agents use their data.'],
  catalog: ['Add connection', 'Choose a service to connect to your monitor.'],
  presets: ['Connection preset editor', 'Edit the operations, actions, and setup fields of connection presets.'],
  rules: ['Saved rules', 'Review the permissions you have saved from request approvals.'],
  policy: ['Policy', 'Edit, validate, and review the policy that controls your monitor.'],
  integrations: ['Integrations', 'Connect commands, shells, and MCP clients through Monitor.'],
  settings: ['Settings', 'Manage guardrails, policy, and monitor preferences.'],
};
export function sectionFor(kind) {
  return ({agent: 'agents', 'agent-settings': 'agents', pair: 'agents', account: 'accounts', add: 'accounts', catalog: 'accounts', preset: 'settings', presets: 'settings', policy: 'settings', request: 'activity'})[kind] ?? kind;
}
const buttonLink = (href, title, glyph = 'plus') => `<a class="button primary" href="#${href}">${icon(glyph)}${title}</a>`;
export function navigation(kind, view, records) {
  const counts = { activity: records.filter(r => owner.stateAt(r, Date.now()) === 'pending').length, agents: Object.keys(view.config.identities ?? {}).length, accounts: Object.keys(view.config.accounts ?? {}).length };
  return Object.entries(sections).filter(([key]) => !['catalog', 'presets', 'policy'].includes(key)).map(([key, [title]]) => [key,
    `<a class="nav-item ${sectionFor(kind) === key ? 'on' : ''}" href="#${key}" ${sectionFor(kind) === key ? 'aria-current="page"' : ''}>${icon(key)}<span>${title}</span>${counts[key] ? `<small class="nav-count">${counts[key]}</small>` : ''}</a>`]);
}
export function pageHeader(kind, args, view, records) {
  let [title, description] = sections[kind] ?? ['', ''];
  if (kind === 'agent' || kind === 'agent-settings') [title, description] = [args[0], kind === 'agent' ? 'Set account permissions and review data labels for this agent.' : 'Manage keys, sandbox connectivity, and settings.'];
  if (kind === 'account') [title, description] = [args[0], view.presets[view.config.accounts?.[args[0]]?.preset]?.title ?? 'Connection settings'];
  if (kind === 'pair') [title, description] = ['Pair an agent', 'Give an agent access using its SSH public key.'];
  if (kind === 'add') [title, description] = ['Add ' + (view.presets[args[0]]?.title ?? 'connection'), 'Configure credentials and data access for this connection.'];
  if (kind === 'preset') [title, description] = [args[0] ? 'Preset: ' + args[0] : 'New preset', 'Define connection operations, actions, and setup fields.'];
  if (kind === 'request') {
    const request = records.find(r => r.id === args[0]);
    [title, description] = [request ? owner.requestTitle(request) : 'Request', 'Review the request, policy facts, and approval scope.'];
  }
  let actions = kind === 'agents' ? buttonLink('pair', 'Pair agent') : kind === 'accounts' ? buttonLink('catalog', 'Add connection')
    : kind === 'presets' ? buttonLink('preset', 'New preset') : '';
  actions += `<button onclick="refreshDashboard()" aria-label="Refresh monitor">${icon('refresh')}Refresh</button>`;
  return [['heading', `<div class="page-heading"><div><h1>${esc(title || 'Monitor')}</h1><p>${esc(description)}</p></div><div class="header-actions">${actions}</div></div>`]];
}
export function empty(title, description, action = '', glyph = 'activity') {
  return `<div class="empty-state"><div class="empty-icon">${icon(glyph)}</div><h2>${esc(title)}</h2><p>${esc(description)}</p>${action}</div>`;
}
export function stats(view, records) {
  const pending = records.filter(r => owner.stateAt(r, Date.now()) === 'pending').length;
  return [['stats', `<div class="stats">${[
    ['Awaiting approval', pending, pending ? 'Review before requests expire' : 'No requests waiting', 'clock'],
    ['Paired agents', Object.keys(view.config.identities ?? {}).length, 'Identities managed by this monitor', 'rules'],
    ['Recorded requests', records.length, 'In the current activity log', 'activity'],
  ].map(([title, count, hint, glyph]) => `<div class="stat"><div>${title}${icon(glyph)}</div><strong>${count}</strong><small>${hint}</small></div>`).join('')}</div>`],
    ...(pending ? [['pending', `<div class="pending-notice">${icon('clock')}<span><strong>${pending} ${pending === 1 ? 'request needs' : 'requests need'} your approval.</strong> Agents are waiting to continue.</span><button onclick="filterDashboard('pending')">Review requests</button></div>`]] : [])];
}
export function toolbar(kind, view, records) {
  if (!['activity', 'agents', 'accounts', 'catalog', 'presets'].includes(kind)) return [];
  const select = (id, label, entries) => `<select id="filter-${id}" aria-label="${label}" onchange="filterDashboard('${id}', this.value)"><option value="">${label}</option>${entries.map(([value, text]) => `<option value="${esc(value)}">${esc(text)}</option>`).join('')}</select>`;
  return [['search-' + kind, `<div class="search-field">${icon('search')}<input id="dashboard-search" type="search" aria-label="Search ${sections[kind][0].toLowerCase()}" placeholder="Search ${sections[kind][0].toLowerCase()}…" oninput="filterDashboard('query', this.value)"></div>`],
    ...(kind === 'activity' ? [['status-filter', select('state', 'All statuses', ['pending', 'allowed', 'approved', 'denied', 'refused', 'expired'].map(x => [x, x === 'pending' ? 'Needs approval' : x[0].toUpperCase() + x.slice(1)]))],
      ...['agent', 'account'].map(key => [key + '-filter', select(key, key === 'agent' ? 'All agents' : 'All connections', [...new Set([...Object.keys(key === 'agent' ? view.config.identities ?? {} : view.config.accounts ?? {}), ...records.map(r => key === 'agent' ? r.facts.principal.name : r.facts.account)])].filter(Boolean).sort().map(x => [x, x]))])]
      : [])];
}
export function statusBadge(state) {
  const label = state === 'pending' ? 'Needs approval' : state[0].toUpperCase() + state.slice(1);
  return `<span class="badge status-${esc(state)}">${state === 'pending' ? icon('clock') : ''}${esc(label)}</span>`;
}
export function activity(view, records, filters, dismissed, accountIcon) {
  records = records.map(r => ({ ...r, state: owner.stateAt(r, Date.now()) }));
  const filtered = owner.ordered(records, dismissed).filter(r => (!filters.state || r.state === filters.state)
    && (!filters.agent || r.facts.principal.name === filters.agent) && (!filters.account || r.facts.account === filters.account)
    && `${owner.requestTitle(r)} ${r.facts.principal.name} ${r.facts.account}`.toLowerCase().includes(filters.query.toLowerCase()));
  const pages = Math.max(1, Math.ceil(filtered.length / 50)), page = Math.min(filters.page, pages - 1);
  return [['title', `<div class="resource-heading"><h2>Requests <span class="count">${filtered.length}</span></h2><span>Updates every 5 seconds</span></div>`],
    ...filtered.slice(page * 50, page * 50 + 50).map(r => {
      const decisions = owner.decisions(r);
      return ['request/' + r.id, `<div class="resource-row request-row"><a class="resource-link" href="#request/${encodeURIComponent(r.id)}">${accountIcon(r.facts.account)}<span><strong>${esc(owner.requestTitle(r))}</strong><small>${esc(r.facts.principal.name)} · ${esc(r.facts.account || 'Policy')}</small></span></a>
        <div class="resource-meta">${statusBadge(r.state)}<time title="${esc(new Date(r.time).toLocaleString())}">${esc(new Date(r.time).toLocaleTimeString([], {hour: '2-digit', minute: '2-digit'}))}</time></div>
        <div class="row-actions">${decisions.once ? `<button class="danger" ${r.savingDecision ? 'disabled' : ''} onclick="answer(${q(r.id)}, 'deny')">Deny request</button><button class="primary" ${r.savingDecision ? 'disabled' : ''} onclick="answer(${q(r.id)}, 'once')">Allow once</button>` : `<a class="button" href="#request/${encodeURIComponent(r.id)}">View request${icon('arrow')}</a>`}</div></div>`];
    }),
    ...(filtered.length ? [] : [['empty', empty(records.length ? 'No matching requests' : 'No requests yet', records.length ? 'Try another search or clear the filters.' : 'Requests appear here when an agent uses a connection.', records.length ? '<button onclick="filterDashboard(\'clear\')">Clear filters</button>' : buttonLink('accounts', 'Connect your apps', 'accounts'))]]),
    ['pagination', `<div class="pagination"><span>${filtered.length ? page * 50 + 1 : 0} to ${Math.min((page + 1) * 50, filtered.length)} of ${filtered.length} requests</span><div><button ${page === 0 ? 'disabled' : ''} onclick="filterDashboard('page', ${page - 1})">Previous</button><span>${page + 1} of ${pages}</span><button ${page + 1 === pages ? 'disabled' : ''} onclick="filterDashboard('page', ${page + 1})">Next</button></div></div>`]];
}
export function collection(kind, view, query, connectorIcon, collapsed = new Set(), agentDetails = () => ({ open: false, html: '' })) {
  const identities = view.config.identities ?? {}, accounts = view.config.accounts ?? {};
  let rows;
  if (kind === 'agents') rows = Object.entries(identities).map(([name, id]) => {
    // The CLI enrolls computers as device-<key hash> and workloads as sandbox-<name>.
    const type = /^device-[0-9a-f]{16}$/.test(name) ? 'devices' : name.startsWith('sandbox-') ? 'sandboxes' : 'agents';
    return { name, title: name, type, route: 'agent/' + encodeURIComponent(name), glyph: icon(type), description: `${Object.values(id.accounts ?? {}).filter(a => a.level !== 'off').length} connections · Sandbox connectivity ${id.routes ? 'enabled' : 'disabled'}`, meta: id.profile ? '<span class="badge status-pending">Profiling</span>' : `<span class="muted">${esc(owner.labelStatus(view, view.labels[name] ?? {}))}</span>` };
  });
  else if (kind === 'accounts') rows = Object.entries(accounts).map(([name, a]) => {
    const status = owner.accountStatus(view, name);
    return { name, title: name, route: 'account/' + encodeURIComponent(name), glyph: connectorIcon(a.preset), description: view.presets[a.preset]?.title ?? a.preset, meta: status.blocked ? `<span class="badge status-pending">${status.blocked} tools await review</span>` : status.state === 'error' ? '<span class="badge status-denied">Connection error</span>' : status.state === 'connecting' ? '<span class="badge">Connecting…</span>' : '<span class="badge status-approved">Configured</span>' };
  });
  else rows = owner.catalog(view).flatMap(group => group.presets.map(p => ({ name: p.name, title: p.title, group: group.group, route: (kind === 'catalog' ? 'add/' : 'preset/') + encodeURIComponent(p.name), glyph: connectorIcon(p.name), description: group.title, meta: p.accounts ? `<span class="muted">${p.accounts} ${p.accounts === 1 ? 'connection' : 'connections'}</span>` : '' })));
  rows = rows.filter(row => `${row.name} ${row.title} ${row.description}`.toLowerCase().includes(query.toLowerCase()));
  const [title] = sections[kind];
  const renderRow = row => {
    const label = `${row.glyph}<strong class="collection-name" title="${esc(row.title)}">${esc(row.title)}</strong>${row.group ? '' : `<span class="collection-description">${esc(row.description)}</span>`}<span class="resource-meta">${row.meta}</span>${icon('arrow')}`;
    if (kind !== 'agents') return `<a class="resource-row collection-row" href="#${row.route}">${label}</a>`;
    const key = 'agent/' + encodeURIComponent(row.name), detailID = 'detail/' + key;
    const { open, html } = agentDetails(row.name);
    return `<div class="agent-item"><button class="resource-row collection-row agent-toggle" aria-expanded="${open}" aria-controls="${esc(detailID)}" onclick="toggle(${q(key)})">${label}</button><div class="agent-inline" id="${esc(detailID)}" ${open ? '' : 'hidden'}>${html}</div></div>`;
  };
  const list = (title, rows, group) => {
    const heading = `<h2>${esc(title)} <span class="count">${rows.length}</span></h2>`;
    const content = `<div class="collection-rows">${rows.map(renderRow).join('') || empty(query ? 'No matches' : `No ${title.toLowerCase()} yet`, query ? 'Try a different search.' : kind === 'agents' ? 'Pair an agent with its SSH public key to configure access.' : 'Add a connection to give your agents access to a service.', query ? '' : buttonLink(kind === 'agents' ? 'pair' : 'catalog', kind === 'agents' ? 'Pair agent' : 'Add connection'), kind)}</div>`;
    return group
      ? `<details class="resource-list collection-list" data-group="${esc(kind + '/' + group)}" ${query || !collapsed.has(kind + '/' + group) ? 'open' : ''} ontoggle="toggleCatalogGroup(this)"><summary class="resource-heading">${icon('arrow')}${heading}</summary>${content}</details>`
      : `<div class="resource-list collection-list"><div class="resource-heading">${heading}</div>${content}</div>`;
  };
  if (kind === 'agents' && rows.length) return [['sandboxes', 'Sandboxes'], ['devices', 'Devices'], ['agents', 'Other agents']].flatMap(([type, title]) => {
    const matches = rows.filter(row => row.type === type);
    return matches.length ? [list(title, matches)] : [];
  });
  if (['catalog', 'presets'].includes(kind) && rows.length) return owner.catalog(view).flatMap(group => {
    const matches = rows.filter(row => row.group === group.group);
    return matches.length ? [list(group.title, matches, group.group)] : [];
  });
  return [list(title, rows)];
}
