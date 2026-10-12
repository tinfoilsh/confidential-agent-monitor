import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import test from 'node:test';
import assert from 'node:assert/strict';
import * as ownerModule from './app/owner.js';

const source = readFileSync(new URL('./app/index.html', import.meta.url), 'utf8')
  .match(/<script type="module">([\s\S]*)<\/script>/)[1].replace(/^import .*$/m, '').split('window.addEventListener')[0];
const fixture = () => ({ generation: 1, config: {
  accounts: { work: { preset: 'custom' } },
  identities: { bot: { accounts: { work: { level: 'ask' } }, rules: {} }, other: { accounts: {} } },
}, presets: { custom: { title: 'Custom', actions: {}, operations: [], fields: [], vocabulary: {} } },
labels: { bot: { trust: 'trusted', audience: 'me' } }, status: {}, fields: {} });

function app() {
  const requests = [], notices = [], elements = new Map();
  const storage = () => {
    const entries = new Map();
    return { getItem: key => entries.get(key) ?? null, setItem: (key, value) => entries.set(key, String(value)), removeItem: key => entries.delete(key) };
  };
  const context = vm.createContext({
    owner: ownerModule, URL, URLSearchParams, structuredClone, setTimeout: () => 1, clearTimeout() {}, location: { hash: '#agent/bot' }, localStorage: storage(), sessionStorage: storage(),
    document: { title: '', getElementById(id) { if (!elements.has(id)) elements.set(id, { focus() {} }); return elements.get(id); } },
    fetch(path, options = {}) {
      path = path.replace(/^\/api/, "");
      if (path === 'icons/manifest.json') return Promise.resolve({ ok: true, json: async () => ({}) });
      return new Promise(resolve => requests.push({ path, method: options.method, body: options.body && JSON.parse(options.body),
        respond(body, status = 200) { resolve({ ok: status >= 200 && status < 300, status, text: async () => typeof body === 'string' ? body : JSON.stringify(body) }); },
      }));
    }, fixture: fixture(), notices,
  });
  vm.runInContext(source, context);
  vm.runInContext('ownerSession = "test-local-session"; render = () => {}; toast = message => notices.push(message); remember(fixture);', context);
  return { requests, notices, elements, context, run: code => vm.runInContext(code, context),
    state: () => JSON.parse(vm.runInContext('JSON.stringify({view, records, pending: pendingEdits.length})', context)),
  };
}
function editedValues(request) {
  assert.equal(request.method, 'POST');
  assert.equal(request.path, '/policy/edits');
  const result = {};
  for (const { path, value, delete: remove } of request.body.changes) {
    let parent = result;
    for (const part of path.slice(0, -1)) parent = parent[part] ??= {};
    parent[path.at(-1)] = remove ? null : value;
  }
  return result;
}
const tick = () => new Promise(resolve => setImmediate(resolve));
const level = a => a.state().view.config.identities.bot.accounts.work.level;

test('opening a new bridge session in an existing tab reloads the session bootstrap', () => {
  const a = app();
  a.run('let reloads = 0; let renders = 0; location.reload = () => reloads++; render = () => renders++;');
  a.run('location.hash = "#session=restarted-local-session"; hashChanged();');
  assert.equal(a.run('reloads'), 1);
  assert.equal(a.run('renders'), 0);
  a.run('location.hash = "#policy"; hashChanged();');
  assert.equal(a.run('reloads'), 1);
  assert.equal(a.run('renders'), 1);
});

test('policy drafts survive polling and lose their preview when edited', () => {
  const a = app();
  a.run(String.raw`policyEditor = {source: '# my comment\n', draft: '# my comment\n', preview: {source: 'reviewed'}};
    serverState.view.generation = 2; project(); changePolicy('# my comment\n# another comment\n');`);
  assert.equal(a.run('policyEditor.draft'), '# my comment\n# another comment\n');
  assert.equal(a.run('policyEditor.preview'), null);
  const html = a.run('policyPage().join("\\n")');
  assert.ok(html.includes('disabled onclick="applyPolicySource()"'));
});

test('a policy preview cannot authorize edits made while it was loading', async () => {
  const a = app();
  a.run(`policyEditor = {source: '# original', draft: '# first', preview: null}`);
  const pending = a.run('previewPolicy()');
  assert.equal(a.requests[0].path, '/policy/preview');
  assert.deepEqual(a.requests[0].body, { source: '# first' });
  a.run('changePolicy("# second")');
  a.requests[0].respond({ source: '# first', source_diff: 'first diff' });
  await pending;
  assert.equal(a.run('policyEditor.preview'), null);
});

test('policy proposal cards render agent text and diffs safely', () => {
  const a = app();
  a.run(`records = [{id: 'p1', state: 'pending', time: '2026-01-01', expires: '2026-01-01', requirements: [{id: 'policy', message: '<img src=x>'}],
    facts: {principal: {name: '<script>bad</script>'}, account: '', title: 'Change policy', details: {policy: {source_diff: '<unsafe>', effective_diff: ''}}}}];`);
  const html = a.run('requestPane("p1").join("\\n")');
  assert.ok(!html.includes('<script>'));
  assert.ok(!html.includes('<img src=x>'));
  assert.ok(html.includes('&#60;unsafe&#62;'));
  assert.match(html, /answer\('p1', 'once'\)/);
});

// Drive delayed responses explicitly so these checks do not depend on wall-clock timing.
test('rapid edits render immediately and are sent in click order', async () => {
  const a = app();
  const first = a.run('patchAccess("bot", "work", {level: "allow"})');
  assert.equal(level(a), 'allow');
  assert.equal(a.elements.get('saving').hidden, false);
  const second = a.run('patchAccess("bot", "work", {level: "read"})');
  assert.equal(level(a), 'read');
  assert.equal(a.requests.length, 1);
  const saved = fixture(); saved.generation = 2; saved.config.identities.bot.accounts.work.level = 'allow';
  a.requests[0].respond(saved); await first;
  assert.equal(level(a), 'read');
  assert.equal(editedValues(a.requests[1]).identities.bot.accounts.work.level, 'read');
  saved.generation = 3; saved.config.identities.bot.accounts.work.level = 'read';
  a.requests[1].respond(saved); await second;
  assert.equal(level(a), 'read');
  assert.equal(a.elements.get('saving').hidden, true);
});

test('a stale poll cannot overwrite a completed edit, and polling skips pending edits', async () => {
  const a = app();
  const poll = a.run('refresh()');
  const edit = a.run('patchAccess("bot", "work", {level: "allow"})');
  await a.run('refresh()');
  assert.equal(a.requests.length, 3);
  const saved = fixture(); saved.generation = 2; saved.config.identities.bot.accounts.work.level = 'allow';
  a.requests[2].respond(saved); await edit;
  a.requests[0].respond(fixture()); a.requests[1].respond([]); await poll;
  assert.equal(level(a), 'allow');
  assert.equal(a.state().view.generation, 2);
});

test('a failed edit rolls back without discarding a newer edit', async () => {
  const a = app();
  const first = a.run('patchAccess("bot", "work", {level: "allow"})');
  const second = a.run('patchAccess("bot", "work", {actions: {merge: "off"}})');
  a.requests[0].respond('Access rejected', 400); await first;
  assert.equal(level(a), 'ask');
  assert.deepEqual(a.state().view.config.identities.bot.accounts.work.actions, { merge: 'off' });
  assert.ok(a.notices.includes('Access rejected'));
  const saved = fixture(); saved.config.identities.bot.accounts.work.actions = { merge: 'off' };
  a.requests[1].respond(saved); await second;
  assert.equal(level(a), 'ask');
  assert.equal(a.state().pending, 0);
});

test('failed creation restores its route unless the user has navigated elsewhere', async () => {
  for (const navigateAway of [false, true]) {
    const a = app();
    const edit = a.run('patch({accounts: {new: {preset: "custom"}}}, "account/new")');
    assert.equal(a.context.location.hash, '#account/new');
    assert.ok(a.state().view.config.accounts.new);
    if (navigateAway) a.context.location.hash = '#settings';
    a.requests[0].respond('Account rejected', 400); await edit;
    assert.equal(a.state().view.config.accounts.new, undefined);
    assert.equal(a.context.location.hash, navigateAway ? '#settings' : '#agent/bot');
  }
});

test('labels update before the response and roll back on failure', async () => {
  const a = app();
  const edit = a.run('setLabel("bot", {trust: "trusted", audience: "anyone"})');
  assert.equal(a.state().view.labels.bot.audience, 'anyone');
  a.requests[0].respond('Label rejected', 400); await edit;
  assert.equal(a.state().view.labels.bot.audience, 'me');
});

test('decisions update the log, count and saved rules immediately; failures restore them', async () => {
  const a = app();
  a.run('serverState.records = [{id: "1", facts: {principal: {name: "bot"}, account: "work", operation: {action: "write", id: "items.create"}}, state: "pending", requirements: [{id: "ask", message: "Review this request."}]}]; project()');
  const edit = a.run('answer("1", "save")');
  assert.equal(a.state().records[0].state, 'approved');
  assert.equal(a.context.document.title, 'Monitor');
  assert.equal(Object.keys(a.state().view.config.identities.bot.rules).length, 1);
  await a.run('answer("1", "save")');
  assert.equal(a.requests.length, 1, 'a second click must not submit a duplicate decision');
  a.requests[0].respond('Approval expired', 400); await edit;
  assert.equal(a.state().records[0].state, 'pending');
  assert.equal(Object.keys(a.state().view.config.identities.bot.rules).length, 0);
  assert.equal(a.context.document.title, '(1) Monitor');
});

test('a successful decision is not rolled back if the following refresh fails', async () => {
  const a = app();
  a.run('serverState.records = [{id: "1", facts: {principal: {name: "bot"}, account: "work"}, state: "pending"}]; project()');
  const edit = a.run('answer("1", "deny")');
  a.requests[0].respond(''); await edit;
  a.requests[1].respond('Offline', 503); a.requests[2].respond([]); await tick();
  assert.equal(a.state().records[0].state, 'denied');
  assert.ok(a.notices.includes('Offline'));
});

test('copying settings replaces old entries in one request', async () => {
  const a = app();
  a.run('serverState.view.config.identities.other = {accounts: {mail: {level: "read"}}, rules: {saved: {account: "mail", definition: "approved", scope: {nullable: null, retained: "value"}}}}; serverState.view.config.identities.bot.rules.saved = {account: "work", definition: "old", scope: {obsolete: true}}; project(); $("from").value = "other"');
  const edit = a.run('copySettings("bot")');
  assert.deepEqual(a.state().view.config.identities.bot.accounts, { mail: { level: 'read' } });
  assert.equal(a.requests.length, 1);
  assert.deepEqual(editedValues(a.requests[0]).identities.bot.accounts, { mail: { level: 'read' } });
  assert.deepEqual(editedValues(a.requests[0]).identities.bot.rules, { saved: { account: 'mail', definition: 'approved', scope: { nullable: null, retained: 'value' } } });
  a.requests[0].respond('Copy rejected', 400); await edit;
  assert.equal(level(a), 'ask');
});

test('source edits delete overrides, replace arrays and treat object keys as data', () => {
  const a = app();
  const json = a.run('JSON.stringify(owner.applyChanges({actions: {read: "off", write: "ask"}, send: ["a"]}, sourceChanges({actions: {read: null}, send: ["b"]})))');
  assert.deepEqual(JSON.parse(json), { actions: { write: 'ask' }, send: ['b'] });
  a.run('owner.applyChanges({}, sourceChanges(JSON.parse(\'{"__proto__": {"polluted": true}}\')))');
  assert.equal(a.run('({}).polluted'), undefined);
});

test('preset edits update the catalog before the server responds', async () => {
  const a = app();
  const edit = a.run('patch({presets: {custom: {title: "Renamed", catalog: {fields: [], actions: {read: {title: "Read items"}}}}}})');
  assert.equal(a.state().view.presets.custom.title, 'Renamed');
  assert.equal(a.state().view.presets.custom.actions.read.title, 'Read items');
  a.requests[0].respond('Preset rejected', 400); await edit;
  assert.equal(a.state().view.presets.custom.title, 'Custom');
});

const customAPIPreset = JSON.parse(readFileSync(new URL('./presets/custom_api.json', import.meta.url), 'utf8'));
function customAPIApp() {
  const a = app();
  a.context.customAPIPreset = customAPIPreset;
  a.run('serverState.view.presets.custom_api = {...customAPIPreset.catalog, title: customAPIPreset.title}; project(); location.hash = "#add/custom_api"');
  for (const [id, value] of Object.entries({ 'account-name': 'my-app', 'api-url': 'https://API.EXAMPLE.COM:443/v1/', 'api-auth': 'bearer',
    'api-token': 'test-only-credential', 'api-agent': 'bot', 'api-access': 'ask', contents: 'me', sends: 'me' })) a.run(`$(${JSON.stringify(id)}).value = ${JSON.stringify(value)}`);
  a.run('$("strangers").checked = true');
  return a;
}

test('custom API and MCP setup stay first within their own collapsible categories', () => {
  const a = customAPIApp();
  a.run('serverState.view.presets.mcp = {title: "Custom MCP server", group: "mcp"}; serverState.view.presets.airtable = {title: "Airtable", group: "api"}; serverState.view.presets.acme_mcp = {title: "Acme MCP", group: "mcp"}; project(); expanded.add("add"); expanded.add("add-group/api"); expanded.add("add-group/mcp")');
  const html = a.run('sidebar("add", "custom_api").join("")');
  const api = html.indexOf('href="#add/custom_api"'), mcp = html.indexOf('href="#add/mcp"'), airtable = html.indexOf('href="#add/airtable"'), acme = html.indexOf('href="#add/acme_mcp"');
  assert.ok(api >= 0 && api < airtable && airtable < mcp && mcp < acme);
  assert.equal(html.match(/href="#add\/custom_api"/g).length, 1);
  assert.equal(html.match(/href="#add\/mcp"/g).length, 1);
  assert.ok(html.includes('Custom MCP server'));
  a.run('expanded.delete("add-group/api")');
  const apiClosed = a.run('sidebar("add", "mcp").join("")');
  assert.ok(!apiClosed.includes('href="#add/custom_api"'));
  assert.ok(apiClosed.includes('href="#add/mcp"'));
  a.run('expanded.delete("add-group/mcp")');
  assert.ok(!a.run('sidebar("add", "mcp").join("")').includes('href="#add/mcp"'));
});

test('custom API setup creates the account and agent access together, and shows only a placeholder after saving', async () => {
  const a = customAPIApp();
  const save = a.run('addCustomAPI()');
  assert.equal(a.context.location.hash, '#add/custom_api', 'stay on the form until the save succeeds');
  await a.run('addCustomAPI()');
  assert.equal(a.requests.length, 1, 'double submit must not overwrite the new account');
  const body = editedValues(a.requests[0]);
  assert.deepEqual(body.accounts['my-app'].connections[''].http, {
    slots: [{ value: 'token', origin: 'https://api.example.com', path: '/v1', header: 'Authorization', prefix: 'Bearer ' }],
    secrets: { token: 'test-only-credential' },
  });
  assert.deepEqual(body.identities, { bot: { accounts: { 'my-app': { level: 'ask' } } } });
  assert.equal(body.presets, undefined, 'creating an account must not require a user-authored preset');
  const saved = a.state().view; saved.generation = 2;
  saved.config.accounts['my-app'].connections[''].http.secrets.token = null;
  saved.fields['my-app'] = [{ path: ['connections', '', 'http', 'secrets', 'token'], kind: 'static' }];
  a.requests[0].respond(saved); await save;
  assert.equal(a.context.location.hash, 'account/my-app');
  const html = a.run('account("my-app").join("")');
  assert.ok(html.includes('tfm_my-app_token'));
  assert.ok(!html.includes('test-only-credential'));
  assert.ok(html.includes('Configured'));
  assert.ok(html.includes('>Replace</button>'));
  assert.ok(html.includes('>Remove</button>'));
});

test('custom API header and query authentication use only their chosen credential location', async () => {
  for (const auth of ['header', 'query']) {
    const a = customAPIApp();
    a.run(`$("api-auth").value = "${auth}"; $("api-header").value = "X-Service-Key"; $("api-prefix").value = "Token "; $("api-query").value = "key"; $("api-agent").value = ""`);
    const save = a.run('addCustomAPI()');
    const body = editedValues(a.requests[0]), slot = body.accounts['my-app'].connections[''].http.slots[0];
    assert.deepEqual(slot, { value: 'token', origin: 'https://api.example.com', path: '/v1',
      ...(auth === 'header' ? { header: 'X-Service-Key', prefix: 'Token ' } : { query: 'key' }) });
    assert.equal(body.identities, undefined);
    a.requests[0].respond(a.state().view); await save;
  }
});

test('custom API validation rejects credential-bearing URLs and duplicate accounts before sending', async () => {
  for (const url of ['http://api.example.com', 'https://user:password@api.example.com', 'https://api.example.com?key=secret',
    'https://api.example.com#secret', 'https://api.example.com:80', 'not a URL']) {
    const a = customAPIApp();
    a.run(`$("api-url").value = ${JSON.stringify(url)}`);
    await a.run('addCustomAPI()');
    assert.equal(a.requests.length, 0, url);
    assert.equal(a.notices.length, 1);
  }
  const a = customAPIApp();
  a.run('$("account-name").value = "work"');
  await a.run('addCustomAPI()');
  assert.equal(a.requests.length, 0);
  assert.match(a.notices[0], /already exists/);
});

test('a rejected custom API save keeps the form and allows retrying', async () => {
  const a = customAPIApp();
  const save = a.run('addCustomAPI()');
  a.requests[0].respond('The connection name is reserved', 400); await save;
  assert.equal(a.context.location.hash, '#add/custom_api');
  assert.equal(a.state().view.config.accounts['my-app'], undefined);
  assert.equal(a.elements.get('api-add').disabled, false);
  assert.ok(a.notices.includes('The connection name is reserved'));
});

test('editing custom API authentication preserves its credential unless explicitly replaced', async () => {
  const a = customAPIApp();
  a.run('serverState.view.config.accounts.api = {preset: "custom_api", contents: "me", sends: "me", connections: {"": {http: {slots: [{value: "token", origin: "https://api.example.com", path: "/", header: "Authorization", prefix: "Bearer "}], values: {token: null}}}}}; serverState.view.fields.api = [{path: ["connections", "", "http", "values", "token"], kind: "static"}]; project();');
  a.run('$("mode-connections//http/values/token").value = "keep"; $("api-auth").value = "query"; $("api-query").value = "key"');
  const save = a.run('saveAccount("api")');
  const update = editedValues(a.requests[0]).accounts.api.connections[''].http;
  assert.deepEqual(update.slots, [{ value: 'token', origin: 'https://api.example.com', path: '/v1', query: 'key' }]);
  assert.equal(update.values, undefined);
  a.requests[0].respond(a.state().view); await save;
});

function secretApp(oauth = false) {
  const a = app();
  a.context.oauth = oauth;
  a.run(`serverState.view.presets.service = {title: 'Service', defaults: {contents: 'me', sends: 'me'}, actions: {},
    connections: {'': {http: {slots: []}}}, fields: [
      {key: 'client', label: 'Client secret', secret: true, paths: []},
      {key: 'token', label: 'API token', secret: true, path: ['connections', '', 'http', 'values', 'token'],
        ...(oauth ? {oauth: {resource: 'https://service.example', client_secret: '{client}'}} : {})}
    ]}; project(); location.hash = '#add/service'; location.origin = 'http://localhost'; location.pathname = '/';
    $('account-name').value = 'service'; $('contents').value = 'me'; $('sends').value = 'me';
    $('f-client').value = 'test-client'; $('f-token').value = ''; $('token-field-token').hidden = oauth;`);
  return a;
}

function savedSecret(a, kind = 'static') {
  const saved = a.state().view;
  saved.config.accounts.service.connections[''].http.values = { token: null };
  saved.fields.service = [{ path: ['connections', '', 'http', 'values', 'token'], kind }];
  return saved;
}

test('preset setup leaves blank secrets unset and preserves pasted values exactly', async () => {
  for (const token of ['', '  test-only-token  ', 'test-only-key\nsecond line\n']) {
    const a = secretApp();
    a.run(`$('f-token').value = ${JSON.stringify(token)}`);
    const save = a.run('addAccount("service")');
    assert.equal(editedValues(a.requests[0]).accounts.service.connections[''].http.values.token, token || null);
    assert.equal(editedValues(a.requests[0]).accounts.service.client, undefined, 'setup-only secrets are not stored as settings');
    a.requests[0].respond(savedSecret(a, token ? 'static' : 'unset')); await save;
  }
});

test('OAuth setup saves its grant before starting sign-in and prevents duplicate creation', async () => {
  const a = secretApp(true);
  const save = a.run('addAccount("service", "token")');
  await a.run('addAccount("service", "token")');
  assert.equal(a.requests.length, 1);
  assert.deepEqual(editedValues(a.requests[0]).accounts.service.connections[''].http.values.token,
    { oauth: { resource: 'https://service.example', client_secret: 'test-client' } });
  assert.equal(a.context.location.hash, '#add/service');
  a.requests[0].respond(savedSecret(a, 'oauth-required')); await tick();
  assert.equal(a.requests[1].path, '/accounts/service/sign-in');
  assert.deepEqual(a.requests[1].body, {path: ['connections', '', 'http', 'values', 'token'], redirect: 'http://localhost/'});
  a.requests[1].respond({url: 'https://service.example/authorize'}); await save;
  assert.equal(a.context.location.href, 'https://service.example/authorize');
  assert.equal(a.run('sessionStorage.getItem(RETURN)'), 'account/service');
});

test('a rejected OAuth account save does not start sign-in and allows retrying', async () => {
  const a = secretApp(true);
  const save = a.run('addAccount("service", "token")');
  a.requests[0].respond('Account rejected', 400); await save;
  assert.equal(a.context.location.hash, '#add/service');
  assert.equal(a.elements.get('account-add').disabled, false);
  assert.ok(a.requests.every(r => !r.path.includes('sign-in')));
  assert.ok(a.notices.includes('Account rejected'));
});

test('OAuth setup can defer sign-in or use an optional pasted access token', async () => {
  for (const token of [undefined, '', '  test-only-token  ']) {
    const a = secretApp(true);
    if (token !== undefined) a.run(`$('token-field-token').hidden = false; $('f-token').value = ${JSON.stringify(token)}`);
    const save = a.run('addAccount("service")');
    const value = editedValues(a.requests[0]).accounts.service.connections[''].http.values.token;
    if (token === undefined) assert.equal(value.oauth.client_secret, 'test-client');
    else assert.equal(value, token || null);
    a.requests[0].respond(savedSecret(a, token === undefined ? 'oauth-required' : token ? 'static' : 'unset')); await save;
    assert.equal(a.requests.length, 1);
  }
});

test('credential edits preserve, replace, and explicitly remove saved values', async () => {
  for (const action of ['keep', 'replace', 'clear', 'cancel-replace', 'cancel-clear']) {
    const a = secretApp();
    const create = a.run('addAccount("service")');
    a.requests[0].respond(savedSecret(a)); await create;
    const key = 'connections//http/values/token';
    a.run(`credentialMode('service', ${JSON.stringify(key)}, '${action.replace('cancel-', '')}')`);
    if (action.endsWith('replace')) a.run(`$('f-${key}').value = '  replacement  '`);
    if (action.startsWith('cancel-')) {
      a.run(`credentialMode('service', ${JSON.stringify(key)}, 'keep')`);
      assert.equal(a.elements.get('credential-edit-' + key).innerHTML, '');
    }
    const save = a.run('saveAccount("service")');
    const connections = editedValues(a.requests[1]).accounts?.service?.connections;
    if (action === 'replace') assert.equal(a.requests[1].body.changes.length, 1, 'a credential replacement must not resubmit unchanged policy settings');
    if (action === 'replace' || action === 'clear') assert.equal(connections[''].http.values.token, action === 'clear' ? null : '  replacement  ');
    else assert.equal(connections, undefined);
    a.requests[1].respond(savedSecret(a, action === 'clear' ? 'unset' : 'static')); await save;
    assert.equal(a.elements.get('mode-' + key).value, 'keep');
    assert.equal(a.elements.get('credential-edit-' + key).innerHTML, '');
    assert.deepEqual(a.notices, ['Account added', 'Saved']);
  }
});

test('an empty replacement cannot silently erase an existing secret', async () => {
  const a = secretApp();
  const create = a.run('addAccount("service")');
  a.requests[0].respond(savedSecret(a)); await create;
  a.run(`credentialMode('service', 'connections//http/values/token', 'replace'); $('f-connections//http/values/token').value = ''`);
  await a.run('saveAccount("service")');
  assert.equal(a.requests.length, 1);
  assert.match(a.notices.at(-1), /Enter a value/);
});

const browserApp = () => {
  const a = app();
  a.run('serverState.view.config.accounts.web = {preset: "custom", connections: {"": {browser: {}}}}; project(); ownerSession = "key"; location.hash = "#account/web"; liveSync()');
  return a;
};
const frame = (owner, token, extra = {}) => ({ owner, frame: token, url: 'http://site/', screenshot: 'AAAA', tabs: [{ id: 't1', url: 'http://site/', title: 'Site', active: true }], ...extra });
const owner = a => a.run('live.frame?.owner');

test('a poll sent before a pause cannot undo it, whichever response arrives first', async () => {
  for (const pollFirst of [false, true]) {
    const a = browserApp();
    assert.equal(a.requests[0].method, 'GET');
    const pause = a.run('liveOwn()');
    assert.deepEqual(a.requests[1].body, { action: 'pause' });
    assert.equal(a.elements.get('live-take').disabled, true);
    if (pollFirst) { a.requests[0].respond(frame(false, 'old')); await tick(); }
    assert.equal(owner(a), undefined);
    a.requests[1].respond(frame(true, 'new')); await pause;
    if (!pollFirst) { a.requests[0].respond('stale failure', 503); await tick(); }
    assert.equal(owner(a), true);
    assert.equal(a.elements.get('live-error').hidden, true);
    assert.equal(a.elements.get('live-take').textContent, 'Return to agent');
    assert.equal(a.elements.get('live-input').disabled, false);
  }
});

test('a failed pause keeps the confirmed owner and looks again; a capture failure keeps control and the dialog usable', async () => {
  const a = browserApp();
  a.requests[0].respond(frame(false, 'a')); await tick();
  const pause = a.run('liveOwn()');
  a.requests[1].respond('timed out', 504); await pause;
  assert.ok(a.notices.includes('timed out'));
  assert.equal(owner(a), false);
  assert.equal(a.elements.get('live-take').textContent, 'Pause and take control');
  assert.equal(a.requests[2].method, 'GET');
  a.requests[2].respond(frame(true, undefined, { screenshot: undefined, url: undefined, error: 'capture timed out' })); await tick();
  assert.equal(owner(a), true);
  assert.equal(a.elements.get('live-input').disabled, true, 'input needs a frame to aim at');
  assert.equal(a.elements.get('live-dialog').disabled, false);
  assert.equal(a.elements.get('live-error').hidden, false);
  a.run('liveAct({action: "dialog", accept: false})');
  assert.deepEqual(a.requests[3].body, { action: 'dialog', accept: false });
});

test('leaving the account stops polling but still reports a failed return of control', async () => {
  const a = browserApp();
  a.requests[0].respond(frame(true, 'a')); await tick();
  const resume = a.run('liveOwn()');
  a.run('location.hash = "#settings"; liveSync()');
  a.requests[1].respond('the browser is stopped', 409); await resume;
  assert.ok(a.notices.includes('the browser is stopped'));
  assert.equal(a.run('live.frame'), undefined);
  assert.equal(a.requests.length, 2, 'no poll off the account page');
  a.run('location.hash = "#account/web"; liveSync()');
  assert.equal(a.requests[2].method, 'GET');
  assert.equal(a.requests[2].path, '/connections/web/browser');
});

test('clicks map to screenshot pixels, and input is sent in order aimed at the frame it was given on', async () => {
  const a = browserApp();
  a.requests[0].respond(frame(true, 'f1')); await tick();
  a.run('Object.assign($("live-shot"), {naturalWidth: 1280, getBoundingClientRect: () => ({left: 10, top: 20, width: 640})})');
  a.run('liveClick({clientX: 330, clientY: 120})');
  assert.deepEqual(a.requests[1].body, { action: 'click', frame: 'f1', x: 640, y: 200 });
  const key = k => a.run(`liveKey({key: ${JSON.stringify(k)}, preventDefault() {}})`);
  key('h'); key('i'); key('Enter');
  assert.equal(a.requests.length, 2, 'one input at a time');
  a.requests[1].respond(frame(true, 'f2')); await tick();
  assert.deepEqual(a.requests[2].body, { action: 'type', frame: 'f1', text: 'hi' });
  a.requests[2].respond('the page changed', 409); await tick();
  assert.equal(a.requests.length, 3, 'input queued behind a stale one is dropped');
  assert.ok(a.notices.includes('the page changed'));
});


test('owner panel credentials stay in memory and are forgotten on authentication failure', async () => {
  const a = app();
  a.run('ownerSession = "private-credential"');
  assert.equal(a.run('sessionStorage.getItem("monitor-owner-key")'), null);
  assert.match(a.run('keyPage()'), /tinfoil monitor open/);
  assert.ok(!a.run('keyPage()').includes('<input'));
  const pending = a.run('observe("/", {})');
  a.requests[0].respond('refused', 401);
  await pending;
  assert.equal(a.run('ownerSession'), null);
});
