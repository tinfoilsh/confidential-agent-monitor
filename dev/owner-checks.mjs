#!/usr/bin/env node
// Owner HTTP contract: both transports, validators, mutations and older servers.
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { requestTitle, summary, ownerApi, ownerClient, localOwnerClient, decisions, draftable, withDraft, saveText, effectSettings, mode, edits, previewChanges, agentAccess, accountUsers, setupFields, fieldPaths, apiSettings, credentialFields, catalog } from '../ui/src/owner.js';

for (const local of [false, true]) {
  const calls = [];
  let generation = 1, pending = false, reject = false, validators = true;
  const fetch = async (url, options) => {
    const path = url.replace(/^\/api/, '');
    calls.push({ path, ...options });
    assert.equal(options.redirect, 'error');
    assert.equal(options.credentials, 'omit');
    assert.equal(options.cache, 'no-store');
    assert.equal(options.headers[local ? 'X-Tinfoil-Session' : 'Authorization'], local ? 'synthetic-token' : 'Bearer synthetic-key');
    if (reject) return new Response('Unauthorized', { status: 401 });
    if (path.startsWith('/sign-in/')) {
      const body = JSON.parse(options.body);
      return Response.json(body.cancel ? null : { pending: true });
    }
    if (options.method === 'POST') { pending = false; return new Response('null'); }
    const tag = `W/"${generation}-${pending}-${path}"`;
    if (validators && options.headers['If-None-Match'] === tag) return new Response(null, { status: 304 });
    const value = path.startsWith('/requests') ? [{ id: 'r', state: pending ? 'pending' : 'approved', summary: path.includes('?summary') }]
      : { generation, config: {}, catalog_id: 'catalog', ...(path.includes('?catalog=') ? {} : { presets: { custom: { title: 'Custom' } } }) };
    return Response.json(value, { headers: validators ? { ETag: tag } : {} });
  };
  const client = local ? localOwnerClient({ token: 'synthetic-token', fetch, generation: 1 }) : ownerClient({ key: 'synthetic-key', fetch, generation: 1 });
  await client.read(undefined, { summary: true });
  const warm = await client.read(undefined, { summary: true }); // catalog URL warms separately
  const unchanged = await client.read(undefined, { summary: true });
  assert.equal(unchanged.view, warm.view);
  assert.equal(unchanged.requests, warm.requests);
  assert.ok(unchanged.view.presets.custom);
  assert.ok(calls.slice(-2).every(c => c.headers['If-None-Match']));
  pending = true;
  const changed = await client.read(undefined, { summary: true });
  assert.equal(changed.requests[0].state, 'pending');
  await client.decide('r', 'once');
  assert.equal((await client.read(undefined, { summary: true })).requests[0].state, 'approved');
  assert.ok(calls.slice(-2).every(c => !c.headers['If-None-Match']));
  await client.request('r/encoded');
  assert.equal(calls.at(-1).path, '/requests/r%2Fencoded');
  await client.read();
  assert.equal(calls.at(-1).path, '/requests'); // published full-history API remains supported
  const signInSignal = new AbortController().signal;
  assert.deepEqual(await client.finishSignIn('device/state', {}, signInSignal), { pending: true });
  assert.equal(calls.at(-1).path.split('?')[0], '/sign-in/device%2Fstate');
  assert.equal(calls.at(-1).signal, signInSignal);
  assert.equal(await client.finishSignIn('device/state', { cancel: true }), null);
  reject = true;
  await assert.rejects(client.read(undefined, { summary: true }), e => e.status === 401);
  reject = false;
  generation = 0;
  await assert.rejects(client.read(undefined, { summary: true }), e => e.status === 409);
  generation = 2;
  validators = false; // older deployed Monitor does not implement conditional reads
  assert.equal((await client.read()).view.generation, 2);
  const onboarding = { generation: 2, config: {} }, signal = new AbortController().signal;
  for (const preset of ['known_only', 'open', 'offline']) {
    for (const allowPaidInference of [undefined, false, true]) {
      await client.onboard(onboarding, preset, signal, { allowPaidInference });
      const call = calls.at(-1), body = JSON.parse(call.body);
      assert.equal(call.path.split('?')[0], '/policy/edits');
      assert.equal(call.signal, signal);
      assert.equal(body.generation, onboarding.generation);
      const saved = structuredClone(onboarding);
      previewChanges(saved, body.changes);
      assert.equal(saved.config.allow_paid_inference, allowPaidInference ?? true);
      assert.deepEqual(saved.config.data.onboarding, { completed: true });
      const network = 'network';
      assert.equal(saved.config.accounts[network].preset, 'tcp');
      assert.deepEqual(saved.config.accounts[network].connections, { '': { tcp: { hosts: ['*'] } } });
      assert.deepEqual(saved.config.default_access[network], { level: preset === 'open' ? 'allow' : 'off' });
      assert.equal(saved.config.effects?.pay, undefined); // unrelated payments keep their default
      const count = calls.length;
      assert.equal(await client.onboard(saved, preset === 'open' ? 'known_only' : 'open'), saved);
      assert.equal(calls.length, count); // reopening never reapplies an onboarding choice
    }
  }
  // Already configured monitors, including their stored metadata, stay intact.
  const configured = { generation: 2, config: {
    data: { onboarding: { completed: true, preset: 'open', account: 'network', policy: 'network-default' } },
    accounts: { network: { preset: 'custom' } },
  } };
  const count = calls.length;
  assert.equal(await client.onboard(configured, 'known_only'), configured);
  assert.equal(calls.length, count);
}
console.log('Owner client checks passed for bearer and SSH transports.');

const github = JSON.parse(readFileSync(new URL('../presets/github.json', import.meta.url), 'utf8'));
const githubView = { config: { accounts: {} }, presets: { github: { ...github.catalog, title: github.title } } };
const githubToken = github.catalog.fields.find(field => field.key === 'token');
for (const useOAuth of [false, true]) {
  const added = previewChanges(structuredClone(githubView), edits.addAccount(githubView, 'github', {
    name: 'github', values: { token: 'test-personal-access-token', private: [] }, answers: github.catalog.defaults,
    oauth: useOAuth ? ['token'] : [],
  }));
  for (const path of fieldPaths(githubToken)) {
    const value = path.reduce((obj, key) => obj[key], added.config.accounts.github);
    assert.deepEqual(value, useOAuth ? { oauth: githubToken.oauth } : 'test-personal-access-token');
  }
  // Blurring an empty replacement must not materialize untouched optional settings.
  delete added.config.accounts.github.policy_options;
  added.fields = { github: fieldPaths(githubToken).map(path => ({ path, kind: useOAuth ? 'oauth' : 'static' })) };
  const credentials = Object.fromEntries(credentialFields(added, 'github').map(f => [f.key, { mode: 'keep' }]));
  assert.deepEqual(edits.saveAccount(added, 'github', { values: { private: [] }, credentials }), []);
  const field = credentialFields(added, 'github')[0];
  assert.equal(credentialFields(added, 'github').length, 1);
  assert.equal(field.label, 'GitHub account');
  assert.deepEqual(fieldPaths(field), fieldPaths(githubToken));
  assert.deepEqual(edits.saveAccount(added, 'github', {
    values: { private: [] }, credentials: { [field.key]: { mode: 'replace', value: 'replacement-token' } },
  }), fieldPaths(githubToken).map(path => ({ path: ['accounts', 'github', ...path], value: 'replacement-token' })));
  assert.deepEqual(edits.saveAccount(added, 'github', {
    credentials: { [field.key]: { mode: 'clear' } },
  }), fieldPaths(githubToken).map(path => ({ path: ['accounts', 'github', ...path], delete: true })));
  added.fields.github[0].kind = 'static';
  added.fields.github[1].kind = 'oauth';
  const mixed = credentialFields(added, 'github')[0];
  assert.deepEqual(mixed.path, fieldPaths(githubToken)[1]);
  assert.equal(mixed.key, field.key);
  assert.equal(mixed.credential, undefined); // Sign in through the existing grant, preserving its stored endpoints/client.
  added.fields.github[0].kind = 'unset';
  assert.equal(credentialFields(added, 'github')[0].status, 'Partially configured');
  added.fields.github = added.fields.github.slice(0, 1);
  assert.deepEqual(edits.saveAccount(added, 'github', {
    credentials: { [field.key]: { mode: 'replace', value: 'http-only-token' } },
  }), [{ path: ['accounts', 'github', ...fieldPaths(githubToken)[0]], value: 'http-only-token' }]);
  previewChanges(added, edits.saveAccount(added, 'github', { values: { private: ['example/*'] } }));
  assert.deepEqual(edits.saveAccount(added, 'github', { values: { private: [] } }), [
    { path: ['accounts', 'github', 'policy_options', 'private'], value: [] },
  ]);
}
assert.equal(githubToken.oauth.device_auth_url, 'https://github.com/login/device/code');
assert.equal(githubToken.oauth.client_secret, undefined);
console.log('GitHub device sign-in and personal-token setup cover both HTTP and MCP credentials.');

const customApi = {
  config: { accounts: { api: { preset: 'custom_api', connections: { '': { http: {
    slots: [{ origin: 'https://api.example.test', header: 'X-API-Key', value: 'token' }],
  } } } } } },
  presets: { custom_api: { fields: [] } },
  fields: { api: [{ path: ['connections', '', 'http', 'secrets', 'token'], kind: 'static' }] },
};
assert.deepEqual(edits.saveAccount(customApi, 'api', { api: apiSettings(customApi, 'api') }), []);
const customCredential = credentialFields(customApi, 'api')[0];
assert.deepEqual(edits.saveAccount(customApi, 'api', {
  credentials: { [customCredential.key]: { mode: 'replace', value: 'replacement-key' } },
}), [{ path: ['accounts', 'api', ...customCredential.path], value: 'replacement-key' }]);
const changedApi = edits.saveAccount(customApi, 'api', {
  api: { ...apiSettings(customApi, 'api'), url: 'https://api.example.test/v2' },
});
assert.equal(changedApi.length, 1);
assert.equal(changedApi[0].value[0].path, '/v2');
console.log('Empty credential replacements leave optional settings and custom API slots unchanged.');

const openRouter = Object.fromEntries(['open_router', 'open_router_api', 'openrouter'].map(name => [
  name, JSON.parse(readFileSync(new URL(`../presets/${name}.json`, import.meta.url), 'utf8')),
]));
const openRouterView = {
  config: { accounts: { legacy: { preset: 'open_router_api' }, current: { preset: 'open_router' } } },
  presets: Object.fromEntries(Object.entries(openRouter).map(([name, p]) => [name, { ...p.catalog, title: p.title }])),
};
const openRouterCatalog = catalog(openRouterView).flatMap(group => group.presets);
assert.deepEqual(openRouterCatalog.map(p => p.name).sort(), ['open_router', 'openrouter']);
assert.equal(openRouterCatalog.find(p => p.name === 'open_router').accounts, 2);
assert.equal(openRouterView.config.accounts.legacy.preset, 'open_router_api');
const legacyKey = setupFields(openRouterView, 'open_router_api').find(f => f.secret);
assert.deepEqual(legacyKey.path, ['connections', '', 'http', 'secrets', 'api_key']);
openRouterView.fields = { legacy: [{ path: legacyKey.path, kind: 'static' }] };
const legacyCredential = credentialFields(openRouterView, 'legacy')[0];
assert.deepEqual(edits.saveAccount(openRouterView, 'legacy', {
  credentials: { [legacyCredential.key]: { mode: 'replace', value: 'replacement-openrouter-key' } },
}), [{ path: ['accounts', 'legacy', ...legacyKey.path], value: 'replacement-openrouter-key' }]);
assert.equal(openRouter.open_router_api.http.operations.sendChatCompletionRequest.action, 'send.completions');
for (const id of ['sendChatCompletionRequest', 'createEmbeddings', 'createResponses'])
  assert.deepEqual(openRouter.open_router.http.operations[id].effects, ['generate', 'pay', 'send']);
console.log('OpenRouter has one API catalog entry; existing credential paths and permissions remain supported.');

function onboard(view, preset) {
  return ownerApi(async (method, path, body) => {
    assert.equal(method, 'POST');
    assert.equal(path, '/policy/edits');
    assert.equal(body.generation, view.generation);
    return previewChanges(structuredClone(view), body.changes);
  }).onboard(view, preset);
}

for (const preset of ['open', 'known_only', 'offline']) {
  const policy = await onboard({ generation: 4, config: { accounts: { api: { preset: 'custom' } },
    default_access: { api: { level: 'ask' } }, identities: { agent: { routes: true, accounts: { api: { level: 'allow' } } } } } }, preset);
  assert.deepEqual(policy.config.data.onboarding, { completed: true });
  assert.deepEqual(Object.keys(policy.config.accounts).sort(), ['api', 'network']);
  assert.equal(policy.config.accounts.network.preset, 'tcp');
  assert.deepEqual(policy.config.default_access.network, { level: preset === 'open' ? 'allow' : 'off' });
  assert.equal(policy.config.identities.agent.accounts.network, undefined);
  assert.equal(Object.hasOwn(policy.config.identities.agent, 'profile'), false);
  if (preset === 'offline') {
    assert.deepEqual(policy.config.default_access, { network: { level: 'off' } });
    assert.equal(policy.config.identities.agent.accounts.api.level, 'off');
    assert.equal(policy.config.identities.agent.routes, false);
    assert.match(policy.config.policies['network-default'], /Network access is disabled/);
  } else {
    assert.deepEqual(policy.config.default_access.api, { level: 'ask' });
    assert.deepEqual(policy.config.identities.agent.accounts.api, { level: 'allow' });
    assert.equal(policy.config.identities.agent.routes, true);
    if (preset === 'known_only') assert.match(policy.config.policies['network-default'], /input.facts.operation == null/);
    else assert.equal(policy.config.policies, undefined);
  }
  assert.deepEqual(policy.config.allow_networks, preset === 'open' ? ['0.0.0.0/0', '::/0'] : []);
  assert.deepEqual(policy.config.lattices, { confidentiality: preset !== 'open', integrity: false });
}

// Leave user accounts, connection names and policy modules alone when naming the default.
const existing = { generation: 7, config: {
  accounts: { network: { preset: 'custom', connections: { '2': { tcp: { hosts: ['example.com'] } } } } },
  policies: { 'network-default': 'package sentinel\n' },
  data: { team: 'example' },
} };
const collision = await onboard(existing, 'known_only');
assert.deepEqual(collision.config.accounts.network, existing.config.accounts.network);
assert.equal(collision.config.accounts['network-3'].preset, 'tcp');
assert.equal(collision.config.policies['network-default'], 'package sentinel\n');
assert.match(collision.config.policies['network-default-2'], /input.facts.operation == null/);
assert.deepEqual(collision.config.data, { team: 'example', onboarding: { completed: true } });
previewChanges(collision, edits.removeAccount(collision, 'network-3'));
assert.equal(collision.config.accounts['network-3'], undefined);
assert.deepEqual(collision.config.data.onboarding, { completed: true });
console.log('Onboarding-only policy choices, default TCP access, and name collision checks passed.');

const view = { config: { accounts: { api: { preset: 'custom' } } }, presets: { custom: { operations: {} } } };
const file = { http: { operations: {} } };
const unknown = { state: 'refused', facts: { account: 'api', operation: null, details: { http: {
  method: 'GET', origin: 'https://example.com', path: '/item', body_kind: 'none', query: {}
} } } };
// A policy refusal can still be recognized by adding an operation; validation failures cannot.
assert.equal(draftable(view, unknown), 'custom');
assert.ok(withDraft(file, unknown).http.operations['GET /item']);
assert.deepEqual(file.http.operations, {});
const invalid = { ...unknown, invalid: true };
assert.equal(draftable(view, invalid), null);
assert.deepEqual(withDraft(file, invalid), file);
const known = { ...unknown, state: 'pending', facts: { ...unknown.facts, operation: { id: 'item.read', action: 'read' } } };
assert.equal(draftable(view, known), null);
assert.deepEqual(withDraft(file, known), file);
assert.deepEqual(decisions(known), { once: true, save: true, deny: true });
assert.deepEqual(decisions({ ...known, state: 'expired' }), { save: true, dismiss: true });
assert.deepEqual(decisions({ ...known, state: 'refused' }), {});
assert.match(saveText(known), /future attempts.*Retry/);
console.log('Approval retry and operation-draft checks passed.');

const permissions = {
  vocabulary: { pay: { change: true, ask: true }, publish: { change: true, ask: true }, read: {} },
  config: { effects: { pay: 'allow' }, accounts: { api: { preset: 'custom', effects: { pay: 'off' } } },
    identities: { agent: { effects: { pay: 'ask' }, accounts: { api: { level: 'allow', effects: { pay: 'allow' } } } } } },
  presets: { custom: { actions: { generate: { effects: ['pay'] } } } },
};
const scope = { agent: 'agent', account: 'api' };
const payment = (scope) => effectSettings(permissions, scope).find(e => e.effect === 'pay');
assert.deepEqual(payment(scope), { effect: 'pay', own: 'allow', inherited: 'ask', mode: 'allow', source: 'Agent agent on api' });
assert.equal(payment({}).mode, 'allow');
assert.equal(payment({ account: 'api' }).mode, 'off');
assert.equal(payment({ agent: 'agent' }).mode, 'ask');
assert.equal(agentAccess(permissions, 'agent')[0].actions[0].inherited, 'allow');
for (const [current, expected, source] of [[scope, 'ask', 'Agent agent'], [{ agent: 'agent' }, 'off', 'Account api'], [{ account: 'api' }, 'allow', 'Global settings'], [{}, 'ask', 'Monitor defaults']]) {
  previewChanges(permissions, edits.setEffect(current, 'pay', null));
  assert.equal(payment(scope).mode, expected);
  assert.equal(payment(scope).source, source);
  assert.equal(agentAccess(permissions, 'agent')[0].actions[0].inherited, expected);
}
const vocabulary = permissions.vocabulary;
assert.equal(mode({ level: 'allow' }, vocabulary, ['pay'], 'generate', { pay: 'allow' }), 'allow');
assert.equal(mode({ level: 'allow' }, vocabulary, ['pay', 'publish'], 'generate', { pay: 'allow' }), 'ask');
assert.equal(mode({ level: 'allow', actions: { generate: 'allow' } }, vocabulary, ['pay'], 'generate', { pay: 'off' }), 'off');
assert.equal(mode({ level: 'read' }, vocabulary, ['pay'], 'generate', { pay: 'allow' }), 'off');
assert.equal(mode({ level: 'ask' }, vocabulary, ['pay'], 'generate', { pay: 'allow' }), 'ask');
assert.equal(mode({ level: 'off', actions: { generate: 'allow' } }, vocabulary, ['pay'], 'generate', { pay: 'allow' }), 'off');
assert.deepEqual(edits.setEffect(scope, 'pay', 'allow'), [{ path: ['identities', 'agent', 'accounts', 'api', 'effects', 'pay'], value: 'allow' }]);
console.log('Effect precedence, inheritance, and access checks passed.');

const usage = { config: { accounts: { api: {} }, default_access: { api: { level: 'read' } }, identities: {
  inherited: {},
  blocked: { accounts: { api: { level: 'off', actions: { write: 'off' }, effects: { pay: 'off' } }, other: { level: 'allow' } } },
  explicit: { accounts: { api: { level: 'allow' } } },
} } };
assert.deepEqual(accountUsers(usage, 'api').map(({ name, level }) => [name, level]), [['inherited', 'read'], ['explicit', 'allow']]);
assert.deepEqual(accountUsers(usage, 'unknown'), []);
previewChanges(usage, edits.setAccess('blocked', 'api', { level: 'ask' }));
assert.equal(accountUsers(usage, 'api').find(({ name }) => name === 'blocked').level, 'ask');
assert.deepEqual(usage.config.identities.blocked.accounts, {
  api: { level: 'ask', actions: { write: 'off' }, effects: { pay: 'off' } }, other: { level: 'allow' },
});
console.log('Account usage includes inherited access; adding access preserves existing restrictions.');

permissions.config.allow_paid_inference = true;
const inference = ['generate', 'pay', 'send'];
assert.equal(effectSettings(permissions, scope, inference).find(e => e.effect === 'pay').mode, 'allow');
assert.equal(payment(scope).mode, 'ask');
for (const layer of [{}, { account: 'api' }, { agent: 'agent' }, scope]) {
  for (const setting of ['ask', 'off']) {
    previewChanges(permissions, edits.setEffect(layer, 'pay', setting));
    assert.equal(effectSettings(permissions, scope, inference).find(e => e.effect === 'pay').mode, setting);
  }
  previewChanges(permissions, edits.setEffect(layer, 'pay', null));
}
permissions.presets.custom = { actions: {
  'use.model': { effects: inference },
  'use.payment': { effects: ['pay'] },
} };
let group = agentAccess(permissions, 'agent')[0].actions[0];
assert.equal(group.inherited, 'ask');
assert.deepEqual(group.children.map(c => [c.key, c.inherited]), [['use.model', 'allow'], ['use.payment', 'ask']]);
previewChanges(permissions, edits.setPaidInference(false));
group = agentAccess(permissions, 'agent')[0].actions[0];
assert.equal(group.children[0].inherited, 'ask');
console.log('Paid-inference onboarding, opt-out, and permission checks passed.');

let presetsChecked = 0, arrayPresetsChecked = 0;
const presetRoot = new URL('../presets/', import.meta.url);
for (const file of readdirSync(presetRoot).filter(name => name.endsWith('.json'))) {
  const preset = file.slice(0, -5), source = JSON.parse(readFileSync(new URL(file, presetRoot), 'utf8'));
  const catalog = { title: source.title, ...source.catalog };
  const view = { config: { accounts: {} }, presets: { [preset]: catalog } };
  const fields = setupFields(view, preset);
  const values = Object.fromEntries(fields.map(f => [f.key, f.json ? f.default ?? {} : f.list ? ['audit.example.com']
    : f.secret ? 'synthetic-credential' : f.key.includes('origin') || f.key.includes('url') ? 'https://audit.example.com' : `audit-${f.key}`]));
  const changes = edits.addAccount(view, preset, { name: 'audit', values, answers: catalog.defaults ?? {} });
  previewChanges(view, JSON.parse(JSON.stringify(changes)));
  presetsChecked++;
  const arrays = fields.flatMap(f => fieldPaths(f).filter(path => path.some(key => typeof key === 'number'))
    .map(path => path.slice(0, path.findIndex(key => typeof key === 'number'))));
  if (arrays.length) arrayPresetsChecked++;
  for (const path of arrays) {
    const actual = path.reduce((value, key) => value?.[key], view.config.accounts.audit);
    const inherited = path.reduce((value, key) => value?.[key], { connections: catalog.connections });
    assert.ok(Array.isArray(actual), `${preset}: ${path.join('/')} must remain an array`);
    if (inherited) assert.equal(actual.length, inherited.length, `${preset}: preserve all inherited entries`);
  }
  if (preset === 'pinecone') {
    const slots = view.config.accounts.audit.connections[''].http.slots;
    assert.deepEqual(slots, [
      { value: 'api_key', origin: 'https://api.pinecone.io', path: '/', header: 'Api-Key' },
      { value: 'api_key', origin: values.origin, path: '/', header: 'Api-Key' },
    ]);
    assert.deepEqual(catalog.connections[''].http.slots[1].origin, 'https://example.com');
    const saved = edits.saveAccount(view, 'audit', { answers: {}, values: { origin: 'https://changed.example.com' } });
    assert.ok(saved.some(change => Array.isArray(change.value) && change.path.at(-1) === 'slots'));
    previewChanges(view, saved);
    assert.equal(view.config.accounts.audit.connections[''].http.slots[0].origin, 'https://api.pinecone.io');
    assert.equal(view.config.accounts.audit.connections[''].http.slots[1].origin, 'https://changed.example.com');
  }
}
console.log(`Account setup checked for ${presetsChecked} presets; ${arrayPresetsChecked} preserve inherited arrays.`);

// Optimistic projections must share untouched data without mutating confirmed state.
const confirmed = {
  config: { accounts: { api: { preset: 'custom', connections: { '': { http: { slots: [{ value: 'token' }] } } } } },
    identities: { agent: { accounts: { api: { level: 'allow', actions: { 'items.read': 'ask' } } } } } },
  presets: { custom: { actions: { 'items.read': { effects: ['read'] } } } }, vocabulary: { read: {} },
};
const original = structuredClone(confirmed), projected = { ...confirmed };
previewChanges(projected, [
  ...edits.setAccess('agent', 'api', { actions: { 'items.write': 'off' } }),
  ...edits.setEffect({ agent: 'agent', account: 'api' }, 'read', 'ask'),
]);
assert.deepEqual(confirmed, original);
assert.equal(projected.config.accounts, confirmed.config.accounts);
assert.equal(projected.presets, confirmed.presets);
assert.equal(projected.config.identities.agent.accounts.api.actions['items.read'], 'ask');
assert.equal(projected.config.identities.agent.accounts.api.actions['items.write'], 'off');
const arrays = { ...confirmed };
previewChanges(arrays, [{ path: ['accounts', 'api', 'connections', '', 'http', 'slots', '0', 'value'], value: 'changed' }]);
assert.equal(arrays.config.accounts.api.connections[''].http.slots[0].value, 'changed');
assert.deepEqual(confirmed, original);
const hostile = { ...confirmed };
previewChanges(hostile, [{ path: ['__proto__', 'monitorProjection'], value: true }]);
assert.equal(Object.prototype.monitorProjection, undefined);
assert.equal(Object.hasOwn(hostile.config, '__proto__'), true);
const summaryOnly = { ...confirmed, presets: new Proxy({}, { get() { throw new Error('Summary derived an action tree'); } }) };
assert.equal(agentAccess(summaryOnly, 'agent')[0].level, 'allow');
Object.defineProperty(summaryOnly.config.accounts, 'unselected', { enumerable: true, configurable: true, get() { throw new Error('Read an unrelated account'); } });
assert.equal(agentAccess(summaryOnly, 'agent', 'api')[0].account, 'api');
assert.deepEqual(agentAccess(summaryOnly, 'agent', 'missing'), []);
delete summaryOnly.config.accounts.unselected;
console.log('Optimistic projection isolation, structural sharing, lazy summaries, and selected-account checks passed.');

assert.equal(requestTitle({ facts: { title: 'POST google.com/' } }), 'POST google.com/');
assert.equal(requestTitle({ facts: { title: 'GET https://example.com/items?q=1' } }), 'GET https://example.com/items?q=1');
assert.equal(requestTitle({ facts: { title: 'List files' } }), 'List files');
assert.equal(summary({ http: { method: 'POST', host: 'google.com', path: '/' } }), 'POST google.com/');
console.log('Activity titles and technical request facts remain available to API consumers.');
