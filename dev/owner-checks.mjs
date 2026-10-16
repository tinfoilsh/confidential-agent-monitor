#!/usr/bin/env node
// Owner HTTP contract: both transports, validators, mutations and older servers.
import assert from 'node:assert/strict';
import { ownerClient, localOwnerClient, decisions, draftable, withDraft, saveText, effectSettings, mode, edits, previewChanges, agentAccess } from '../app/owner.js';

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
      assert.equal(saved.config.data.onboarding.completed, true);
      assert.equal(saved.config.data.onboarding.preset, preset);
      const network = saved.config.data.onboarding.account;
      assert.equal(saved.config.accounts[network].preset, 'tcp');
      assert.deepEqual(saved.config.accounts[network].connections, { '': { tcp: { hosts: ['*'] } } });
      assert.deepEqual(saved.config.default_access[network], { level: preset === 'open' ? 'allow' : 'off' });
      assert.equal(saved.config.effects?.pay, undefined); // unrelated payments keep their default
      const count = calls.length;
      assert.equal(await client.onboard(saved, preset), saved);
      assert.equal(calls.length, count); // reopening an onboarded monitor does not reset the choice
      previewChanges(saved, edits.applyPolicyPreset(saved, 'known_only'));
      assert.equal(saved.config.allow_paid_inference, allowPaidInference ?? true);
      assert.equal(saved.config.data.onboarding.account, network);
      assert.equal(saved.config.accounts[network].preset, 'tcp');
      assert.deepEqual(saved.config.default_access[network], { level: 'off' });
    }
  }
}
console.log('Owner client checks passed for bearer and SSH transports.');

for (const initial of ['open', 'known_only', 'offline']) {
  for (const next of ['open', 'known_only', 'offline']) {
    const policy = { config: { accounts: { api: { preset: 'custom' } },
      default_access: { api: { level: 'ask' } }, identities: { agent: { profile: true, routes: true, accounts: { api: { level: 'allow' } } } } } };
    previewChanges(policy, edits.applyPolicyPreset(policy, initial));
    const account = policy.config.data.onboarding.account;
    // Applying a preset must replace old defaults and explicit per-agent access.
    policy.config.default_access[account] = { level: 'ask', actions: { connect: 'off' } };
    policy.config.identities.agent.accounts[account] = { level: next === 'open' ? 'off' : 'allow', actions: { connect: 'allow' } };
    const apiAccess = structuredClone(policy.config.identities.agent.accounts.api);
    previewChanges(policy, edits.applyPolicyPreset(policy, next));
    assert.equal(policy.config.data.onboarding.account, account);
    assert.deepEqual(Object.keys(policy.config.accounts).sort(), ['api', account].sort());
    assert.equal(policy.config.accounts[account].preset, 'tcp');
    assert.deepEqual(policy.config.default_access[account], { level: next === 'open' ? 'allow' : 'off' });
    assert.equal(policy.config.identities.agent.accounts[account], undefined);
    assert.equal(policy.config.identities.agent.profile, false);
    if (next === 'offline') {
      assert.deepEqual(policy.config.default_access, { [account]: { level: 'off' } });
      assert.equal(policy.config.identities.agent.accounts.api.level, 'off');
      assert.equal(policy.config.identities.agent.routes, false);
    } else assert.deepEqual(policy.config.identities.agent.accounts.api, apiAccess);
    assert.deepEqual(policy.config.allow_networks, next === 'open' ? ['0.0.0.0/0', '::/0'] : []);
  }
}

// Leave user accounts, connection names and policy modules alone when naming the default.
const collision = { config: {
  accounts: { network: { preset: 'custom', connections: { '2': { tcp: { hosts: ['example.com'] } } } } },
  policies: { 'network-default': 'package sentinel\n' },
} };
const existingAccount = structuredClone(collision.config.accounts.network);
previewChanges(collision, edits.applyPolicyPreset(collision, 'known_only'));
assert.equal(collision.config.data.onboarding.account, 'network-3');
assert.equal(collision.config.data.onboarding.policy, 'network-default-2');
assert.deepEqual(collision.config.accounts.network, existingAccount);
assert.equal(collision.config.policies['network-default'], 'package sentinel\n');
const networkAccount = collision.config.data.onboarding.account;
previewChanges(collision, edits.applyPolicyPreset(collision, 'open'));
assert.equal(collision.config.data.onboarding.account, networkAccount);
previewChanges(collision, edits.removeAccount(collision, networkAccount));
assert.equal(collision.config.data.onboarding.account, undefined);
previewChanges(collision, edits.applyPolicyPreset(collision, 'offline'));
assert.equal(collision.config.accounts[collision.config.data.onboarding.account].preset, 'tcp');
// A saved onboarding name must not turn an account repurposed by its owner back into TCP.
collision.config.accounts[collision.config.data.onboarding.account].preset = 'custom';
previewChanges(collision, edits.applyPolicyPreset(collision, 'open'));
assert.equal(collision.config.accounts[networkAccount].preset, 'custom');
assert.notEqual(collision.config.data.onboarding.account, networkAccount);
console.log('Default TCP onboarding, policy transitions, and name collision checks passed.');

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
