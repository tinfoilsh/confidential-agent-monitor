#!/usr/bin/env node
// Owner HTTP contract: both transports, validators, mutations and older servers.
import assert from 'node:assert/strict';
import { ownerClient, localOwnerClient, decisions, draftable, withDraft, saveText } from '../app/owner.js';

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
}
console.log('Owner client checks passed for bearer and SSH transports.');

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
