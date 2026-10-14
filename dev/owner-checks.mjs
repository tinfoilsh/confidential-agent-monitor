#!/usr/bin/env node
// Owner HTTP contract: both transports, validators, mutations and older servers.
import assert from 'node:assert/strict';
import { ownerClient, localOwnerClient } from '../app/owner.js';

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
