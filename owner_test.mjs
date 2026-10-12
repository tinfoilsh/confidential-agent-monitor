import { spawn, execFileSync } from 'node:child_process';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import assert from 'node:assert/strict';
import * as owner from './app/owner.js';

const { edits } = owner;
const respond = (body, status = 200) => ({ ok: status < 300, status, text: async () => typeof body === 'string' ? body : JSON.stringify(body) });

test('the client sends the key only to its endpoint, never follows redirects, and unlocks at the known generation', async () => {
  const calls = [];
  const replies = [respond('locked', 423), respond('locked', 423), respond({ generation: 7 }), respond([])];
  const api = owner.ownerClient({ endpoint: 'http://127.0.0.1:8080/', key: 'k', generation: 7,
    fetch: async (url, options) => { calls.push([url, options]); return replies.shift(); } });
  assert.deepEqual(await api.read(), { view: { generation: 7 }, requests: [] });
  assert.deepEqual(calls.map(([url, o]) => `${o.method} ${url}`), ['GET http://127.0.0.1:8080/', 'GET http://127.0.0.1:8080/requests',
    'POST http://127.0.0.1:8080/unlock', 'GET http://127.0.0.1:8080/requests']);
  assert.deepEqual(JSON.parse(calls[2][1].body), { generation: 7 });
  for (const [, o] of calls) {
    assert.equal(o.headers.Authorization, 'Bearer k');
    assert.deepEqual([o.redirect, o.credentials, o.cache], ['error', 'omit', 'no-store']);
  }
  for (const endpoint of ['', 'http://monitor.example.test', 'https://user:pass@monitor.example.test', 'https://monitor.example.test/?next=x'])
    assert.throws(() => owner.ownerClient({ endpoint, key: 'k' }), endpoint);
});

test('an older view than the known generation is a rollback, and the same-origin client never unlocks by itself', async () => {
  const pinned = owner.ownerApi(async (_, path) => path === '/' ? { generation: 3 } : [], 5);
  await assert.rejects(pinned.read(), (err) => err.status === 409);
  const local = owner.ownerApi(async () => { throw new owner.OwnerError('locked', 423); });
  await assert.rejects(local.read(), (err) => err.status === 423);
});

const view = () => ({
  generation: 1, host_key: '', ca: '', labels: {}, status: { 'gh-mcp': { state: 'ready', details: { blocked: 2, changes: ['+ a', '~ b'], pin: { tools: [] } } } },
  vocabulary: { read: {}, write: { change: true }, send: { change: true, ask: true } },
  fields: { svc: [{ path: ['connections', '', 'http', 'secrets', 'token'], kind: 'static' }] },
  presets: {
    svc: { title: 'Service', actions: { items: { title: 'Items', effects: ['read'] }, 'items.send': { title: 'Send' } },
      operations: { post: { action: 'items.send', effects: ['send'] }, edit: { action: 'items.edit', effects: ['write'] } },
      connections: { '': { http: { slots: [{ value: 'token', origin: '{origin}' }] } } },
      fields: [{ key: 'origin', label: 'Origin', path: ['origin_setting'] }, { key: 'token', label: 'Token', secret: true, path: ['connections', '', 'http', 'secrets', 'token'] }] },
    gh: { title: 'GitHub', actions: {} },
    custom_api: { title: 'Custom API', actions: { request: { title: 'Use API', effects: ['send'] } } },
  },
  config: {
    accounts: {
      svc: { preset: 'svc', contents: 'team', sends: 'me', strangers: false, origin_setting: 'https://svc.example', connections: { '': { http: { slots: [{ value: 'token', origin: 'https://svc.example' }] } } } },
      gh: { preset: 'gh', contents: 'me', sends: 'me', connections: { mcp: { mcp: { pin: { tools: [{ name: 'list', annotations: { readOnlyHint: true } }, { name: 'merge', title: 'Merge' }] } } } } },
    },
    identities: { bot: { key: 'ssh-ed25519 A', accounts: { svc: { level: 'allow', actions: { 'items.edit': 'off' } } } }, other: { key: 'k', accounts: { gh: { level: 'read' } } } },
  },
});

test('permissions include pinned MCP tools, inherit ancestor effects, and show each action\'s own and inherited mode', () => {
  const v = view();
  assert.deepEqual(Object.keys(owner.actionsOf(v, 'gh')).sort(), ['read.list', 'use.merge']);
  assert.deepEqual(owner.effectsOf(v, 'svc', 'items.send').sort(), ['read', 'send']);
  const [svc] = owner.agentAccess(v, 'bot');
  const items = svc.actions.find((n) => n.key === 'items'), byKey = Object.fromEntries(items.children.map((n) => [n.key, n]));
  assert.equal(items.overrides, 1);
  assert.deepEqual([byKey['items.send'].own, byKey['items.send'].inherited], [null, 'ask']);
  assert.deepEqual([byKey['items.edit'].own, byKey['items.edit'].inherited], ['off', 'allow']);
  assert.deepEqual(owner.levelsOf({ preset: 'custom_api' }).map(([l]) => l), ['off', 'ask', 'allow']);
});

test('account edits send credentials as their own changes and leave unedited ones alone', () => {
  const v = view();
  const added = edits.addAccount(v, 'svc', { name: ' new ', values: { origin: 'https://new.example', token: 'secret' }, answers: { contents: 'me', strangers: true, sends: 'me' } });
  assert.deepEqual(added.find((c) => c.path.at(-1) === 'token'), { path: ['accounts', 'new', 'connections', '', 'http', 'secrets', 'token'], value: 'secret' });
  assert.deepEqual(added.find((c) => c.path.at(-1) === 'slots').value, [{ value: 'token', origin: 'https://new.example' }]);
  assert.throws(() => edits.addAccount(v, 'svc', { name: 'svc', values: {}, answers: {} }), /already exists/);
  const answers = { contents: 'team', strangers: false, sends: 'me' };
  assert.deepEqual(edits.saveAccount(v, 'svc', { answers, values: { origin: 'https://svc.example' } }), []);
  v.config.accounts.api = { preset: 'custom_api', contents: 'me', sends: 'me', connections: { '': { http: { slots: [{ prefix: 'Bearer ', header: 'Authorization', path: '/v1', origin: 'https://api.example.test', value: 'token' }] } } } };
  assert.deepEqual(edits.saveAccount(v, 'api', { answers: { contents: 'me', sends: 'me' }, api: { url: 'https://api.example.test/v1', auth: 'bearer' } }), [], 'reordered server keys are not a change');
  assert.deepEqual(edits.saveAccount(v, 'svc', { answers: { ...answers, contents: 'me' }, credentials: { 'connections//http/secrets/token': { mode: 'clear' } } }), [
    { path: ['accounts', 'svc', 'contents'], value: 'me' },
    { path: ['accounts', 'svc', 'connections', '', 'http', 'secrets', 'token'], delete: true },
  ]);
  assert.throws(() => edits.saveAccount(v, 'svc', { answers, credentials: { 'connections//http/secrets/token': { mode: 'replace', value: '' } } }), /Enter a value/);
  assert.deepEqual(edits.removeAccount(v, 'svc'), [{ path: ['accounts', 'svc'], delete: true }, { path: ['policies', 'svc'], delete: true },
    { path: ['identities', 'bot', 'accounts', 'svc'], delete: true }, { path: ['identities', 'other', 'accounts', 'svc'], delete: true }]);
});

test('connector icons come from the manifest, with dark variants and the custom icon as fallback', () => {
  const manifest = { github: { src: 'github.svg', dark: 'github.dark.svg' }, custom: { src: 'custom.svg' }, broken: {} };
  assert.deepEqual(owner.connectorIcon(manifest, 'github', 'https://m.test'), { src: 'https://m.test/app/icons/github.svg', dark: 'https://m.test/app/icons/github.dark.svg' });
  assert.deepEqual(owner.connectorIcon(manifest, 'broken'), { src: '/app/icons/custom.svg' });
  assert.deepEqual(owner.connectorIcon(undefined, 'unknown'), { src: '/app/icons/custom.svg' });
});

test('decisions follow the request lifecycle, including expiry before the next poll', () => {
  const r = { id: '1', state: 'pending', expires: '2026-01-01T00:00:00Z', facts: { principal: { name: 'bot' }, account: 'svc', operation: { id: 'post', action: 'items.send' } } };
  assert.deepEqual(owner.decisions(r), { once: true, save: true, deny: true });
  assert.deepEqual(owner.decisions(r, Date.parse('2026-02-01T00:00:00Z')), { save: true, dismiss: true });
  assert.deepEqual(owner.decisions({ ...r, facts: { ...r.facts, operation: undefined } }), { once: true, save: false, deny: true });
  assert.deepEqual(owner.reviews(view(), 'gh').map(({ name, blocked, added, changed }) => [name, blocked, added, changed]), [['gh-mcp', 2, 1, 1]]);
});

// The live check runs these edits against a real Monitor with a throwaway store on ports kept apart from other local servers.
test('a real Monitor accepts the shared edits and enforces origins', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'owner-test-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const bin = join(dir, 'monitor'), api = process.env.OWNER_TEST_API ?? '127.0.0.1:28080', origin = 'http://localhost:3200';
  execFileSync('go', ['build', '-o', bin, '.'], { stdio: 'inherit' });
  const server = spawn(bin, ['-listen', process.env.OWNER_TEST_SSH ?? '127.0.0.1:22223', '-api', api, '-bucket', `file://${dir}/store?no_tmp_dir=1&create_dir=1`, '-owner-origins', origin], { stdio: 'ignore' });
  t.after(() => server.kill());
  const base = `http://${api}`;
  for (let i = 0; ; i++) {
    try { if ((await fetch(base + '/healthz')).ok) break; } catch (err) { if (i > 100) throw err; }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  const key = randomBytes(32).toString('base64'), client = owner.ownerClient({ endpoint: base, key, generation: 0 });
  let { view: v } = await client.read();
  assert.equal(v.generation, 1);

  const icon = await client.icons();
  assert.equal(icon('aws_bedrock').src, `${base}/app/icons/aws.svg`);
  assert.equal(icon('no_such_preset').src, `${base}/app/icons/custom.svg`);
  for (const src of [icon('github').dark, icon('anthropic').src, icon('no_such_preset').src]) {
    const res = await fetch(src, { headers: { Origin: origin } });
    assert.equal(res.status, 200, src);
    assert.match(res.headers.get('content-type'), /^image\//);
  }

  const preflight = await fetch(base + '/', { method: 'OPTIONS', headers: { Origin: origin, 'Access-Control-Request-Method': 'GET' } });
  assert.equal(preflight.headers.get('access-control-allow-origin'), origin);
  const foreign = await fetch(base + '/', { headers: { Origin: 'https://evil.example', Authorization: 'Bearer ' + key } });
  assert.equal(foreign.headers.get('access-control-allow-origin'), null);

  const answers = { contents: 'me', strangers: true, sends: 'me' };
  v = await client.edit(edits.addAccount(v, 'anthropic', { name: 'model', values: { token: 'test-only-token' }, answers }));
  assert.deepEqual(v.fields.model.map((f) => f.kind), ['static']);
  assert.ok(!JSON.stringify(v).includes('test-only-token'));
  v = await client.edit(edits.addCustomApi(v, { name: 'my-api', api: { url: 'https://api.example.test/v1', auth: 'bearer' }, token: 'test-only-api-token', answers }));
  assert.equal(owner.apiSetup(v, 'my-api').value, 'Bearer tfm_my-api_token');

  const jwk = generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' });
  const blob = Buffer.concat([Buffer.from([0, 0, 0, 11]), Buffer.from('ssh-ed25519'), Buffer.from([0, 0, 0, 32]), Buffer.from(jwk.x, 'base64url')]);
  v = await client.edit(edits.pairAgent('bot', `ssh-ed25519 ${blob.toString('base64')} bot`));
  v = await client.edit([...edits.setAccess('bot', 'model', { level: 'ask' }), ...edits.setAccess('bot', 'model', { actions: { agents: 'allow' } }), ...edits.setRoutes('bot', true)]);
  assert.equal(owner.agentAccess(v, 'bot').find((a) => a.account === 'model').actions.find((n) => n.key === 'agents').own, 'allow');
  v = await client.label('bot', { trust: 'untrusted', audience: 'team' });
  assert.equal(owner.labelStatus(v, v.labels.bot), 'Has seen private data from the owner');

  const token = 'connections//http/secrets/token';
  v = await client.edit(edits.saveAccount(v, 'model', { answers: { ...answers, contents: 'team' }, credentials: { [token]: { mode: 'keep' } } }));
  assert.deepEqual([v.config.accounts.model.contents, v.fields.model[0].kind], ['team', 'static']);
  v = await client.edit(edits.saveAccount(v, 'my-api', { answers, api: { url: 'https://api.example.test/v2', auth: 'query', query: 'key' } }));
  assert.deepEqual(v.config.accounts['my-api'].connections[''].http.slots, [{ value: 'token', origin: 'https://api.example.test', path: '/v2', query: 'key' }]);
  assert.equal(v.fields['my-api'][0].kind, 'static');
  v = await client.edit(edits.saveAccount(v, 'model', { answers, credentials: { [token]: { mode: 'clear' } } }));
  assert.equal(v.fields.model[0].kind, 'unset');

  const shipped = await client.preset('web');
  v = await client.edit(edits.savePreset('web', JSON.stringify({ ...shipped, title: 'Browsing' }), shipped));
  assert.equal(v.presets.web.title, 'Browsing');
  v = await client.edit(edits.removePreset('web'));
  assert.equal(v.presets.web.title, 'Web');

  const { source } = await client.policy();
  const preview = await client.previewPolicy(source + '\n# reviewed\n');
  assert.match(preview.source_diff, /\+# reviewed/);
  v = await client.applyPolicy(source + '\n# reviewed\n');
  assert.match((await client.policy(true)).effective, /presets/);

  v = await client.edit(edits.removeAccount(v, 'model'));
  assert.equal(v.config.identities.bot.accounts?.model, undefined);
  await assert.rejects(client.decide('missing', 'once'), (err) => err.status === 400);
  await assert.rejects(owner.ownerClient({ endpoint: base, key, generation: v.generation + 1 }).read(), (err) => err.status === 409);
  await assert.rejects(owner.ownerClient({ endpoint: base, key: randomBytes(32).toString('base64') }).read(), (err) => err.status === 401);
});


test('owner input preserves passphrase bytes and recognizes old keys', () => {
  const passphrase = '  Café workspace 🔐\n';
  assert.equal(Buffer.from(owner.encodeOwnerKey(passphrase), 'base64').toString(), passphrase);
  const legacy = randomBytes(32).toString('base64');
  assert.equal(owner.encodeOwnerKey('  ' + legacy + '\n'), legacy);
  for (const invalid of ['', 'short', 'é'.repeat(2049)]) assert.throws(() => owner.encodeOwnerKey(invalid));
  assert.equal(Buffer.from(owner.encodeOwnerKey('é'.repeat(8)), 'base64').length, 16);
});
