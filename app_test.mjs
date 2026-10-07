import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import test from 'node:test';
import assert from 'node:assert/strict';

const source = readFileSync(new URL('./app/index.html', import.meta.url), 'utf8')
  .match(/<script>([\s\S]*)<\/script>/)[1].split('window.addEventListener')[0];
const fixture = () => ({ generation: 1, config: {
  accounts: { work: { preset: 'custom' } },
  identities: { bot: { accounts: { work: { level: 'ask' } }, rules: [] }, other: { accounts: {} } },
}, presets: { custom: { title: 'Custom', actions: {}, operations: [], fields: [], vocabulary: {} } },
labels: { bot: { trust: 'trusted', audience: 'me' } }, status: {}, fields: {} });

function app() {
  const requests = [], notices = [], elements = new Map();
  const storage = () => {
    const entries = new Map();
    return { getItem: key => entries.get(key) ?? null, setItem: (key, value) => entries.set(key, String(value)), removeItem: key => entries.delete(key) };
  };
  const context = vm.createContext({
    structuredClone, setTimeout: () => 1, clearTimeout() {}, location: { hash: '#agent/bot' }, localStorage: storage(), sessionStorage: storage(),
    document: { title: '', getElementById(id) { if (!elements.has(id)) elements.set(id, {}); return elements.get(id); } },
    fetch(path, options = {}) {
      if (path === 'icons/manifest.json') return Promise.resolve({ ok: true, json: async () => ({}) });
      return new Promise(resolve => requests.push({ path, method: options.method, body: options.body && JSON.parse(options.body),
        respond(body, status = 200) { resolve({ ok: status >= 200 && status < 300, status, text: async () => typeof body === 'string' ? body : JSON.stringify(body) }); },
      }));
    }, fixture: fixture(), notices,
  });
  vm.runInContext(source, context);
  vm.runInContext('render = () => {}; toast = message => notices.push(message); remember(fixture);', context);
  return { requests, notices, elements, context, run: code => vm.runInContext(code, context),
    state: () => JSON.parse(vm.runInContext('JSON.stringify({view, records, pending: pendingEdits.length})', context)),
  };
}
const tick = () => new Promise(resolve => setImmediate(resolve));
const level = a => a.state().view.config.identities.bot.accounts.work.level;

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
  assert.equal(a.requests[1].body.identities.bot.accounts.work.level, 'read');
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
  a.run('serverState.records = [{id: "1", identity: "bot", account: "work", action: "write", operation: "items.create", state: "pending", gaps: ["ask"]}]; project()');
  const edit = a.run('answer("1", "save")');
  assert.equal(a.state().records[0].state, 'approved');
  assert.equal(a.context.document.title, 'Monitor');
  assert.equal(a.state().view.config.identities.bot.rules.length, 1);
  await a.run('answer("1", "save")');
  assert.equal(a.requests.length, 1, 'a second click must not submit a duplicate decision');
  a.requests[0].respond('Approval expired', 400); await edit;
  assert.equal(a.state().records[0].state, 'pending');
  assert.equal(a.state().view.config.identities.bot.rules.length, 0);
  assert.equal(a.context.document.title, '(1) Monitor');
});

test('a successful decision is not rolled back if the following refresh fails', async () => {
  const a = app();
  a.run('serverState.records = [{id: "1", identity: "bot", account: "work", state: "pending"}]; project()');
  const edit = a.run('answer("1", "deny")');
  a.requests[0].respond(''); await edit;
  a.requests[1].respond('Offline', 503); a.requests[2].respond([]); await tick();
  assert.equal(a.state().records[0].state, 'denied');
  assert.ok(a.notices.includes('Offline'));
});

test('copying settings replaces old entries in one request', async () => {
  const a = app();
  a.run('serverState.view.config.identities.other = {accounts: {mail: {level: "read"}}, rules: []}; project(); $("from").value = "other"');
  const edit = a.run('copySettings("bot")');
  assert.deepEqual(a.state().view.config.identities.bot.accounts, { mail: { level: 'read' } });
  assert.equal(a.requests.length, 1);
  assert.deepEqual(a.requests[0].body.identities.bot.accounts, { work: null, mail: { level: 'read' } });
  a.requests[0].respond('Copy rejected', 400); await edit;
  assert.equal(level(a), 'ask');
});

test('merge patches delete overrides, replace arrays and treat object keys as data', () => {
  const a = app();
  const json = a.run('JSON.stringify(mergePatch({actions: {read: "off", write: "ask"}, send: ["a"]}, {actions: {read: null}, send: ["b"]}))');
  assert.deepEqual(JSON.parse(json), { actions: { write: 'ask' }, send: ['b'] });
  a.run('mergePatch({}, JSON.parse(\'{"__proto__": {"polluted": true}}\'))');
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

const browserApp = () => {
  const a = app();
  a.run('serverState.view.config.accounts.web = {preset: "custom", connections: {"": {browser: {}}}}; project(); sessionStorage.setItem(KEY, "key"); location.hash = "#account/web"; liveSync()');
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
