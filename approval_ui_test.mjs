import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import test from 'node:test';
import assert from 'node:assert/strict';
import * as ownerModule from './app/owner.js';

const source = readFileSync(new URL('./app/index.html', import.meta.url), 'utf8')
  .match(/<script type="module">([\s\S]*)<\/script>/)[1].replace(/^import .*$/m, '').split('window.addEventListener')[0];

function app() {
  const requests = [];
  const context = vm.createContext({
    owner: ownerModule, URL, structuredClone, setTimeout: () => 1, clearTimeout() {},
    location: { hash: '#request/1' },
    localStorage: { getItem: () => null, setItem() {}, removeItem() {} },
    sessionStorage: { getItem: () => null, setItem() {}, removeItem() {} },
    document: { title: '', getElementById: () => ({}) },
    fetch(path, options = {}) {
      if (path === 'icons/manifest.json') return Promise.resolve({ ok: true, json: async () => ({}) });
      return new Promise(resolve => requests.push({ path, options, respond(body, status = 200) {
        resolve({ ok: status < 400, status, text: async () => body });
      } }));
    },
  });
  const run = code => vm.runInContext(code, context);
  run(source);
  run(`render = () => {}; toast = () => {};
    remember({generation: 1, config: {
      accounts: {work: {preset: "custom"}},
      identities: {bot: {accounts: {work: {level: "allow"}}, rules: {}}}
    }, presets: {custom: {title: "Custom", actions: {}, operations: {}, vocabulary: {}}}, labels: {}, fields: {}, status: {}});
    serverState.records = [{id: "1", state: "pending", time: "2026-10-08T00:00:00Z", expires: "2026-10-08T01:00:00Z",
      facts: {principal: {name: "bot"}, account: "work", operation: {id: "transfer", action: "transfer"}, parameters: {amount: 501}},
      grant: {amount: 501}, definition: "definition",
      requirements: [{id: "owner.payment_limit", message: "Review <script>alert(1)</script> & payment."}]
    }]; project();`);
  return { run, requests };
}

test('approval messages come from the decision and render as text', () => {
  const a = app();
  const html = a.run('requestPane("1").join("")');
  assert.ok(html.includes('Review &#60;script&#62;alert(1)&#60;/script&#62; &#38; payment.'));
  assert.ok(!html.includes('<script>alert(1)</script>'));
  assert.ok(!html.includes('undefined'));
});

test('built-in explanations also come from policy', () => {
  const a = app();
  a.run(`serverState.records[0].requirements = [
      {id: "ask", message: "Access explanation."},
      {id: "audience", message: "Disclosure explanation."},
      {id: "trust", message: "Trust explanation."}
    ]; project();`);
  assert.deepEqual(JSON.parse(a.run('JSON.stringify(reasons(records[0]))')),
    ['Access explanation.', 'Disclosure explanation.', 'Trust explanation.']);
});

test('saved approvals retain IDs and messages and roll back together', async () => {
  const a = app();
  const edit = a.run('answer("1", "save")');
  const rule = JSON.parse(a.run('JSON.stringify(view.config.identities.bot.rules["1"])'));
  assert.deepEqual(rule.requirements, [{ id: 'owner.payment_limit', message: 'Review <script>alert(1)</script> & payment.' }]);
  assert.match(a.run('ruleSentence(view.config.identities.bot.rules["1"])'), /Review <script>/);
  assert.match(a.run('rulesSection("bot")'), /Review &#60;script&#62;/);
  assert.equal(a.run('records[0].state'), 'approved');
  assert.deepEqual(JSON.parse(a.requests[0].options.body), { decision: 'save' });
  a.requests[0].respond('Approval expired', 400);
  await edit;
  assert.equal(a.run('records[0].state'), 'pending');
  assert.equal(a.run('Object.keys(view.config.identities.bot.rules).length'), 0);
});

test('refused requests display the policy denial safely', () => {
  const a = app();
  a.run('serverState.records[0].state = "refused"; serverState.records[0].requirements = []; serverState.records[0].deny = ["Message delivery requires approval: Review <data>."]; project()');
  assert.match(a.run('requestPane("1").join("")'), /Message delivery requires approval: Review &#60;data&#62;./);
});
