import test from 'node:test';
import assert from 'node:assert/strict';
import * as dashboard from './app/dashboard.js';

const view = { config: { identities: { bot: { accounts: {} } }, accounts: {} }, presets: {}, labels: {} };
const filters = { query: '', state: '', agent: '', account: '', page: 0 };
const request = (id, overrides = {}) => ({ id: String(id), state: 'allowed', time: '2026-10-12T10:00:00Z',
  facts: { principal: { name: 'bot' }, account: 'work', title: `Request ${id}`, operation: { id: 'create', action: 'write' } }, ...overrides });
const html = parts => parts.map(([, value]) => value).join('');
const activity = (requests, overrides = {}) => html(dashboard.activity(view, requests, { ...filters, ...overrides }, [], () => ''));

test('activity combines text, status, agent and account filters', () => {
  const records = [request(1), request(2, { state: 'denied' }), request(3, { facts: { principal: {name: 'other'}, account: 'other', title: 'Elsewhere' } })];
  const result = activity(records, { query: 'REQUEST', state: 'allowed', agent: 'bot', account: 'work' });
  assert.match(result, /href="#request\/1"/);
  assert.doesNotMatch(result, /href="#request\/[23]"/);
  assert.match(activity(records, { query: 'missing' }), /No matching requests/);
});

test('activity paginates and clamps the page after a filtered list shrinks', () => {
  const records = Array.from({ length: 51 }, (_, i) => request(i));
  assert.doesNotMatch(activity(records), /href="#request\/50"/);
  assert.match(activity(records, { page: 1 }), /51 to 51 of 51 requests/);
  assert.match(activity(records.slice(0, 1), { page: 1 }), /1 to 1 of 1 requests/);
});

test('expired requests cannot show inline approval buttons before the next poll', () => {
  const expired = request(1, { state: 'pending', expires: '2000-01-01T00:00:00Z' });
  const result = activity([expired]);
  assert.match(result, /Expired/);
  assert.doesNotMatch(result, /Allow once|Deny request/);
  assert.doesNotMatch(html(dashboard.stats(view, [expired])), /Agents are waiting/);
  const pending = request(2, { state: 'pending', expires: '2999-01-01T00:00:00Z' });
  assert.match(activity([pending]), /Allow once/);
  assert.doesNotMatch(activity([{...pending, savingDecision: true}]), /Allow once/);
});

test('request and agent names are escaped in text, attributes and action handlers', () => {
  const hostile = `<img src=x onerror='alert(1)'>`;
  const r = request(`id' onclick='bad`, {state: 'pending', facts: {principal: {name: hostile}, account: hostile, title: hostile}});
  const result = activity([r]);
  assert.doesNotMatch(result, /<img|onclick='bad/);
  assert.match(result, /&#60;img/);
  assert.match(result, /id&#39; onclick=&#39;bad/);
  const v = {...view, config: {...view.config, identities: {[hostile]: {accounts: {}}}}};
  assert.doesNotMatch(dashboard.collection('agents', v, '', () => '').join(''), /<img/);
});

test('all management sections and their detail routes keep the correct navigation active', () => {
  for (const [kind, section] of Object.entries({activity: 'activity', request: 'activity', agent: 'agents', pair: 'agents',
    'agent-settings': 'agents', account: 'accounts', add: 'accounts', catalog: 'accounts', preset: 'presets', rules: 'rules', policy: 'policy', integrations: 'integrations', settings: 'settings'})) {
    const nav = dashboard.navigation(kind, view, []);
    assert.match(nav.find(([key]) => key === section)[1], /aria-current="page"/);
    assert.equal(nav.filter(([,markup]) => markup.includes('aria-current="page"')).length, 1);
  }
});

test('catalog connections and preset definitions lead to different shared forms', () => {
  const v = {...view, presets: {custom_api: {title: 'Custom API'}, github: {title: 'GitHub'}}};
  assert.match(dashboard.collection('catalog', v, 'GitHub', () => '').join(''), /href="#add\/github"/);
  assert.match(dashboard.collection('presets', v, 'GitHub', () => '').join(''), /href="#preset\/github"/);
});
