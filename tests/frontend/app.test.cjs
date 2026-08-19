'use strict';

const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { resolve } = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const appSource = readFileSync(resolve(__dirname, '../../src/frontend/app.js'), 'utf8');

function storage(initial = {}) {
  const values = new Map(Object.entries(initial));
  return {
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, String(value)),
    removeItem: (key) => values.delete(key),
  };
}

function loadApp(overrides = {}) {
  const listeners = {};
  const context = vm.createContext({
    URL,
    URLSearchParams,
    console,
    document: { cookie: '' },
    fetch: async () => { throw new Error('Unexpected fetch'); },
    history: { replaceState() {} },
    localStorage: storage(),
    location: { origin: 'https://example.test', hash: '' },
    sessionStorage: storage(),
    setTimeout,
    window: { addEventListener: (event, handler) => { listeners[event] = handler; } },
    ...overrides,
  });

  vm.runInContext(`${appSource}\n;globalThis.testApi = { api, apiUrl, confidenceBar, cookieValue, escapeHtml, guardClick, severityBadge, state, router };`, context);
  return { ...context.testApi, listeners };
}

test('apiUrl builds an API path and omits empty parameters', () => {
  const { apiUrl } = loadApp();

  assert.equal(
    apiUrl('/findings', { severity: 'high', skip: 0, empty: '', missing: undefined }),
    '/api/v1/findings?severity=high&skip=0',
  );
});

test('escapeHtml escapes unsafe markup and handles absent values', () => {
  const { escapeHtml } = loadApp();

  assert.equal(escapeHtml(`<script data-x="a&b">'x'</script>`), '&lt;script data-x=&quot;a&amp;b&quot;&gt;&#39;x&#39;&lt;/script&gt;');
  assert.equal(escapeHtml(null), '');
  assert.equal(escapeHtml(undefined), '');
});

test('guardClick prevents duplicate submissions and restores the button', async () => {
  let release;
  let calls = 0;
  const pending = new Promise((resolve) => { release = resolve; });
  const button = { disabled: false };
  const { guardClick } = loadApp();
  const guarded = guardClick(button, async () => { calls += 1; await pending; });

  const first = guarded();
  const second = guarded();
  assert.equal(button.disabled, true);
  assert.equal(calls, 1);

  release();
  await Promise.all([first, second]);
  assert.equal(button.disabled, false);
});

test('api sends same-origin credentials and returns parsed data', async () => {
  let request;
  const fetch = async (url, options) => {
    request = { url, options };
    return { ok: true, status: 200, json: async () => ({ id: 7 }) };
  };
  const { api } = loadApp({ fetch });

  assert.deepEqual(await api('/findings/7', { headers: { 'X-Test': 'yes' } }), { id: 7 });
  assert.equal(request.url, '/api/v1/findings/7');
  assert.equal(request.options.credentials, 'same-origin');
  assert.equal(request.options.headers.Authorization, undefined);
  assert.equal(request.options.headers['Content-Type'], 'application/json');
  assert.equal(request.options.headers['X-Test'], 'yes');
});

test('api sends the double-submit CSRF token on mutations', async () => {
  let request;
  const fetch = async (_url, options) => {
    request = options;
    return { ok: true, status: 200, json: async () => ({ detail: 'ok' }) };
  };
  const { api } = loadApp({ fetch, document: { cookie: 'csrf_token=csrf-value' } });

  await api('/auth/logout', { method: 'POST' });

  assert.equal(request.headers['X-CSRF-Token'], 'csrf-value');
});

test('api surfaces server error details', async () => {
  const fetch = async () => ({
    ok: false,
    status: 422,
    statusText: 'Unprocessable Content',
    json: async () => ({ detail: 'Invalid filter' }),
  });
  const { api } = loadApp({ fetch });

  await assert.rejects(api('/findings'), /Invalid filter/);
});

test('api surfaces errors from the application exception envelope', async () => {
  const fetch = async () => ({
    ok: false,
    status: 500,
    statusText: 'Server Error',
    json: async () => ({ error: 'Database unavailable' }),
  });
  const { api } = loadApp({ fetch });

  await assert.rejects(api('/findings'), /Database unavailable/);
});

test('api clears authentication and redirects after an unauthorized response', async () => {
  const location = { origin: 'https://example.test', hash: '' };
  const fetch = async () => ({
    ok: false,
    status: 401,
    statusText: 'Unauthorized',
    json: async () => ({ detail: 'Session expired' }),
  });
  const { api, state } = loadApp({ fetch, location });

  await assert.rejects(api('/findings'), /Session expired/);
  assert.equal(state.authenticated, false);
  assert.equal(location.hash, '/login');
});

test('api rejects malformed JSON from an otherwise successful response', async () => {
  const fetch = async () => ({
    ok: true,
    status: 200,
    json: async () => { throw new SyntaxError('Invalid JSON'); },
  });
  const { api } = loadApp({ fetch });

  await assert.rejects(api('/findings'), /Invalid JSON/);
});

test('load restores an authenticated session from the HttpOnly cookie', async () => {
  const location = { origin: 'https://example.test', hash: '#/dashboard' };
  const fetch = async () => ({
    ok: true,
    status: 200,
    json: async () => ({ id: 7, username: 'octocat' }),
  });
  const app = loadApp({ fetch, location });
  let routed = 0;
  app.router.handle = () => { routed += 1; };

  await app.listeners.load();

  assert.equal(app.state.authenticated, true);
  assert.equal(app.state.currentUser.username, 'octocat');
  assert.equal(routed, 1);
});

test('load redirects an unauthenticated browser to login', async () => {
  const location = { origin: 'https://example.test', hash: '#/dashboard' };
  const fetch = async () => ({
    ok: false,
    status: 401,
    statusText: 'Unauthorized',
    json: async () => ({ detail: 'Not authenticated' }),
  });
  const app = loadApp({ fetch, location });
  app.router.handle = () => {};

  await app.listeners.load();

  assert.equal(app.state.authenticated, false);
  assert.equal(location.hash, '/login');
});

test('frontend source never persists or parses bearer tokens', () => {
  assert.doesNotMatch(appSource, /localStorage|access_token|oauth_pending/);
});

test('severityBadge escapes labels and restricts CSS severity classes', () => {
  const { severityBadge } = loadApp();
  const html = severityBadge('critical\"><script>alert(1)</script>');

  assert.match(html, /badge-low/);
  assert.doesNotMatch(html, /<script>/);
  assert.match(html, /&lt;script&gt;/);
});

test('confidenceBar treats API confidence as an integer percentage', () => {
  const { confidenceBar } = loadApp();

  assert.match(confidenceBar(95), /width:95%/);
  assert.match(confidenceBar(95), />95%</);
  assert.match(confidenceBar(150), /width:100%/);
});
