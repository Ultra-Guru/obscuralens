import test from 'node:test';
import assert from 'node:assert/strict';

const values = new Map();
globalThis.sessionStorage = {
  getItem: (key) => values.get(key) ?? null,
  setItem: (key, value) => values.set(key, String(value)),
  removeItem: (key) => values.delete(key),
};
const events = [];
globalThis.window = {
  dispatchEvent: (event) => { events.push(event); return true; },
};
if (typeof globalThis.CustomEvent !== 'function') {
  globalThis.CustomEvent = class CustomEvent extends Event {
    constructor(type, options = {}) { super(type); this.detail = options.detail; }
  };
}

const apiModule = await import('../../obscuralens/web/static/js/api.js');
const { ApiError, clearApiToken, request, setApiToken } = apiModule;

test(' bearer credential is session-scoped and sent only as a header', async (t) => {
  const originalFetch = globalThis.fetch;
  t.after(() => { globalThis.fetch = originalFetch; clearApiToken(); });
  let captured;
  globalThis.fetch = async (path, init) => {
    captured = { path, init };
    return new Response('{"ok":true}', {
      status: 200, headers: { 'Content-Type': 'application/json' },
    });
  };

  setApiToken('  test-long-lived-token  ');
  assert.equal(values.get('ol-web-token'), 'test-long-lived-token');
  assert.deepEqual(await request('/api/example'), { ok: true });
  assert.equal(captured.path, '/api/example');
  assert.equal(captured.init.headers.Authorization, 'Bearer test-long-lived-token');
  assert.equal(captured.path.includes('test-long-lived-token'), false);

  clearApiToken();
  assert.equal(values.has('ol-web-token'), false);
  await request('/api/example');
  assert.equal(captured.init.headers.Authorization, undefined);
});

test('401 raises ApiError and notifies the authentication gate', async (t) => {
  const originalFetch = globalThis.fetch;
  t.after(() => { globalThis.fetch = originalFetch; });
  globalThis.fetch = async () => new Response('{"detail":"authentication required"}', {
    status: 401, headers: { 'Content-Type': 'application/json' },
  });
  events.length = 0;
  await assert.rejects(request('/api/private'), (error) => {
    assert.ok(error instanceof ApiError);
    assert.equal(error.status, 401);
    return true;
  });
  assert.equal(events.length, 1);
  assert.equal(events[0].type, 'obscuralens:auth-required');
});
