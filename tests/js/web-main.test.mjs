import test from 'node:test';
import assert from 'node:assert/strict';

// Absolute /static imports are browser-only; loadViews intentionally falls
// back to placeholders under Node, which is sufficient for this boot test.
console.warn = () => {};

class FakeNode {
  constructor(tagName = 'node', text = '') {
    this.tagName = tagName.toUpperCase();
    this.children = [];
    this.dataset = {};
    this.style = {};
    this.attributes = {};
    this.listeners = new Map();
    this.textContent = text;
    this.value = '';
    this.disabled = false;
    this.className = '';
    const classes = new Set();
    this.classList = {
      add: (...names) => names.forEach((name) => classes.add(name)),
      remove: (...names) => names.forEach((name) => classes.delete(name)),
      toggle: (name, force) => {
        const enabled = force === undefined ? !classes.has(name) : Boolean(force);
        enabled ? classes.add(name) : classes.delete(name);
        return enabled;
      },
    };
  }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.children = [...nodes]; }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  removeAttribute(name) { delete this.attributes[name]; }
  addEventListener(type, callback) {
    if (!this.listeners.has(type)) this.listeners.set(type, []);
    this.listeners.get(type).push(callback);
  }
  removeEventListener() {}
  querySelector() { return null; }
  focus() {}
  select() {}
  get isConnected() { return true; }
}

globalThis.Node = FakeNode;
const ids = new Map();
for (const id of [
  'view', 'status-text', 'status-dot', 'brand-version', 'footer-version',
  'view-title', 'view-subtitle', 'app', 'palette-input', 'palette-list',
  'palette', 'palette-open', 'quick-search', 'theme-toggle', 'nav-toggle',
  'sidebar-backdrop', 'nav-workspace', 'nav-investigation', 'nav-platform',
]) ids.set(id, new FakeNode('div'));
ids.get('palette-input').value = '';
ids.get('view-title').textContent = '';

globalThis.document = {
  documentElement: new FakeNode('html'),
  activeElement: null,
  createElement: (tag) => new FakeNode(tag),
  createElementNS: (_namespace, tag) => new FakeNode(tag),
  createTextNode: (text) => new FakeNode('#text', String(text)),
  getElementById: (id) => ids.get(id) ?? null,
  querySelectorAll: () => [],
  addEventListener() {},
  removeEventListener() {},
};
globalThis.location = { hash: '#/startup-probe' };
globalThis.history = {
  replaceState: (_state, _unused, url) => { location.hash = url; },
};
globalThis.localStorage = { getItem: () => null, setItem() {} };
globalThis.window = {
  addEventListener() {},
  dispatchEvent() { return true; },
  matchMedia: () => ({ matches: false }),
  open() {},
};
// Do not leave the 30-second health poll alive in the Node test process.
globalThis.setInterval = () => 1;
globalThis.clearInterval = () => {};

const requests = [];
globalThis.fetch = async (path, init = {}) => {
  requests.push({ path, init });
  if (path === '/api/health') {
    return new Response(JSON.stringify({
      status: 'ok', version: 'test', authentication_required: true,
    }), { status: 200 });
  }
  if (path === '/api/kinds') {
    const valid = init.headers?.Authorization === 'Bearer first-login-token';
    return new Response(valid ? '[]' : '{"detail":"authentication required"}', {
      status: valid ? 200 : 401,
    });
  }
  return new Response('{}', { status: 200 });
};

function find(node, predicate) {
  if (predicate(node)) return node;
  for (const child of node.children || []) {
    const found = find(child, predicate);
    if (found) return found;
  }
  return null;
}
const flush = () => new Promise((resolve) => setImmediate(resolve));

test('first successful login continues into view and navigation startup', async () => {
  await import('../../obscuralens/web/static/js/main.js');
  await flush();
  const root = ids.get('view');
  const form = find(root, (node) => node.tagName === 'FORM');
  assert.ok(form, 'the protected server initially renders the auth gate');
  const input = find(form, (node) => node.tagName === 'INPUT');
  input.value = 'first-login-token';

  await form.listeners.get('submit')[0]({ preventDefault() {} });
  await flush();
  const kinds = requests.find((entry) => entry.path === '/api/kinds');
  assert.equal(kinds.init.headers.Authorization, 'Bearer first-login-token');
  const navItems = ['nav-workspace', 'nav-investigation', 'nav-platform']
    .reduce((total, id) => total + ids.get(id).children.length, 0);
  assert.ok(navItems > 0, 'navigation is built after the first login');
  assert.equal(find(root, (node) => node.tagName === 'FORM'), null,
    'the gate is replaced by the routed workspace');
});
