import test from 'node:test';
import assert from 'node:assert/strict';

class FakeEventSource {
  static instances = [];
  constructor(url) {
    this.url = url;
    this.listeners = new Map();
    this.closed = false;
    FakeEventSource.instances.push(this);
  }
  addEventListener(topic, callback) { this.listeners.set(topic, callback); }
  close() { this.closed = true; }
}

const { SseClient } = await import('../../obscuralens/web/static/js/sse.js');
const flush = () => new Promise((resolve) => setImmediate(resolve));

test('EventSource receives a one-time ticket, never the bearer token', async (t) => {
  const original = globalThis.EventSource;
  t.after(() => { globalThis.EventSource = original; });
  globalThis.EventSource = FakeEventSource;
  FakeEventSource.instances.length = 0;

  const client = new SseClient('/api/stream', {
    ticketProvider: async () => ({ ticket: 'single-use_ticket', expires_in: 30 }),
  });
  t.after(() => client.close());
  client.connect();
  await flush();
  assert.equal(FakeEventSource.instances.length, 1);
  const source = FakeEventSource.instances[0];
  assert.equal(source.url, '/api/stream?ticket=single-use_ticket');
  assert.equal(source.url.includes('Bearer'), false);
  source.onopen();
  assert.equal(client.state, 'open');
});

test('closing during ticket issuance cannot open a stale stream', async (t) => {
  const original = globalThis.EventSource;
  t.after(() => { globalThis.EventSource = original; });
  globalThis.EventSource = FakeEventSource;
  FakeEventSource.instances.length = 0;

  let issue;
  const client = new SseClient('/api/stream', {
    ticketProvider: () => new Promise((resolve) => { issue = resolve; }),
  });
  client.connect();
  await flush(); // let the deferred ticketProvider start
  client.close();
  issue({ ticket: 'too-late' });
  await flush();
  assert.equal(FakeEventSource.instances.length, 0);
  assert.equal(client.state, 'closed');
});
