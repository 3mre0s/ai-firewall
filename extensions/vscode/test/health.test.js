'use strict';

const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const test = require('node:test');
const { pingHealth } = require('../src/health');

function fakeRequest() {
    const req = new EventEmitter();
    req.destroyed = false;
    req.destroy = () => { req.destroyed = true; };
    return req;
}

test('health check accepts only HTTP 200', async () => {
    for (const [status, expected] of [[200, true], [503, false]]) {
        const req = fakeRequest();
        const result = pingHealth(8080, { get: (_options, callback) => {
            queueMicrotask(() => callback({ statusCode: status }));
            return req;
        }});
        assert.equal(await result, expected);
    }
});

test('health check fails closed on connection error', async () => {
    const req = fakeRequest();
    const result = pingHealth(8080, { get: () => {
        queueMicrotask(() => req.emit('error', new Error('connection refused')));
        return req;
    }});
    assert.equal(await result, false);
});

test('health timeout destroys the stale request', async () => {
    const req = fakeRequest();
    const result = pingHealth(8080, { get: () => {
        queueMicrotask(() => req.emit('timeout'));
        return req;
    }});
    assert.equal(await result, false);
    assert.equal(req.destroyed, true);
});
