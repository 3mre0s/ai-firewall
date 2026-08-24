'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { ProcessLifecycle } = require('../src/process-lifecycle');

function fakeChild() {
    const child = new EventEmitter();
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
    child.signals = [];
    child.kill = signal => { child.signals.push(signal); return true; };
    return child;
}

test('only one child can be active and stop uses SIGTERM', () => {
    const child = fakeChild();
    const lifecycle = new ProcessLifecycle({ spawn: () => child });

    assert.equal(lifecycle.start('/trusted/firewall', { FORWARD_API_KEY: 'secret' }), true);
    assert.equal(lifecycle.start('/other/firewall', {}), false);
    assert.equal(lifecycle.stop(), true);
    assert.deepEqual(child.signals, ['SIGTERM']);
    assert.equal(lifecycle.active, true, 'process remains active until exit is observed');

    child.emit('exit', 0, null);
    assert.equal(lifecycle.active, false);
});

test('late exit from a stale child cannot clear the replacement child', () => {
    const first = fakeChild();
    const second = fakeChild();
    const children = [first, second];
    const exits = [];
    const lifecycle = new ProcessLifecycle({
        spawn: () => children.shift(),
        onExit: (code, signal) => exits.push({ code, signal }),
    });

    lifecycle.start('/trusted/firewall', {});
    first.emit('exit', 0, null);
    lifecycle.start('/trusted/firewall', {});
    first.emit('exit', 1, 'SIGKILL');

    assert.equal(lifecycle.active, true);
    assert.deepEqual(exits, [{ code: 0, signal: null }]);
    second.emit('exit', 0, null);
    assert.equal(lifecycle.active, false);
});

test('spawn and asynchronous child errors fail closed', () => {
    const errors = [];
    const thrown = new ProcessLifecycle({
        spawn: () => { throw new Error('spawn denied'); },
        onError: error => errors.push(error.message),
    });
    assert.equal(thrown.start('/bad/firewall', {}), false);
    assert.equal(thrown.active, false);

    const child = fakeChild();
    const emitted = new ProcessLifecycle({
        spawn: () => child,
        onError: error => errors.push(error.message),
    });
    emitted.start('/trusted/firewall', {});
    child.emit('error', new Error('binary vanished'));
    assert.equal(emitted.active, false);
    assert.deepEqual(errors, ['spawn denied', 'binary vanished']);
});

test('dispose terminates the owned child and clears state', () => {
    const child = fakeChild();
    const lifecycle = new ProcessLifecycle({ spawn: () => child });
    lifecycle.start('/trusted/firewall', {});
    lifecycle.dispose();
    assert.deepEqual(child.signals, ['SIGTERM']);
    assert.equal(lifecycle.active, false);
});
