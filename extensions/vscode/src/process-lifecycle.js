'use strict';

/**
 * Owns exactly one child process and ignores late events from older children.
 * Keeping this independent of VS Code makes restart and stale-process behavior
 * deterministic and unit-testable.
 */
class ProcessLifecycle {
    constructor({ spawn, onStdout = () => {}, onStderr = () => {}, onError = () => {}, onExit = () => {} }) {
        this.spawn = spawn;
        this.onStdout = onStdout;
        this.onStderr = onStderr;
        this.onError = onError;
        this.onExit = onExit;
        this.current = null;
    }

    get active() {
        return this.current !== null;
    }

    start(binary, env) {
        if (this.current) return false;

        let child;
        try {
            child = this.spawn(binary, [], { env, stdio: ['ignore', 'pipe', 'pipe'] });
        } catch (error) {
            this.onError(error);
            return false;
        }

        this.current = child;
        child.stdout?.on('data', data => this.onStdout(data));
        child.stderr?.on('data', data => this.onStderr(data));
        child.on('error', error => {
            if (!this.clear(child)) return;
            this.onError(error);
        });
        child.on('exit', (code, signal) => {
            if (!this.clear(child)) return;
            this.onExit(code, signal);
        });
        return true;
    }

    stop(signal = 'SIGTERM') {
        if (!this.current) return false;
        this.current.kill(signal);
        return true;
    }

    dispose() {
        this.stop();
        this.current = null;
    }

    clear(child) {
        if (this.current !== child) return false;
        this.current = null;
        return true;
    }
}

module.exports = { ProcessLifecycle };
