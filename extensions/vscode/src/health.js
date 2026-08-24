'use strict';

const http = require('http');

function pingHealth(port, options = {}) {
    const get = options.get || http.get;
    const timeout = options.timeout ?? 500;
    return new Promise(resolve => {
        let settled = false;
        const finish = value => {
            if (settled) return;
            settled = true;
            resolve(value);
        };
        const req = get(
            { host: '127.0.0.1', port, path: '/health', timeout },
            res => finish(res.statusCode === 200),
        );
        req.on('error', () => finish(false));
        req.on('timeout', () => {
            req.destroy();
            finish(false);
        });
    });
}

module.exports = { pingHealth };
