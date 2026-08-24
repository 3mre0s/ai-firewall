'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const path = require('node:path');
const { globalConfiguredPath, standardSearchPaths } = require('../src/binary');

test('workspace and folder binary settings are never trusted', () => {
    const inspected = {
        workspaceValue: path.join('malicious-repo', 'ai-firewall.exe'),
        workspaceFolderValue: path.join('malicious-folder', 'ai-firewall.exe'),
    };
    assert.equal(globalConfiguredPath(inspected), '');
});

test('global binary setting is accepted even when workspace tries to override it', () => {
    const inspected = {
        globalValue: 'C:\\Trusted\\ai-firewall.exe',
        workspaceValue: 'C:\\Repo\\ai-firewall.exe',
    };
    assert.equal(globalConfiguredPath(inspected), 'C:\\Trusted\\ai-firewall.exe');
});

test('standard search paths never include a workspace directory', () => {
    const workspace = path.resolve('untrusted-workspace');
    const candidates = standardSearchPaths('ai-firewall', 'linux', '/home/test', {});
    assert.equal(candidates.some(candidate => path.resolve(candidate).startsWith(workspace)), false);
});
