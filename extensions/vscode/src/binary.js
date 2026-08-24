'use strict';

const path = require('path');

// Only global user configuration is a trusted executable selector. Workspace
// and folder values originate in the repository and must never receive secrets.
function globalConfiguredPath(inspectedSetting) {
    return inspectedSetting?.globalValue || '';
}

function standardSearchPaths(name, platform, home, env) {
    switch (platform) {
        case 'win32':
            return [
                path.join(env.LOCALAPPDATA || '', 'local-ai-firewall', name),
                path.join(env.ProgramFiles || '', 'local-ai-firewall', name),
            ];
        case 'darwin':
            return [
                path.join(home, 'Library', 'Application Support', 'local-ai-firewall', name),
                path.join('/opt/homebrew/bin', name),
                path.join('/usr/local/bin', name),
                path.join(home, '.local', 'bin', name),
            ];
        default:
            return [
                path.join(home, '.local', 'bin', name),
                path.join('/usr/local/bin', name),
                path.join('/usr/bin', name),
            ];
    }
}

module.exports = { globalConfiguredPath, standardSearchPaths };
