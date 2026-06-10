// Local AI Firewall — VS Code Extension
// Zero-friction sidecar management for AI coding agents.
//
// User journey (kullanıcı yolculuğu):
//   Install VSIX → first-run wizard → API key stored → firewall starts → status bar shows shield
//   From that point: VS Code opens → firewall auto-starts → Claude Code / Cursor just works.

'use strict';

const vscode  = require('vscode');
const cp      = require('child_process');
const path    = require('path');
const fs      = require('fs');
const http    = require('http');
const os      = require('os');

// ── Constants ─────────────────────────────────────────────────────────────────

const EXT          = 'localAiFirewall';
const SECRET_KEY   = `${EXT}.apiKey`;
const HEALTH_INTERVAL_MS = 15_000; // poll every 15 s once running
const START_TIMEOUT_MS   = 6_000;  // max wait for first healthy response
const HEALTH_POLL_MS     = 300;    // interval while waiting for startup

// ── Module-level state ────────────────────────────────────────────────────────

/** @type {cp.ChildProcess|null} */
let proc          = null;
/** @type {vscode.StatusBarItem|null} */
let statusBar     = null;
/** @type {vscode.OutputChannel|null} */
let out           = null;
/** @type {NodeJS.Timeout|null} */
let healthTimer   = null;
/** @type {vscode.SecretStorage} */
let secrets;

// ── Activate / Deactivate ─────────────────────────────────────────────────────

/**
 * Called once when the extension is first loaded.
 * @param {vscode.ExtensionContext} ctx
 */
async function activate(ctx) {
    secrets = ctx.secrets;
    out     = vscode.window.createOutputChannel('Local AI Firewall');

    // Status bar — always visible on the right side, click = toggle
    statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    ctx.subscriptions.push(statusBar);
    renderStatus('stopped');
    statusBar.show();

    // Register commands
    const register = (id, fn) =>
        ctx.subscriptions.push(vscode.commands.registerCommand(`${EXT}.${id}`, fn));

    register('start',       () => cmdStart(ctx));
    register('stop',        () => cmdStop());
    register('restart',     () => cmdRestart(ctx));
    register('setApiKey',   () => cmdSetApiKey());
    register('openMetrics', () => cmdOpenMetrics());
    register('copyEnv',     () => cmdCopyEnv());

    // First-run: if no API key is stored yet, walk the user through setup
    const stored = await secrets.get(SECRET_KEY);
    if (!stored) {
        await firstRunWizard(ctx);
    } else if (cfg().get('autoStart')) {
        // Returning user with autoStart — launch silently
        await cmdStart(ctx);
    }
}

/** Called when VS Code shuts down or the extension is uninstalled. */
function deactivate() {
    stopHealthCheck();
    if (proc) {
        proc.kill('SIGTERM');
        proc = null;
    }
}

// ── Commands ──────────────────────────────────────────────────────────────────

/** Start the firewall binary as a child process. */
async function cmdStart(ctx) {
    if (proc) {
        vscode.window.showInformationMessage('🔥 Firewall is already running.');
        return;
    }

    const binary = await resolveBinary(ctx);
    if (!binary) return;

    const apiKey = await resolveApiKey();
    if (!apiKey) return;

    const c    = cfg();
    const port = c.get('port') ?? 8080;

    const env = {
        ...process.env,
        FORWARD_API_KEY: apiKey,
        UPSTREAM_URL:    c.get('upstreamUrl')   || 'https://api.anthropic.com',
        FIREWALL_PORT:   String(port),
        LOG_LEVEL:       c.get('logLevel')       || 'info',
        PROVIDER_HINT:   c.get('providerHint')   || '',
        VAULT_SIZE_LIMIT: String(c.get('vaultSizeLimit') || 1000),
        MASK_PATHS:      String(c.get('maskPaths')  !== false),
        MASK_EMAILS:     String(c.get('maskEmails') !== false),
    };

    out.appendLine(`\n[firewall] Starting on :${port}  binary=${binary}`);
    out.appendLine(`[firewall] Upstream: ${env.UPSTREAM_URL}\n`);

    proc = cp.spawn(binary, [], { env, stdio: ['ignore', 'pipe', 'pipe'] });

    proc.stdout.on('data', d => out.append(d.toString()));
    proc.stderr.on('data', d => out.append(d.toString()));

    proc.on('error', err => {
        out.appendLine(`[error] ${err.message}`);
        vscode.window.showErrorMessage(`🔥 Firewall failed to start: ${err.message}`);
        proc = null;
        renderStatus('error');
    });

    proc.on('exit', (code, signal) => {
        out.appendLine(`\n[firewall] exited  code=${code}  signal=${signal}`);
        proc = null;
        renderStatus('stopped');
        stopHealthCheck();
    });

    renderStatus('starting');
    const healthy = await waitUntilHealthy(port);
    if (healthy) {
        renderStatus('running');
        startHealthCheck(port);
        vscode.window.showInformationMessage(
            `🔥 Firewall running on :${port}`,
            'Copy Agent Env'
        ).then(v => v === 'Copy Agent Env' && cmdCopyEnv());
    } else {
        renderStatus('error');
        vscode.window.showErrorMessage(
            'Firewall did not respond to /health — check Output for logs.',
            'Show Logs'
        ).then(v => v === 'Show Logs' && out.show());
    }
}

/** Stop the running firewall. */
async function cmdStop() {
    if (!proc) {
        vscode.window.showInformationMessage('Firewall is not running.');
        return;
    }
    proc.kill('SIGTERM');
    stopHealthCheck();
    // proc.on('exit') will call renderStatus('stopped')
}

/** Restart: stop → short pause → start. */
async function cmdRestart(ctx) {
    if (proc) {
        await cmdStop();
        // wait for port to release
        await sleep(700);
    }
    await cmdStart(ctx);
}

/** Prompt for an API key and persist it in SecretStorage. */
async function cmdSetApiKey() {
    const key = await vscode.window.showInputBox({
        title:          'Local AI Firewall — API Key',
        prompt:         'Your key is stored in VS Code SecretStorage (never written to disk or logs)',
        password:       true,
        placeHolder:    'sk-ant-...  /  sk-...  /  AIza...',
        ignoreFocusOut: true,
    });
    if (!key?.trim()) return;
    await secrets.store(SECRET_KEY, key.trim());
    vscode.window.showInformationMessage('🔑 API key saved securely.');
}

/** Open the /metrics JSON endpoint in the browser. */
function cmdOpenMetrics() {
    const port = cfg().get('port') ?? 8080;
    vscode.env.openExternal(vscode.Uri.parse(`http://127.0.0.1:${port}/metrics`));
}

/**
 * Copy the correct env-var block to the clipboard so the user can paste it
 * into their terminal before starting Claude Code / Cursor / Aider.
 */
async function cmdCopyEnv() {
    const port     = cfg().get('port') ?? 8080;
    const upstream = (cfg().get('upstreamUrl') || 'https://api.anthropic.com').toLowerCase();

    /** @type {string[]} */
    const lines = [];

    const isShell = os.platform() !== 'win32';
    const exp     = (k, v) => isShell ? `export ${k}="${v}"` : `$env:${k}="${v}"`;
    const comment = isShell ? '#' : '#';

    if (upstream.includes('anthropic') || (!upstream.includes('openai') && !upstream.includes('googleapis'))) {
        lines.push(comment + ' Anthropic SDK / Claude Code / Cursor');
        lines.push(exp('ANTHROPIC_BASE_URL', `http://127.0.0.1:${port}`));
        lines.push(exp('ANTHROPIC_API_KEY',  'local-firewall-placeholder'));
    }
    if (upstream.includes('openai')) {
        lines.push(comment + ' OpenAI SDK');
        lines.push(exp('OPENAI_BASE_URL', `http://127.0.0.1:${port}/v1`));
        lines.push(exp('OPENAI_API_KEY',  'local-firewall-placeholder'));
    }
    if (upstream.includes('googleapis')) {
        lines.push(comment + ' Google Gemini SDK');
        lines.push(exp('GOOGLE_API_BASE', `http://127.0.0.1:${port}`));
    }
    if (upstream.includes('groq')) {
        lines.push(comment + ' Groq SDK');
        lines.push(exp('GROQ_API_BASE', `http://127.0.0.1:${port}/openai/v1`));
        lines.push(exp('GROQ_API_KEY',  'local-firewall-placeholder'));
    }

    lines.push('');
    lines.push(comment + ' Then launch your agent:  claude / cursor / aider / continue');

    const text = lines.join('\n');
    await vscode.env.clipboard.writeText(text);

    vscode.window.showInformationMessage(
        `📋 Env vars copied — paste in terminal, then start your agent.`,
        'Show'
    ).then(v => { if (v === 'Show') { out.appendLine('\n' + text + '\n'); out.show(); } });
}

// ── First-run wizard ──────────────────────────────────────────────────────────

/**
 * Guide a brand-new user through API key setup and optionally enable autoStart.
 * @param {vscode.ExtensionContext} ctx
 */
async function firstRunWizard(ctx) {
    const choice = await vscode.window.showInformationMessage(
        '🔥 Welcome to Local AI Firewall! Set your API key to protect AI prompts from leaking secrets.',
        { modal: false },
        'Set API Key & Start', 'Later'
    );
    if (choice !== 'Set API Key & Start') return;

    await cmdSetApiKey();

    // Only continue if a key was actually saved
    const saved = await secrets.get(SECRET_KEY);
    if (!saved) return;

    const autoChoice = await vscode.window.showInformationMessage(
        'Start the firewall automatically every time VS Code opens?',
        'Yes, auto-start', 'No'
    );
    if (autoChoice === 'Yes, auto-start') {
        await cfg().update('autoStart', true, vscode.ConfigurationTarget.Global);
    }

    await cmdStart(ctx);
}

// ── Binary resolution ─────────────────────────────────────────────────────────

/**
 * Find the ai-firewall binary through a 5-level fallback chain.
 * @param {vscode.ExtensionContext} ctx
 * @returns {Promise<string|null>} absolute path or null if user cancelled
 */
async function resolveBinary(ctx) {
    const c          = cfg();
    const name       = os.platform() === 'win32' ? 'ai-firewall.exe' : 'ai-firewall';
    const configured = c.get('binaryPath');

    // 1. Explicit setting
    if (configured && fs.existsSync(configured)) return configured;

    // 2. AI_FIREWALL_BINARY env var (useful for CI / dotfiles)
    const fromEnv = process.env['AI_FIREWALL_BINARY'];
    if (fromEnv) {
        const expanded = fromEnv.replace(/^~/, os.homedir());
        if (fs.existsSync(expanded)) return expanded;
    }

    // 3. Workspace root folders
    for (const folder of vscode.workspace.workspaceFolders ?? []) {
        const p = path.join(folder.uri.fsPath, name);
        if (fs.existsSync(p)) return p;
    }

    // 4. Extension bundle directory (when binary is shipped alongside VSIX)
    const bundled = path.join(ctx.extensionPath, name);
    if (fs.existsSync(bundled)) return bundled;

    // 5. OS standard install locations
    const candidates = binarySearchPaths(name);
    for (const p of candidates) {
        if (fs.existsSync(p)) return p;
    }

    // 6. PATH lookup
    try {
        const cmd    = os.platform() === 'win32' ? `where ${name}` : `which ${name}`;
        const result = cp.execSync(cmd, { encoding: 'utf8', timeout: 2000 }).trim().split('\n')[0];
        if (result && fs.existsSync(result)) return result;
    } catch { /* not on PATH */ }

    // 7. Not found — give user actionable options
    const action = await vscode.window.showErrorMessage(
        `ai-firewall binary not found. Download it from GitHub Releases or point to it manually.`,
        'Browse for binary…', 'Open Releases', 'Cancel'
    );

    if (action === 'Browse for binary…') {
        const picked = await vscode.window.showOpenDialog({
            canSelectFiles:   true,
            canSelectFolders: false,
            canSelectMany:    false,
            title:            'Select ai-firewall binary',
            filters: os.platform() === 'win32' ? { Executable: ['exe'] } : {},
        });
        if (picked?.[0]) {
            const p = picked[0].fsPath;
            await c.update('binaryPath', p, vscode.ConfigurationTarget.Global);
            return p;
        }
    } else if (action === 'Open Releases') {
        vscode.env.openExternal(vscode.Uri.parse('https://github.com/localai/firewall/releases/latest'));
    }

    return null;
}

/**
 * OS-specific standard locations to check before falling back to PATH lookup.
 * @param {string} name  binary filename
 * @returns {string[]}
 */
function binarySearchPaths(name) {
    const home = os.homedir();
    switch (os.platform()) {
        case 'win32':
            return [
                path.join(process.env['LOCALAPPDATA'] || '', 'local-ai-firewall', name),
                path.join(process.env['ProgramFiles']  || '', 'local-ai-firewall', name),
            ];
        case 'darwin':
            return [
                path.join(home, 'Library', 'Application Support', 'local-ai-firewall', name),
                path.join('/opt/homebrew/bin', name),   // Apple Silicon Homebrew
                path.join('/usr/local/bin', name),      // Intel Homebrew
                path.join(home, '.local', 'bin', name),
            ];
        default: // linux + other unix
            return [
                path.join(home, '.local', 'bin', name),
                path.join('/usr/local/bin', name),
                path.join('/usr/bin', name),
            ];
    }
}

// ── API key resolution ────────────────────────────────────────────────────────

/**
 * Retrieve the API key: SecretStorage → settings fallback → prompt.
 * @returns {Promise<string|null>}
 */
async function resolveApiKey() {
    const fromSecret = await secrets.get(SECRET_KEY);
    if (fromSecret) return fromSecret;

    const fromSettings = cfg().get('forwardApiKey');
    if (fromSettings) return fromSettings;

    // Nothing stored — ask now
    await cmdSetApiKey();
    return secrets.get(SECRET_KEY); // null if user dismissed
}

// ── Status bar ────────────────────────────────────────────────────────────────

/**
 * Update the status bar to reflect the current firewall state.
 * @param {'stopped'|'starting'|'running'|'error'} state
 */
function renderStatus(state) {
    if (!statusBar) return;
    const map = {
        stopped:  { text: '$(debug-stop) Firewall',          tip: 'Local AI Firewall: stopped — click to start',  cmd: `${EXT}.start`, bg: undefined },
        starting: { text: '$(loading~spin) Firewall',        tip: 'Firewall starting…',                            cmd: undefined,       bg: new vscode.ThemeColor('statusBarItem.warningBackground') },
        running:  { text: '$(shield) Firewall',              tip: 'Local AI Firewall: active — click to stop',    cmd: `${EXT}.stop`,  bg: new vscode.ThemeColor('statusBarItem.prominentBackground') },
        error:    { text: '$(error) Firewall',               tip: 'Firewall error — click to retry',              cmd: `${EXT}.start`, bg: new vscode.ThemeColor('statusBarItem.errorBackground') },
    };
    const s = map[state] ?? map.stopped;
    statusBar.text            = s.text;
    statusBar.tooltip         = s.tip;
    statusBar.command         = s.cmd;
    statusBar.backgroundColor = s.bg;
}

// ── Health check ──────────────────────────────────────────────────────────────

/**
 * Poll /health until the firewall responds 200 or the timeout expires.
 * @param {number} port
 * @returns {Promise<boolean>}
 */
async function waitUntilHealthy(port) {
    const deadline = Date.now() + START_TIMEOUT_MS;
    while (Date.now() < deadline) {
        if (await pingHealth(port)) return true;
        await sleep(HEALTH_POLL_MS);
    }
    return false;
}

/** Kick off a recurring health-check that updates the status bar. */
function startHealthCheck(port) {
    stopHealthCheck();
    healthTimer = setInterval(async () => {
        if (!proc) { stopHealthCheck(); return; }
        const ok = await pingHealth(port);
        renderStatus(ok ? 'running' : 'error');
    }, HEALTH_INTERVAL_MS);
}

function stopHealthCheck() {
    if (healthTimer) { clearInterval(healthTimer); healthTimer = null; }
}

/**
 * Single HTTP GET to /health.
 * @param {number} port
 * @returns {Promise<boolean>}
 */
function pingHealth(port) {
    return new Promise(resolve => {
        const req = http.get(
            { host: '127.0.0.1', port, path: '/health', timeout: 500 },
            res => { resolve(res.statusCode === 200); }
        );
        req.on('error',   () => resolve(false));
        req.on('timeout', () => { req.destroy(); resolve(false); });
    });
}

// ── Utilities ─────────────────────────────────────────────────────────────────

/** @returns {vscode.WorkspaceConfiguration} */
function cfg() { return vscode.workspace.getConfiguration(EXT); }

/** @param {number} ms */
const sleep = ms => new Promise(r => setTimeout(r, ms));

// ── Exports ───────────────────────────────────────────────────────────────────

module.exports = { activate, deactivate };