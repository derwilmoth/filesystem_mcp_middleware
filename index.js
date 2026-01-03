"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const child_process_1 = require("child_process");
const path_1 = __importDefault(require("path"));
const fs_1 = __importDefault(require("fs"));
const minimatch_1 = require("minimatch");
// --- Konfiguration laden ---
const CONFIG_PATH = path_1.default.join(__dirname, 'config.json');
const config = JSON.parse(fs_1.default.readFileSync(CONFIG_PATH, 'utf-8'));
// --- Original Server starten ---
// Wir starten den offiziellen Filesystem-Server direkt über npx.
// Das Argument '-y' bestätigt automatisch die Installation, falls nötig.
const args = process.argv.slice(2); // Die erlaubten Pfade von Claude durchreichen
const serverProcess = (0, child_process_1.spawn)('npx', [
    '-y',
    '@modelcontextprotocol/server-filesystem',
    ...args
], {
    stdio: ['pipe', 'pipe', process.stderr] // Stderr leiten wir direkt weiter
});
// --- Security Engine ---
function isRequestAllowed(req) {
    // Nur 'tools/call' ist sicherheitsrelevant
    if (req.method !== 'tools/call')
        return true;
    const toolName = req.params?.name;
    const filePath = req.params?.arguments?.path;
    // Wenn kein Pfad involviert ist, lassen wir es durch
    if (!filePath || !toolName)
        return true;
    const filename = path_1.default.basename(filePath);
    // 1. Check: Totale Sperre (Read & Write)
    const isTotallyBlocked = config.deny_read_and_write.some(pattern => (0, minimatch_1.minimatch)(filename, pattern));
    if (isTotallyBlocked)
        return false;
    // 2. Check: Schreibsperre (Write Only)
    if (toolName === 'write_file') {
        const isWriteBlocked = config.deny_write.some(pattern => (0, minimatch_1.minimatch)(filename, pattern));
        if (isWriteBlocked)
            return false;
    }
    return true;
}
// --- Stream Interceptor Logic ---
// Wir lesen stdin (von Claude), puffern Zeilen und parsen JSON
let buffer = '';
process.stdin.on('data', (chunk) => {
    buffer += chunk.toString();
    // JSON-RPC über Stdio ist oft "Newline Delimited"
    const lines = buffer.split('\n');
    buffer = lines.pop() || ''; // Letztes (unvollständiges) Element behalten
    for (const line of lines) {
        if (!line.trim())
            continue;
        try {
            const message = JSON.parse(line);
            // Sicherheitsprüfung
            if (isRequestAllowed(message)) {
                // ERLAUBT: Nachricht an den echten Server weiterleiten
                serverProcess.stdin.write(JSON.stringify(message) + '\n');
            }
            else {
                // BLOCKIERT: Wir faken eine Antwort an Claude
                const errorResponse = {
                    jsonrpc: "2.0",
                    id: message.id,
                    error: {
                        code: -32000, // App-spezifischer Fehlercode
                        message: "Access denied by MCP Firewall Policy."
                    }
                };
                process.stdout.write(JSON.stringify(errorResponse) + '\n');
                // Optional: Logging für den Admin
                console.error(`[BLOCKED] ${message.params?.name} on ${message.params?.arguments?.path}`);
            }
        }
        catch (e) {
            // Bei Parse-Fehlern leiten wir einfach weiter (Fail-Open oder Fail-Closed)
            console.error("JSON Parse Error", e);
        }
    }
});
// --- Server Output Handling ---
// Antworten vom Server leiten wir einfach zurück an Claude
serverProcess.stdout.pipe(process.stdout);
// Prozess-Ende behandeln
serverProcess.on('exit', (code) => {
    process.exit(code ?? 0);
});
