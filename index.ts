import { spawn } from 'child_process';
import path from 'path';
import fs from 'fs';
import { minimatch } from 'minimatch';

// --- Typ-Definitionen ---
interface JsonRpcRequest {
  jsonrpc: string;
  id?: number | string;
  method: string;
  params?: {
    name?: string;
    arguments?: {
      path?: string;
      paths?: string[];      // Fuer read_multiple_files
      source?: string;       // Fuer move_file
      destination?: string;  // Fuer move_file
    };
  };
}

interface Config {
  deny_insight: string[];
  deny_modification: string[];
}

// --- Konfiguration laden ---
const CONFIG_PATH = path.join(__dirname, 'config.json');
const config: Config = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf-8'));

// --- Tool-Kategorien definieren ---
const INSIGHT_TOOLS = [
  'read_text_file',
  'read_media_file',
  'read_multiple_files',
  'list_directory_with_sizes',
  'get_file_info'
];

const MODIFICATION_TOOLS = [
  'write_file',
  'edit_file',
  'move_file'
];

// --- Original Server starten ---
const args = process.argv.slice(2); 

const serverProcess = spawn('npx', [
  '-y',
  '@modelcontextprotocol/server-filesystem',
  ...args
], {
  stdio: ['pipe', 'pipe', process.stderr] 
});

// --- Security Engine ---
function isRequestAllowed(req: JsonRpcRequest): boolean {
  if (req.method !== 'tools/call') return true;
  
  const toolName = req.params?.name;
  const args = req.params?.arguments;
  
  if (!toolName || !args) return true;

  // Sammle alle betroffenen Dateien aus verschiedenen Parametern
  let filesToCheck: string[] = [];
  
  // Standard 'path'
  if (args.path) filesToCheck.push(args.path);
  
  // Array 'paths' (read_multiple_files)
  if (args.paths && Array.isArray(args.paths)) {
    filesToCheck.push(...args.paths);
  }
  
  // Source & Destination (move_file)
  if (args.source) filesToCheck.push(args.source);
  if (args.destination) filesToCheck.push(args.destination);

  // Wenn keine Datei betroffen ist (z.B. list_allowed_directories), erlauben
  if (filesToCheck.length === 0) return true;

  // 1. Check: Insight (Vertraulichkeit)
  const isInsightBlocked = filesToCheck.some(filePath => {
    const filename = path.basename(filePath);
    return config.deny_insight.some(pattern => minimatch(filename, pattern));
  });

  if (isInsightBlocked) {
    if (INSIGHT_TOOLS.includes(toolName) || MODIFICATION_TOOLS.includes(toolName)) {
      return false;
    }
  }

  // 2. Check: Modification (Integrität)
  if (MODIFICATION_TOOLS.includes(toolName)) {
    const isModificationBlocked = filesToCheck.some(filePath => {
      const filename = path.basename(filePath);
      return config.deny_modification.some(pattern => minimatch(filename, pattern));
    });
    
    if (isModificationBlocked) return false;
  }

  return true;
}

// --- Stream Interceptor Logic ---
let buffer = '';

process.stdin.on('data', (chunk) => {
  buffer += chunk.toString();
  
  const lines = buffer.split('\n');
  buffer = lines.pop() || ''; 

  for (const line of lines) {
    if (!line.trim()) continue;

    try {
      const message = JSON.parse(line);
      
      if (isRequestAllowed(message)) {
        serverProcess.stdin.write(JSON.stringify(message) + '\n');
      } else {
        const errorResponse = {
          jsonrpc: "2.0",
          id: message.id,
          error: {
            code: -32000, 
            message: "Access denied by MCP Firewall Policy."
          }
        };
        process.stdout.write(JSON.stringify(errorResponse) + '\n');
        
        console.error(`[BLOCKED] Tool: ${message.params?.name}`);
      }
    } catch (e) {
      console.error("JSON Parse Error", e);
    }
  }
});

// --- Server Output Handling ---
serverProcess.stdout.pipe(process.stdout);

serverProcess.on('exit', (code) => {
  process.exit(code ?? 0);
});