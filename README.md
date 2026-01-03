# Filesystem MCP Server Security Middleware

This project implements a security middleware for the Model Context Protocol (MCP) Filesystem Server. It acts as a transparent proxy between an MCP Client (e.g., Claude Desktop) and the official Anthropic Filesystem Server.

While the standard Filesystem Server controls access based on directory paths (spatial security), this middleware adds a layer of granular access control based on filenames and user intent (read vs. write). It prevents "excessive agency" by blocking access to sensitive files (like `.env`) or preventing modification of critical documents within allowed directories.

## Features

- **Intent-Based Filtering:** Distinguishes between "Insight" (read) and "Modification" (write) operations.
- **Filename Pattern Matching:** Uses glob patterns (e.g., `*.env`, `*.lock`) to define rules independent of the absolute path.
- **Transparent Proxy:** Intercepts JSON-RPC messages via Stdio, validates them, and forwards allowed requests to the original server via `npx`.
- **Zero-Config Server Management:** Automatically spawns the official `@modelcontextprotocol/server-filesystem` internally.

## Requirements

- **Node.js**: Version 18 or higher.
- **NPM**: Installed automatically with Node.js.
- **MCP Client**: An application compatible with MCP, such as Claude Desktop.

## Installation

1.  Clone this repository to a permanent location on your machine.
2.  Navigate into the project directory.
3.  Install the required dependencies (specifically `minimatch`):

```bash
npm install
```

_Note: The project includes the pre-compiled `index.js`, so no TypeScript build step is required._

## Configuration

The security rules are defined in the `config.json` file located in the root directory. You can define two types of restrictions:

### 1. deny_insight

Files matching these patterns are completely invisible to the AI agent. Any attempt to read, list, or get metadata for these files will be blocked. This implies a modification ban as well.

- **Target Tools:** `read_text_file`, `read_media_file`, `read_multiple_files`, `list_directory_with_sizes`, `get_file_info`.

### 2. deny_modification

Files matching these patterns can be read by the AI (to provide context), but cannot be modified, moved, or overwritten.

- **Target Tools:** `write_file`, `edit_file`, `move_file`.

### Example `config.json`

```json
{
  "deny_insight": [".env", "id_rsa", "*.pem", "credentials.json", ".git"],
  "deny_modification": [
    "thesis.tex",
    "package-lock.json",
    "README.md",
    "*.lock"
  ]
}
```

## Integration with Claude Desktop

To use this middleware with Claude Desktop, you must modify your MCP configuration file.

1.  Open your Claude Desktop configuration file:

    - **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
    - **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

2.  Edit the `mcpServers` section. Instead of running `npx` directly, you will configure it to run this middleware using `node`.

**Configuration Example:**

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "node",
      "args": [
        "/ABSOLUTE/PATH/TO/YOUR/REPO/index.js",
        "/Users/username/Desktop",
        "/Users/username/Projects"
      ]
    }
  }
}
```

- Replace `/ABSOLUTE/PATH/TO/YOUR/REPO/index.js` with the actual full path to the `index.js` file in this repository.
- The paths following the script path (e.g., `/Users/username/Desktop`) are the allowed root directories. The middleware passes these arguments directly to the internal MCP server.

## How it Works

1.  **Initialization:** When Claude Desktop starts, it executes `node index.js`.
2.  **Spawning:** The middleware internally spawns the official server using `npx -y @modelcontextprotocol/server-filesystem`.
3.  **Interception:**
    - The middleware listens to the `stdin` stream from Claude.
    - It parses incoming JSON-RPC messages.
    - If the message is a `tools/call` request, it checks the tool name and arguments against `config.json`.
4.  **Decision:**
    - **Allowed:** The message is forwarded to the internal server.
    - **Blocked:** The middleware generates a synthetic JSON-RPC error response ("Access denied by MCP Firewall Policy") and sends it back to Claude. The internal server never receives the command.
5.  **Output:** Responses from the internal server are piped directly back to `stdout` for Claude to read.

## Troubleshooting

If the server does not appear in Claude:

1.  Check the Claude Desktop logs: `~/Library/Logs/Claude/mcp.log` (macOS) or `%APPDATA%\Claude\logs\mcp.log` (Windows).
2.  Ensure you have run `npm install` in this directory.
3.  Ensure the path to `index.js` in the config file is absolute and correct.
4.  Verify that `config.json` contains valid JSON syntax.
