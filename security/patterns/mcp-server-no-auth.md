# Pattern: MCP server exposes tools without authentication

**Rule:** G3 (also G5 if it fronts a paid LLM)
**Severity:** P0
**Seen in:** Most of the MCP server examples floating around GitHub in 2025–2026. The MCP spec assumes trusted transports; a surprising amount of hobbyist code exposes HTTP transports without auth.

## Incident story

**2026-01 — indie dev building a "run-my-claude-on-a-vps" server.** The MCP server exposed tools: `run_shell`, `read_file`, `write_file`, `fetch_url`. Transport was plain HTTP on `0.0.0.0:8080`. No bearer check. A Shodan scan picked it up. Within 48 hours someone had used `run_shell` to install a crypto miner. The dev found out when the VPS provider suspended the box for unusual CPU.

## Why MCP servers are especially dangerous

- They intentionally expose **executive** capabilities (run commands, read files) that a classic REST API wouldn't.
- The MCP spec was designed for **trusted transports** — stdio between a trusted LLM process and a local tool server. HTTP/SSE/WebSocket transports inherit *none* of that trust by default.
- Tutorials often skip auth because "I'm just testing locally" — and then the server ships to prod.

## Bad code

### FastMCP without auth

```python
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("my-server")

@mcp.tool()
def run_shell(cmd: str) -> str:
    """Run a shell command."""
    import subprocess
    return subprocess.check_output(cmd, shell=True, text=True)

if __name__ == "__main__":
    mcp.run(transport="sse", host="0.0.0.0", port=8080)
    # No auth. Anyone who can reach port 8080 can run anything.
```

### Node `@modelcontextprotocol/sdk` HTTP

```ts
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import express from 'express';

const server = new McpServer({ name: 'demo', version: '0.1' });
server.tool('deleteFile', { path: z.string() }, async ({ path }) => {
  await fs.unlink(path);
  return { content: [{ type: 'text', text: 'ok' }] };
});

const app = express();
app.get('/sse', async (req, res) => {
  const transport = new SSEServerTransport('/messages', res);
  await server.connect(transport);
});
app.listen(8080);
```

## Good code

### Option 1 — stdio only (safest)

If the server is used by a local LLM process (Claude Desktop, Cursor, Claude Code), use `stdio` transport. The parent process authenticates by virtue of having spawned you.

```python
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("my-server")
# ... tools ...

if __name__ == "__main__":
    mcp.run()    # defaults to stdio
```

### Option 2 — HTTP with bearer auth + allowlist

```python
import os, secrets
from mcp.server.fastmcp import FastMCP
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

EXPECTED = os.environ["MCP_SHARED_SECRET"]   # must be set, ≥ 32 chars

class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        got = request.headers.get("authorization", "")
        if not got.startswith("Bearer ") or not secrets.compare_digest(got[7:], EXPECTED):
            return Response("unauthorized", status_code=401)
        return await call_next(request)

mcp = FastMCP("my-server", middleware=[AuthMiddleware])

@mcp.tool()
def run_shell(cmd: str) -> str:
    # Even with auth, restrict tools to a tight allowlist of commands.
    ALLOWED = {"uptime", "whoami", "date"}
    if cmd.split()[0] not in ALLOWED:
        raise ValueError("command not allowed")
    import subprocess
    return subprocess.check_output(cmd, shell=True, text=True)

if __name__ == "__main__":
    mcp.run(transport="sse", host="127.0.0.1", port=8080)   # localhost only
```

Set a strong secret:
```bash
export MCP_SHARED_SECRET=$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')
```

### Option 3 — behind an authenticated reverse proxy

Put the MCP server behind Caddy / Nginx / Cloudflare Access that enforces auth and only proxies to the MCP server after identity is proven. The MCP server binds to `127.0.0.1`.

### Dangerous tools — extra guardrails

Tools like `run_shell`, `write_file`, `exec_code`, `http_fetch` should **also**:

- Have a per-tool allowlist (commands, paths, URLs).
- Log every invocation.
- Rate-limit.
- Require a second confirmation for destructive actions.
- Refuse to operate outside a sandboxed directory.

```python
SANDBOX = Path("/srv/mcp-sandbox").resolve()

@mcp.tool()
def write_file(path: str, content: str) -> str:
    target = (SANDBOX / path).resolve()
    if not target.is_relative_to(SANDBOX):
        raise ValueError("path escapes sandbox")
    if len(content) > 1_000_000:
        raise ValueError("content too large")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)
    return f"wrote {target}"
```

## Detection

`auto_audit.py` flags any file that creates an MCP server **and** doesn't reference an auth/secret token anywhere:

```regex
FastMCP\s*\(|McpServer\s*\(|new\s+Server\s*\(|StdioServerTransport|create_mcp_server
```

Plus the absence of `Authorization`, `Bearer `, `auth_token`, `shared_secret`, `allowlist` in the file.

## Runtime probe

```bash
# Is the MCP server open?
curl -i http://your.host:8080/sse
# If you get a 200 + an SSE stream without Authorization, it's open.

# Is it bindable from the public internet?
nmap -p 8080 your.host
```

## References

- [MCP spec — Transports](https://spec.modelcontextprotocol.io/specification/basic/transports/)
- [Anthropic's MCP security note](https://www.anthropic.com/news/model-context-protocol) (check the latest; guidance evolves)
- [CVE-style disclosures for open dev tools — Redis, MongoDB, Elasticsearch](https://www.shodan.io/) — same pattern (service with no auth bound to `0.0.0.0`).
