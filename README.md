# ssh-mcp

SSH MCP server that just works. Execute commands on remote hosts via SSH. Also supports scp/sftp.

## Usage with Claude Code

Run without installing

```bash
claude mcp add -s user ssh-mcp -- go run github.com/tenox7/ssh-mcp@latest
```

Install

```bash
go install github.com/tenox7/ssh-mcp@latest
claude mcp add ssh-mcp $(go env GOPATH)/bin/ssh-mcp
```

## Testing with Inspector

```bash
npx @modelcontextprotocol/inspector -- go run github.com/tenox7/ssh-mcp@latest
```
