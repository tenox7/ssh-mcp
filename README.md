# ssh-mcp

SSH MCP server. Execute commands on remote hosts via SSH.

## Install

```bash
go install github.com/tenox7/ssh-mcp@latest
```

## Usage with Claude Code

```bash
claude mcp add ssh-mcp -- go run github.com/tenox7/ssh-mcp@latest
```

Or if installed:

```bash
claude mcp add ssh-mcp $(go env GOPATH)/bin/ssh-mcp
```

## Testing with Inspector

```bash
npx @modelcontextprotocol/inspector -- go run github.com/tenox7/ssh-mcp@latest
```

## Tools

### ssh_exec

Execute a command on a remote host.

- `host` - SSH target in format `user@host` or `user@host:port`
- `command` - Command to execute

### ssh_sftp

Copy files via SFTP (requires SFTP subsystem on server).

- `host` - SSH target in format `user@host` or `user@host:port`
- `source` - Source path (prefix with `remote:` for remote files)
- `dest` - Destination path (prefix with `remote:` for remote files)

### ssh_scp

Copy files via SCP (works on most servers).

- `host` - SSH target in format `user@host` or `user@host:port`
- `source` - Source path (prefix with `remote:` for remote files)
- `dest` - Destination path (prefix with `remote:` for remote files)

**Examples:**
```
# Upload local file to remote
ssh_scp user@example.com /local/file.txt remote:/remote/file.txt

# Download remote file to local
ssh_scp user@example.com remote:/remote/file.txt /local/file.txt
```

## Authentication

Uses default SSH key from `~/.ssh/` (id_ed25519, id_rsa, or id_ecdsa).
