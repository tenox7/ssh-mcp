package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type Response struct {
	JSONRPC string `json:"jsonrpc"`
	ID      any    `json:"id,omitempty"`
	Result  any    `json:"result,omitempty"`
	Error   *Error `json:"error,omitempty"`
}

type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type InitializeResult struct {
	ProtocolVersion string       `json:"protocolVersion"`
	Capabilities    Capabilities `json:"capabilities"`
	ServerInfo      ServerInfo   `json:"serverInfo"`
}

type Capabilities struct {
	Tools *ToolsCapability `json:"tools,omitempty"`
}

type ToolsCapability struct{}

type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Tool struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema InputSchema `json:"inputSchema"`
}

type InputSchema struct {
	Type       string              `json:"type"`
	Properties map[string]Property `json:"properties"`
	Required   []string            `json:"required"`
}

type Property struct {
	Type        string `json:"type"`
	Description string `json:"description"`
}

type ToolsListResult struct {
	Tools []Tool `json:"tools"`
}

type CallToolParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

type CallToolResult struct {
	Content []Content `json:"content"`
	IsError bool      `json:"isError,omitempty"`
}

type Content struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var req Request
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			continue
		}

		resp := handleRequest(&req)
		if resp == nil {
			continue
		}

		out, _ := json.Marshal(resp)
		fmt.Println(string(out))
	}
}

func handleRequest(req *Request) *Response {
	switch req.Method {
	case "initialize":
		return &Response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: InitializeResult{
				ProtocolVersion: "2024-11-05",
				Capabilities:    Capabilities{Tools: &ToolsCapability{}},
				ServerInfo:      ServerInfo{Name: "ssh-mcp", Version: "1.0.0"},
			},
		}

	case "notifications/initialized":
		return nil

	case "tools/list":
		return &Response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: ToolsListResult{
				Tools: []Tool{
					{
						Name:        "ssh_exec",
						Description: "Execute a command on a remote host via SSH",
						InputSchema: InputSchema{
							Type: "object",
							Properties: map[string]Property{
								"host":    {Type: "string", Description: "SSH target in format user@host or user@host:port"},
								"command": {Type: "string", Description: "Command to execute"},
							},
							Required: []string{"host", "command"},
						},
					},
					{
						Name:        "ssh_copy",
						Description: "Copy files to/from a remote host via SFTP",
						InputSchema: InputSchema{
							Type: "object",
							Properties: map[string]Property{
								"host":      {Type: "string", Description: "SSH target in format user@host or user@host:port"},
								"source":    {Type: "string", Description: "Source path (prefix with 'remote:' for remote files)"},
								"dest":      {Type: "string", Description: "Destination path (prefix with 'remote:' for remote files)"},
							},
							Required: []string{"host", "source", "dest"},
						},
					},
				},
			},
		}

	case "tools/call":
		var params CallToolParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return errorResponse(req.ID, -32602, "Invalid params")
		}
		return handleToolCall(req.ID, &params)

	default:
		return errorResponse(req.ID, -32601, "Method not found")
	}
}

func handleToolCall(id any, params *CallToolParams) *Response {
	switch params.Name {
	case "ssh_exec":
		return handleExec(id, params)
	case "ssh_copy":
		return handleCopy(id, params)
	default:
		return toolError(id, "Unknown tool")
	}
}

func handleExec(id any, params *CallToolParams) *Response {
	host, _ := params.Arguments["host"].(string)
	command, _ := params.Arguments["command"].(string)

	if host == "" || command == "" {
		return toolError(id, "Missing host or command")
	}

	output, err := executeSSH(host, command)
	if err != nil {
		return toolError(id, err.Error())
	}

	return toolSuccess(id, output)
}

func handleCopy(id any, params *CallToolParams) *Response {
	host, _ := params.Arguments["host"].(string)
	source, _ := params.Arguments["source"].(string)
	dest, _ := params.Arguments["dest"].(string)

	if host == "" || source == "" || dest == "" {
		return toolError(id, "Missing host, source, or dest")
	}

	result, err := executeSFTP(host, source, dest)
	if err != nil {
		return toolError(id, err.Error())
	}

	return toolSuccess(id, result)
}

func toolError(id any, msg string) *Response {
	return &Response{
		JSONRPC: "2.0",
		ID:      id,
		Result:  CallToolResult{Content: []Content{{Type: "text", Text: msg}}, IsError: true},
	}
}

func toolSuccess(id any, msg string) *Response {
	return &Response{
		JSONRPC: "2.0",
		ID:      id,
		Result:  CallToolResult{Content: []Content{{Type: "text", Text: msg}}},
	}
}

func executeSSH(host, command string) (string, error) {
	user, addr := parseHost(host)

	key, err := loadDefaultKey()
	if err != nil {
		return "", fmt.Errorf("failed to load SSH key: %w", err)
	}

	config := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(key)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return "", fmt.Errorf("failed to connect: %w", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	output, err := session.CombinedOutput(command)
	if err != nil {
		return string(output), fmt.Errorf("command failed: %w\n%s", err, output)
	}

	return string(output), nil
}

func executeSFTP(host, source, dest string) (string, error) {
	user, addr := parseHost(host)

	key, err := loadDefaultKey()
	if err != nil {
		return "", fmt.Errorf("failed to load SSH key: %w", err)
	}

	config := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(key)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return "", fmt.Errorf("failed to connect: %w", err)
	}
	defer client.Close()

	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		return "", fmt.Errorf("failed to create SFTP client: %w", err)
	}
	defer sftpClient.Close()

	srcRemote := strings.HasPrefix(source, "remote:")
	dstRemote := strings.HasPrefix(dest, "remote:")
	source = strings.TrimPrefix(source, "remote:")
	dest = strings.TrimPrefix(dest, "remote:")

	if srcRemote && dstRemote {
		return "", fmt.Errorf("both source and dest cannot be remote")
	}
	if !srcRemote && !dstRemote {
		return "", fmt.Errorf("either source or dest must be remote")
	}

	if srcRemote {
		return downloadFile(sftpClient, source, dest)
	}
	return uploadFile(sftpClient, source, dest)
}

func uploadFile(sftpClient *sftp.Client, local, remote string) (string, error) {
	src, err := os.Open(local)
	if err != nil {
		return "", fmt.Errorf("failed to open local file: %w", err)
	}
	defer src.Close()

	dst, err := sftpClient.Create(remote)
	if err != nil {
		return "", fmt.Errorf("failed to create remote file: %w", err)
	}
	defer dst.Close()

	n, err := io.Copy(dst, src)
	if err != nil {
		return "", fmt.Errorf("failed to copy: %w", err)
	}

	return fmt.Sprintf("Uploaded %d bytes to %s", n, remote), nil
}

func downloadFile(sftpClient *sftp.Client, remote, local string) (string, error) {
	src, err := sftpClient.Open(remote)
	if err != nil {
		return "", fmt.Errorf("failed to open remote file: %w", err)
	}
	defer src.Close()

	dst, err := os.Create(local)
	if err != nil {
		return "", fmt.Errorf("failed to create local file: %w", err)
	}
	defer dst.Close()

	n, err := io.Copy(dst, src)
	if err != nil {
		return "", fmt.Errorf("failed to copy: %w", err)
	}

	return fmt.Sprintf("Downloaded %d bytes to %s", n, local), nil
}

func parseHost(host string) (user, addr string) {
	user = os.Getenv("USER")
	addr = host

	if at := strings.Index(host, "@"); at != -1 {
		user = host[:at]
		addr = host[at+1:]
	}

	if !strings.Contains(addr, ":") {
		addr = addr + ":22"
	}

	return user, addr
}

func loadDefaultKey() (ssh.Signer, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	keyFiles := []string{
		filepath.Join(home, ".ssh", "id_ed25519"),
		filepath.Join(home, ".ssh", "id_rsa"),
		filepath.Join(home, ".ssh", "id_ecdsa"),
	}

	for _, keyFile := range keyFiles {
		data, err := os.ReadFile(keyFile)
		if err != nil {
			continue
		}

		signer, err := ssh.ParsePrivateKey(data)
		if err != nil {
			continue
		}

		return signer, nil
	}

	return nil, fmt.Errorf("no SSH key found in ~/.ssh/")
}

func errorResponse(id any, code int, message string) *Response {
	return &Response{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &Error{Code: code, Message: message},
	}
}
