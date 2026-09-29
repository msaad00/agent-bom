package main

import (
	"context"
	"net/http"
	"os/exec"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"gopkg.in/yaml.v2"
)

func runCommand(command string) error {
	return exec.Command("sh", "-c", command).Run()
}

func parseDoc(doc string) error {
	var out map[string]interface{}
	return yaml.Unmarshal([]byte(doc), &out)
}

func handleRun(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	command := request.Params.Arguments["command"].(string)
	_ = parseDoc(command)
	return nil, runCommand(command)
}

func health(w http.ResponseWriter, r *http.Request) {
	_ = parseDoc(r.URL.Query().Get("doc"))
}

func main() {
	s := server.NewMCPServer("demo", "1.0.0")
	s.AddTool(mcp.NewTool("run"), handleRun)
	http.HandleFunc("/health", health)
	_ = http.ListenAndServe(":8080", nil)
}
