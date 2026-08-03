"""Non-Python analyzers must find real MCP tools and only real MCP tools.

The Python analyzer had two defects: an over-broad decorator match that claimed
ordinary web handlers, and an idiom the official SDK actually uses that resolved
to nothing. The regex-driven analyzers for the other languages carry the same
two classes, so every case below asserts in BOTH directions -- the current
official SDK idiom is detected, and ordinary same-shaped code is not.

Every "real idiom" sample here is copied from the official SDK's own README or
examples directory, not reconstructed from memory.
"""

from __future__ import annotations

from pathlib import Path

from agent_bom.ast_analyzer import analyze_project

# --------------------------------------------------------------------------
# Go -- github.com/modelcontextprotocol/go-sdk
# --------------------------------------------------------------------------

# internal/readme/server/server.go: the generic free function takes the server
# first and carries the name in a *mcp.Tool composite literal.
GO_OFFICIAL_GENERIC = """package main

import (
\t"context"
\t"log"

\t"github.com/modelcontextprotocol/go-sdk/mcp"
)

type Input struct {
\tName string `json:"name"`
}

func SayHi(ctx context.Context, req *mcp.CallToolRequest, input Input) (*mcp.CallToolResult, any, error) {
\treturn nil, nil, nil
}

func main() {
\tserver := mcp.NewServer(&mcp.Implementation{Name: "greeter", Version: "v1.0.0"}, nil)
\tmcp.AddTool(server, &mcp.Tool{Name: "greet", Description: "say hi"}, SayHi)
\tif err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
\t\tlog.Fatal(err)
\t}
}
"""

# mcp/server.go: func (s *Server) AddTool(t *Tool, h ToolHandler)
GO_OFFICIAL_METHOD = """package main

import "github.com/modelcontextprotocol/go-sdk/mcp"

func handleDelete() {}

func main() {
\tserver := mcp.NewServer(&mcp.Implementation{Name: "s"}, nil)
\tserver.AddTool(&mcp.Tool{Name: "delete_file"}, handleDelete)
}
"""

GO_COMMENTED_OUT = """package widget

import "fmt"

// Legacy registration looked like s.AddTool("legacy_thing", handler) before the
// rewrite; do not resurrect it.
func Describe() string {
\tusage := `run: server.NewTool("example_tool", opts)`
\treturn fmt.Sprint(usage)
}
"""

GO_ORDINARY_TOOL_METHOD = """package shop

type Inventory struct{ items []string }

func (i *Inventory) Tool(sku string) string {
\treturn sku
}

func Setup(i *Inventory) {
\t_ = i.Tool("hammer-42")
}
"""

# The mainstream community server library keeps the name in a nested NewTool.
GO_NESTED_NEW_TOOL = """package main

import (
\t"github.com/mark3labs/mcp-go/mcp"
\t"github.com/mark3labs/mcp-go/server"
)

func handleCalculate() {}

func main() {
\ts := server.NewMCPServer("calc", "1.0.0")
\ts.AddTool(mcp.NewTool("calculate", mcp.WithDescription("do math")), handleCalculate)
}
"""


def _tool_names(project: Path) -> set[str]:
    return {tool.name for tool in analyze_project(project).tools}


def test_go_official_sdk_generic_add_tool_is_detected(tmp_path: Path) -> None:
    (tmp_path / "main.go").write_text(GO_OFFICIAL_GENERIC)

    assert _tool_names(tmp_path) == {"greet"}


def test_go_official_sdk_server_add_tool_method_is_detected(tmp_path: Path) -> None:
    (tmp_path / "srv.go").write_text(GO_OFFICIAL_METHOD)

    assert _tool_names(tmp_path) == {"delete_file"}


def test_go_tool_registration_in_comment_or_raw_string_is_not_a_tool(tmp_path: Path) -> None:
    (tmp_path / "notes.go").write_text(GO_COMMENTED_OUT)

    assert _tool_names(tmp_path) == set()


def test_go_ordinary_method_named_tool_is_not_an_agent_tool(tmp_path: Path) -> None:
    (tmp_path / "shop.go").write_text(GO_ORDINARY_TOOL_METHOD)

    assert _tool_names(tmp_path) == set()


def test_go_nested_new_tool_registration_is_still_detected(tmp_path: Path) -> None:
    (tmp_path / "main.go").write_text(GO_NESTED_NEW_TOOL)

    assert _tool_names(tmp_path) == {"calculate"}


# --------------------------------------------------------------------------
# TypeScript / JavaScript -- @modelcontextprotocol/sdk
# --------------------------------------------------------------------------

# examples/tools/server.ts in the official SDK: registerTool is the current API.
TS_REGISTER_TOOL = """import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import * as z from 'zod';

const server = new McpServer({ name: 'tools-example', version: '1.0.0' });

server.registerTool(
    'calc',
    {
        title: 'Calculator',
        description: 'Apply an arithmetic operation to two numbers',
        inputSchema: z.object({ a: z.number(), b: z.number() })
    },
    async ({ a, b }) => ({ content: [{ type: 'text', text: String(a + b) }] })
);
"""

TS_LEGACY_TOOL = """import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

const server = new McpServer({ name: 'x', version: '1.0.0' });
server.tool('echo', { text: 'string' }, async ({ text }) => ({ content: [] }));
"""

JS_COMMENTED_OUT = """// Older releases exposed server.tool("legacy_echo", handler).
const usage = 'call server.tool("documented_example", cb)';
export function help() {
  return usage;
}
"""


def test_ts_official_sdk_register_tool_is_detected(tmp_path: Path) -> None:
    (tmp_path / "server.ts").write_text(TS_REGISTER_TOOL)

    assert _tool_names(tmp_path) == {"calc"}


def test_ts_legacy_server_tool_is_still_detected(tmp_path: Path) -> None:
    (tmp_path / "legacy.ts").write_text(TS_LEGACY_TOOL)

    assert _tool_names(tmp_path) == {"echo"}


TSX_APOSTROPHE_BEFORE_TOOL = """import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

export function Panel() {
  return <p>Here's the panel</p>;
}

const server = new McpServer({ name: 'x', version: '1.0.0' });
server.registerTool('run_query', { description: 'run it' }, async () => ({ content: [] }));
"""

JS_TEMPLATE_PROMPT = """const systemPrompt = `You are an agent.
Call server.tool("pretend_tool", cb) when you need data.`;
export default systemPrompt;
"""


def test_js_tool_registration_in_comment_or_string_is_not_a_tool(tmp_path: Path) -> None:
    (tmp_path / "docs.js").write_text(JS_COMMENTED_OUT)

    assert _tool_names(tmp_path) == set()


def test_js_tool_registration_inside_a_prompt_template_is_not_a_tool(tmp_path: Path) -> None:
    (tmp_path / "prompt.js").write_text(JS_TEMPLATE_PROMPT)

    assert _tool_names(tmp_path) == set()


def test_tsx_apostrophe_in_markup_does_not_hide_a_later_tool(tmp_path: Path) -> None:
    """An apostrophe in JSX text is not a string literal and must not mask code."""
    (tmp_path / "panel.tsx").write_text(TSX_APOSTROPHE_BEFORE_TOOL)

    assert _tool_names(tmp_path) == {"run_query"}


# --------------------------------------------------------------------------
# C# -- ModelContextProtocol (official csharp-sdk)
# --------------------------------------------------------------------------

# samples/AspNetCoreMcpServer/Tools/EchoTool.cs uses the combined attribute list.
CSHARP_COMBINED_ATTRIBUTE = """using ModelContextProtocol.Server;
using System.ComponentModel;

namespace AspNetCoreMcpServer.Tools;

[McpServerToolType]
public sealed class EchoTool
{
    [McpServerTool, Description("Echoes the input back to the client.")]
    public static string Echo(string message)
    {
        return "hello " + message;
    }
}
"""

CSHARP_SINGLE_ATTRIBUTE = """using ModelContextProtocol.Server;

[McpServerToolType]
public sealed class WeatherTools
{
    [McpServerTool(Name = "weather_ui")]
    public static string WeatherUi()
    {
        return "Showing weather forecast UI.";
    }
}
"""


def test_csharp_combined_attribute_list_tool_is_detected(tmp_path: Path) -> None:
    (tmp_path / "EchoTool.cs").write_text(CSHARP_COMBINED_ATTRIBUTE)

    assert _tool_names(tmp_path) == {"Echo"}


def test_csharp_standalone_attribute_tool_is_still_detected(tmp_path: Path) -> None:
    """``Name =`` renames the wire-level tool, so that is the name to report."""
    (tmp_path / "WeatherTools.cs").write_text(CSHARP_SINGLE_ATTRIBUTE)

    assert _tool_names(tmp_path) == {"weather_ui"}


def test_csharp_commented_out_attribute_is_not_a_tool(tmp_path: Path) -> None:
    (tmp_path / "Doc.cs").write_text(
        "using ModelContextProtocol.Server;\n\npublic sealed class Doc\n{\n"
        '    // [McpServerTool, Description("retired")]\n'
        "    public static string Retired(string message)\n    {\n        return message;\n    }\n}\n"
    )

    assert _tool_names(tmp_path) == set()


def test_csharp_tool_type_marker_alone_is_not_a_tool(tmp_path: Path) -> None:
    """``[McpServerToolType]`` marks the container class, not a tool method."""
    (tmp_path / "Marker.cs").write_text(
        "using ModelContextProtocol.Server;\n\n[McpServerToolType]\npublic sealed class Holder\n{\n"
        "    public static string Helper(string message)\n    {\n        return message;\n    }\n}\n"
    )

    assert _tool_names(tmp_path) == set()


# --------------------------------------------------------------------------
# Java -- io.modelcontextprotocol (official java-sdk)
# --------------------------------------------------------------------------

# docs/server.md: the tool name lives in Tool.builder(name, schema).
JAVA_TOOL_BUILDER = """import io.modelcontextprotocol.server.McpServer;
import io.modelcontextprotocol.server.McpServerFeatures.SyncToolSpecification;
import io.modelcontextprotocol.spec.McpSchema.Tool;

public class CalculatorServer {

    public void register(McpSyncServer syncServer) {
        var syncToolSpecification = SyncToolSpecification.builder()
                .tool(Tool.builder("calculator", schema).description("Basic calculator").build())
                .callHandler((exchange, request) -> null)
                .build();
        syncServer.addTool(syncToolSpecification);
    }
}
"""

JAVA_ORDINARY_BUILDER = """public class ReportBuilder {

    public void render() {
        var report = Report.builder("quarterly", schema).title("Quarterly").build();
        registry.addReport(report);
    }
}
"""


def test_java_official_tool_builder_is_detected(tmp_path: Path) -> None:
    (tmp_path / "CalculatorServer.java").write_text(JAVA_TOOL_BUILDER)

    assert _tool_names(tmp_path) == {"calculator"}


def test_java_ordinary_builder_is_not_an_agent_tool(tmp_path: Path) -> None:
    (tmp_path / "ReportBuilder.java").write_text(JAVA_ORDINARY_BUILDER)

    assert _tool_names(tmp_path) == set()


def test_java_commented_out_tool_builder_is_not_a_tool(tmp_path: Path) -> None:
    (tmp_path / "Doc.java").write_text(
        'public class Doc {\n    // Tool.builder("retired_tool", schema).build();\n    public void nothing() {}\n}\n'
    )

    assert _tool_names(tmp_path) == set()


# --------------------------------------------------------------------------
# PHP -- mcp/sdk (official php-sdk, Symfony + PHP Foundation)
# --------------------------------------------------------------------------

# examples/server/oauth-keycloak/McpElements.php uses the #[McpTool] attribute.
PHP_MCP_TOOL_ATTRIBUTE = """<?php

namespace Mcp\\Example\\Server;

use Mcp\\Capability\\Attribute\\McpTool;

final class McpElements
{
    #[McpTool(
        name: 'get_auth_status',
        description: 'Confirm authentication status'
    )]
    public function getAuthStatus(): array
    {
        return ['authenticated' => true];
    }
}
"""

PHP_ORDINARY_ATTRIBUTE = """<?php

namespace App\\Console;

use Symfony\\Component\\Console\\Attribute\\AsCommand;

#[AsCommand(name: 'app:sync', description: 'Sync things')]
final class SyncCommand
{
    public function execute(): int
    {
        return 0;
    }
}
"""


def test_php_official_mcp_tool_attribute_is_detected(tmp_path: Path) -> None:
    (tmp_path / "McpElements.php").write_text(PHP_MCP_TOOL_ATTRIBUTE)

    assert _tool_names(tmp_path) == {"get_auth_status"}


def test_php_ordinary_attribute_is_not_an_agent_tool(tmp_path: Path) -> None:
    (tmp_path / "SyncCommand.php").write_text(PHP_ORDINARY_ATTRIBUTE)

    assert _tool_names(tmp_path) == set()


def test_php_commented_out_mcp_tool_attribute_is_not_a_tool(tmp_path: Path) -> None:
    (tmp_path / "Tools.php").write_text(
        "<?php\n\nclass Tools\n{\n    // #[McpTool(name: 'retired')]\n"
        "    public function retired(): array\n    {\n        return [];\n    }\n}\n"
    )

    assert _tool_names(tmp_path) == set()


# --------------------------------------------------------------------------
# Ruby -- the mcp gem (official ruby-sdk)
# --------------------------------------------------------------------------

# README.md: define_tool takes the name as a keyword and the body as a block.
RUBY_DEFINE_TOOL = """require "mcp"

server = MCP::Server.new(name: "weather_server")

server.define_tool(
  name: "get_weather",
  description: "Get the weather for a city"
) do |server_context:|
  MCP::Tool::Response.new([{ type: "text", text: "Sunny, 22 degrees Celsius" }])
end
"""

RUBY_COMMENTED_OUT = """require "mcp"

server = MCP::Server.new(name: "weather_server")
# server.define_tool(name: "retired_tool") do |server_context:|
#   nothing
# end
"""

RUBY_ORDINARY_KEYWORD_HASH = """config = { name: "not_a_tool", description: "just configuration" }
puts config[:name]
"""


def test_ruby_official_define_tool_is_detected(tmp_path: Path) -> None:
    (tmp_path / "server.rb").write_text(RUBY_DEFINE_TOOL)

    assert _tool_names(tmp_path) == {"get_weather"}


def test_ruby_commented_out_define_tool_is_not_a_tool(tmp_path: Path) -> None:
    (tmp_path / "server.rb").write_text(RUBY_COMMENTED_OUT)

    assert _tool_names(tmp_path) == set()


def test_ruby_ordinary_keyword_hash_is_not_a_tool(tmp_path: Path) -> None:
    (tmp_path / "config.rb").write_text(RUBY_ORDINARY_KEYWORD_HASH)

    assert _tool_names(tmp_path) == set()


# --------------------------------------------------------------------------
# Swift -- the MCP module (official swift-sdk)
# --------------------------------------------------------------------------

# README.md: tools are Tool values returned from the ListTools handler.
SWIFT_LIST_TOOLS = """import MCP

let server = Server(name: "MyServer", version: "1.0.0")

await server.withMethodHandler(ListTools.self) { _ in
    return .init(tools: [
        Tool(name: "example", description: "An example tool")
    ])
}
"""

SWIFT_ORDINARY_TOOL_TYPE = """import Foundation

struct Tool {
    let name: String
    let description: String
}

let hammer = Tool(name: "hammer", description: "a claw hammer")
"""


def test_swift_official_tool_value_is_detected(tmp_path: Path) -> None:
    (tmp_path / "Server.swift").write_text(SWIFT_LIST_TOOLS)

    assert _tool_names(tmp_path) == {"example"}


def test_swift_ordinary_tool_type_without_mcp_is_not_an_agent_tool(tmp_path: Path) -> None:
    (tmp_path / "Hardware.swift").write_text(SWIFT_ORDINARY_TOOL_TYPE)

    assert _tool_names(tmp_path) == set()
