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

# README.md "Tools", form 1: a subclass of MCP::Tool. With no `tool_name`, the
# gem derives the name from the class name -- lib/mcp/tool.rb `name_value` falls
# back to StringUtils.handle_from_class_name, which underscores and downcases it.
RUBY_TOOL_SUBCLASS = """class MyTool < MCP::Tool
  title "My Tool"
  description "This tool performs specific functionality..."
  input_schema(
    properties: {
      message: { type: "string" },
    },
    required: ["message"]
  )

  def self.call(message:, server_context:)
    MCP::Tool::Response.new([{ type: "text", text: "OK" }])
  end
end
"""

# README.md "Tool Output Schemas": `tool_name` overrides the derived name.
RUBY_TOOL_SUBCLASS_EXPLICIT_NAME = """class WeatherTool < MCP::Tool
  tool_name "get_weather"
  description "Get current weather for a location"

  def self.call(location:, server_context:)
    MCP::Tool::Response.new([{ type: "text", text: "Sunny" }])
  end
end
"""

# README.md "Tools", form 2: MCP::Tool.define with the name as a keyword.
RUBY_TOOL_DEFINE = """require "mcp"

tool = MCP::Tool.define(
  name: "my_tool",
  title: "My Tool",
  description: "This tool performs specific functionality...",
  annotations: {
    read_only_hint: true,
    title: "My Tool"
  }
) do |args, server_context:|
  MCP::Tool::Response.new([{ type: "text", text: "OK" }])
end
"""

# Two tool classes in one file, only the second renamed. A `tool_name` must not
# leak across the class boundary in either direction.
RUBY_TWO_TOOL_SUBCLASSES = """class SearchTool < MCP::Tool
  description "Search the corpus"
end

class LookupTool < MCP::Tool
  tool_name "lookup_user"
  description "Look a user up"
end
"""

# An ActiveRecord model in a workshop app. The class name ends in Tool and it
# even carries a `tool_name`, but nothing here is MCP.
RUBY_ORDINARY_TOOL_CLASS = """class HammerTool < ActiveRecord::Base
  belongs_to :workbench

  def tool_name
    "hammer-42"
  end
end
"""

RUBY_TOOL_DEFINE_COMMENTED_OUT = """require "mcp"

# MCP::Tool.define(name: "retired_tool") do |args, server_context:|
#   nothing
# end
"""

# Inside `module MCP` the superclass is written bare. `Tool` on its own is too
# ordinary a name to trust, so it needs the file to require the gem.
RUBY_BARE_TOOL_SUPERCLASS = """class SummarizeTool < Tool
  description "Summarize a document"
end
"""


def test_ruby_official_define_tool_is_detected(tmp_path: Path) -> None:
    (tmp_path / "server.rb").write_text(RUBY_DEFINE_TOOL)

    assert _tool_names(tmp_path) == {"get_weather"}


def test_ruby_official_tool_subclass_is_detected(tmp_path: Path) -> None:
    (tmp_path / "my_tool.rb").write_text(RUBY_TOOL_SUBCLASS)

    assert _tool_names(tmp_path) == {"my_tool"}


def test_ruby_tool_subclass_explicit_tool_name_wins(tmp_path: Path) -> None:
    (tmp_path / "weather_tool.rb").write_text(RUBY_TOOL_SUBCLASS_EXPLICIT_NAME)

    assert _tool_names(tmp_path) == {"get_weather"}


def test_ruby_tool_name_does_not_leak_between_sibling_classes(tmp_path: Path) -> None:
    (tmp_path / "tools.rb").write_text(RUBY_TWO_TOOL_SUBCLASSES)

    assert _tool_names(tmp_path) == {"search_tool", "lookup_user"}


def test_ruby_official_tool_define_is_detected(tmp_path: Path) -> None:
    (tmp_path / "my_tool.rb").write_text(RUBY_TOOL_DEFINE)

    assert _tool_names(tmp_path) == {"my_tool"}


def test_ruby_ordinary_class_named_tool_is_not_an_agent_tool(tmp_path: Path) -> None:
    (tmp_path / "hammer_tool.rb").write_text(RUBY_ORDINARY_TOOL_CLASS)

    assert _tool_names(tmp_path) == set()


def test_ruby_commented_out_tool_define_is_not_a_tool(tmp_path: Path) -> None:
    (tmp_path / "retired.rb").write_text(RUBY_TOOL_DEFINE_COMMENTED_OUT)

    assert _tool_names(tmp_path) == set()


def test_ruby_bare_tool_superclass_needs_the_gem_required(tmp_path: Path) -> None:
    (tmp_path / "summarize_tool.rb").write_text(RUBY_BARE_TOOL_SUPERCLASS)

    assert _tool_names(tmp_path) == set()


def test_ruby_bare_tool_superclass_is_detected_when_the_gem_is_required(tmp_path: Path) -> None:
    (tmp_path / "summarize_tool.rb").write_text('require "mcp"\n\n' + RUBY_BARE_TOOL_SUPERCLASS)

    assert _tool_names(tmp_path) == {"summarize_tool"}


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


# --------------------------------------------------------------------------
# Kotlin -- io.modelcontextprotocol:kotlin-sdk (official kotlin-sdk)
# --------------------------------------------------------------------------

# README.md "Creating a Server": addTool carries the name as a named argument.
KOTLIN_ADD_TOOL = """import io.ktor.server.cio.CIO
import io.ktor.server.engine.embeddedServer
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.server.mcpStreamableHttp
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.ServerCapabilities
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

fun main(args: Array<String>) {
    val port = args.firstOrNull()?.toIntOrNull() ?: 3000
    val mcpServer = Server(
        serverInfo = Implementation(
            name = "example-server",
            version = "1.0.0"
        ),
        options = ServerOptions(
            capabilities = ServerCapabilities(
                tools = ServerCapabilities.Tools(listChanged = true),
            ),
        )
    )

    mcpServer.addTool(
        name = "example-tool",
        description = "An example tool",
        inputSchema = ToolSchema(
            properties = buildJsonObject {
                put("input", buildJsonObject { put("type", "string") })
            }
        )
    ) { request ->
        CallToolResult(content = listOf(TextContent("Hello, world!")))
    }

    embeddedServer(CIO, host = "127.0.0.1", port = port) {
        mcpStreamableHttp {
            mcpServer
        }
    }.start(wait = true)
}
"""

# README.md "Tools": the short form, with the handler as a trailing lambda.
KOTLIN_ADD_TOOL_SHORT = """import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.TextContent

val server = Server(
    serverInfo = Implementation(
        name = "example-server",
        version = "1.0.0"
    )
)

server.addTool(
    name = "echo",
    description = "Return whatever the user sent back to them",
) { request ->
    val text = request.arguments?.get("text")?.jsonPrimitive?.content ?: "(empty)"
    CallToolResult(content = listOf(TextContent(text = "Echo: $text")))
}
"""

# README.md "Prompts"/"Resources": neither registers a tool.
KOTLIN_PROMPT_AND_RESOURCE = """import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.Implementation

val server = Server(serverInfo = Implementation(name = "example-server", version = "1.0.0"))

server.addPrompt(
    name = "code-review",
    description = "Ask the model to review a diff",
) { request -> null }

server.addResource(
    uri = "note://release/latest",
    name = "Release notes",
    description = "Last deployment summary",
) { request -> null }
"""

KOTLIN_ORDINARY_ADD_TOOL = """package com.example.workshop

class Workbench {
    private val tools = mutableListOf<String>()

    fun addTool(name: String, weightKg: Double) {
        tools.add(name)
    }
}

fun setUp(bench: Workbench) {
    bench.addTool(name = "wrench-7", weightKg = 0.4)
}
"""

# Server.kt `public fun addTools(toolsToAdd: List<RegisteredTool>)` -- the bulk
# registration. Sample copied from the SDK's own
# integration-test/.../server/ServerBulkFeaturesTest.kt, where the name is the
# leading positional argument of each Tool rather than a named one.
KOTLIN_ADD_TOOLS_BULK = """import io.modelcontextprotocol.kotlin.sdk.server.RegisteredTool
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.Tool
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema

fun register(server: Server) {
    server.addTools(
        listOf(
            RegisteredTool(Tool("bulk-a", ToolSchema(), "Tool A")) { CallToolResult(emptyList()) },
            RegisteredTool(Tool("bulk-b", ToolSchema(), "Tool B")) { CallToolResult(emptyList()) },
            RegisteredTool(Tool("bulk-c", ToolSchema(), "Tool C")) { CallToolResult(emptyList()) },
        ),
    )
}
"""

# The same call built from a variable. No name is knowable statically, and
# inventing one would be worse than reporting none.
KOTLIN_ADD_TOOLS_NON_LITERAL = """import io.modelcontextprotocol.kotlin.sdk.server.RegisteredTool
import io.modelcontextprotocol.kotlin.sdk.server.Server

fun register(server: Server, discovered: List<RegisteredTool>) {
    server.addTools(discovered)
}
"""

KOTLIN_ORDINARY_ADD_TOOLS = """package com.example.workshop

data class Tool(val name: String)

class Workbench {
    private val tools = mutableListOf<Tool>()

    fun addTools(toolsToAdd: List<Tool>) {
        tools.addAll(toolsToAdd)
    }
}

fun setUp(bench: Workbench) {
    bench.addTools(listOf(Tool("wrench-7"), Tool("hammer-42")))
}
"""

KOTLIN_COMMENTED_OUT = """import io.modelcontextprotocol.kotlin.sdk.server.Server

// Older builds registered server.addTool(name = "retired_tool") here.
val usage = "call server.addTool(name = \\"documented_example\\")"

/* server.addTool(name = "block_commented_tool") { request -> null } */
fun help(): String = usage
"""


def test_kotlin_official_sdk_add_tool_is_detected(tmp_path: Path) -> None:
    (tmp_path / "Main.kt").write_text(KOTLIN_ADD_TOOL)

    assert _tool_names(tmp_path) == {"example-tool"}


def test_kotlin_official_sdk_short_add_tool_is_detected(tmp_path: Path) -> None:
    (tmp_path / "Echo.kt").write_text(KOTLIN_ADD_TOOL_SHORT)

    assert _tool_names(tmp_path) == {"echo"}


def test_kotlin_prompt_and_resource_registrations_are_not_tools(tmp_path: Path) -> None:
    (tmp_path / "Extras.kt").write_text(KOTLIN_PROMPT_AND_RESOURCE)

    assert _tool_names(tmp_path) == set()


def test_kotlin_ordinary_add_tool_without_mcp_is_not_an_agent_tool(tmp_path: Path) -> None:
    (tmp_path / "Workbench.kt").write_text(KOTLIN_ORDINARY_ADD_TOOL)

    assert _tool_names(tmp_path) == set()


def test_kotlin_commented_out_add_tool_is_not_a_tool(tmp_path: Path) -> None:
    (tmp_path / "Docs.kt").write_text(KOTLIN_COMMENTED_OUT)

    assert _tool_names(tmp_path) == set()


def test_kotlin_official_sdk_add_tools_bulk_is_detected(tmp_path: Path) -> None:
    (tmp_path / "Bulk.kt").write_text(KOTLIN_ADD_TOOLS_BULK)

    assert _tool_names(tmp_path) == {"bulk-a", "bulk-b", "bulk-c"}


def test_kotlin_add_tools_from_a_variable_claims_no_name(tmp_path: Path) -> None:
    (tmp_path / "Dynamic.kt").write_text(KOTLIN_ADD_TOOLS_NON_LITERAL)

    assert _tool_names(tmp_path) == set()


def test_kotlin_ordinary_add_tools_without_mcp_is_not_an_agent_tool(tmp_path: Path) -> None:
    (tmp_path / "Workbench.kt").write_text(KOTLIN_ORDINARY_ADD_TOOLS)

    assert _tool_names(tmp_path) == set()


# --------------------------------------------------------------------------
# TypeScript -- the low-level Server class of @modelcontextprotocol/sdk
# --------------------------------------------------------------------------

# Servers built on `Server` rather than the `McpServer` wrapper declare their
# tools in the ListTools response instead of through registerTool.
TS_LOW_LEVEL_LIST_TOOLS = """import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema
} from '@modelcontextprotocol/sdk/types.js';

const server = new Server(
  { name: 'calculator', version: '1.0.0' },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: 'calculate_sum',
        description: 'Add two numbers together',
        inputSchema: {
          type: 'object',
          properties: { a: { type: 'number' }, b: { type: 'number' } },
          required: ['a', 'b']
        }
      },
      {
        name: 'calculate_product',
        description: 'Multiply two numbers together',
        inputSchema: { type: 'object', properties: {} }
      }
    ]
  };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  return { content: [{ type: 'text', text: 'ok' }] };
});
"""

# The v2 SDK migrates the schema identifier to the method string; the codemod's
# own test asserts `server.setRequestHandler('tools/list', …)` is the output.
TS_LOW_LEVEL_METHOD_STRING = """import { Server } from '@modelcontextprotocol/sdk/server/index.js';

const server = new Server({ name: 'calculator', version: '1.0.0' });

server.setRequestHandler('tools/list', async () => ({
  tools: [{ name: 'calculate_sum', description: 'Add two numbers together' }]
}));
"""

TS_LOW_LEVEL_LIST_RESOURCES = """import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { ListResourcesRequestSchema } from '@modelcontextprotocol/sdk/types.js';

const server = new Server({ name: 'notes', version: '1.0.0' });

server.setRequestHandler(ListResourcesRequestSchema, async () => ({
  resources: [{ uri: 'note://1', name: 'First note' }]
}));
"""

JS_ORDINARY_NAMED_OBJECTS = """const contributors = [
  { name: 'ada', role: 'maintainer' },
  { name: 'grace', role: 'reviewer' }
];

export function listContributors() {
  return { tools: contributors };
}
"""


def test_ts_low_level_list_tools_handler_is_detected(tmp_path: Path) -> None:
    (tmp_path / "server.ts").write_text(TS_LOW_LEVEL_LIST_TOOLS)

    assert _tool_names(tmp_path) == {"calculate_sum", "calculate_product"}


def test_ts_low_level_tools_list_method_string_is_detected(tmp_path: Path) -> None:
    (tmp_path / "server.ts").write_text(TS_LOW_LEVEL_METHOD_STRING)

    assert _tool_names(tmp_path) == {"calculate_sum"}


def test_ts_low_level_list_resources_handler_declares_no_tools(tmp_path: Path) -> None:
    (tmp_path / "resources.ts").write_text(TS_LOW_LEVEL_LIST_RESOURCES)

    assert _tool_names(tmp_path) == set()


def test_js_ordinary_named_objects_are_not_tools(tmp_path: Path) -> None:
    (tmp_path / "contributors.js").write_text(JS_ORDINARY_NAMED_OBJECTS)

    assert _tool_names(tmp_path) == set()


# --------------------------------------------------------------------------
# JS/TS agent frameworks that carry the tool name outside the first argument
# --------------------------------------------------------------------------

# ai-sdk.dev/docs/ai-sdk-core/tools-and-tool-calling: the tool NAME is the key
# of the `tools` object, not an argument of `tool()`.
TS_VERCEL_AI_OBJECT_KEY = """import { z } from 'zod';
import { generateText, tool, isStepCount } from 'ai';

const result = await generateText({
  model: 'xai/grok-4.5',
  tools: {
    weather: tool({
      description: 'Get the weather in a location',
      inputSchema: z.object({
        location: z.string().describe('The location to get the weather for'),
      }),
      execute: async ({ location }) => ({
        location,
        temperature: 72 + Math.floor(Math.random() * 21) - 10,
      }),
    }),
  },
  stopWhen: isStepCount(5),
  prompt: 'What is the weather in San Francisco?',
});
"""

# docs.langchain.com/oss/javascript/langchain/tools: the name lives in the
# options object that follows the handler function.
TS_LANGCHAIN_OPTIONS_NAME = """import * as z from 'zod';
import { tool } from 'langchain';

const searchDatabase = tool(
  ({ query, limit }) => `Found ${limit} results for '${query}'`,
  {
    name: 'search_database',
    description: 'Search the customer database for records matching the query.',
    schema: z.object({
      query: z.string().describe('Search terms to look for'),
      limit: z.number().describe('Maximum number of results to return'),
    }),
  }
);
"""

JS_ORDINARY_OBJECT_KEY_CALL = """import { buildHandler } from './handlers.js';

export const handlers = {
  weather: buildHandler({ description: 'Get the weather in a location' }),
};
"""


def test_ts_vercel_ai_object_key_tool_is_detected(tmp_path: Path) -> None:
    (tmp_path / "agent.ts").write_text(TS_VERCEL_AI_OBJECT_KEY)

    assert _tool_names(tmp_path) == {"weather"}


def test_ts_langchain_options_object_name_is_detected(tmp_path: Path) -> None:
    (tmp_path / "tools.ts").write_text(TS_LANGCHAIN_OPTIONS_NAME)

    assert _tool_names(tmp_path) == {"search_database"}


def test_js_ordinary_object_key_call_is_not_a_tool(tmp_path: Path) -> None:
    (tmp_path / "handlers.js").write_text(JS_ORDINARY_OBJECT_KEY_CALL)

    assert _tool_names(tmp_path) == set()


# --------------------------------------------------------------------------
# Residual precision gaps
# --------------------------------------------------------------------------

# ``NewTool`` is the name-bearing call of the mainstream community Go library,
# but ``NewX`` is also the ordinary Go constructor idiom. Without an MCP import
# in the file there is nothing agentic to claim.
GO_ORDINARY_NEW_TOOL = """package hardware

type toolFactory struct{}

func (f *toolFactory) NewTool(sku string) string {
\treturn sku
}

func Setup() string {
\tmcp := &toolFactory{}
\treturn mcp.NewTool("wrench-7")
}
"""

PHP_HASH_COMMENTED_ATTRIBUTE = """<?php

namespace Mcp\\Example\\Server;

use Mcp\\Capability\\Attribute\\McpTool;

final class McpElements
{
    # #[McpTool(name: 'retired_tool', description: 'Removed in v2')]
    public function retiredTool(): array
    {
        return [];
    }
}
"""

# A ``]`` inside the Description string must not truncate the attribute span.
CSHARP_BRACKET_IN_DESCRIPTION = """using ModelContextProtocol.Server;
using System.ComponentModel;

[McpServerToolType]
public sealed class EchoTool
{
    [McpServerTool, Description("Echoes the input back [verbatim] to the client.")]
    public static string Echo(string message)
    {
        return "hello " + message;
    }
}
"""

CSHARP_BRACKET_BEFORE_NAME = """using ModelContextProtocol.Server;
using System.ComponentModel;

[McpServerToolType]
public sealed class ItemTools
{
    [Description("Returns items] in order."), McpServerTool(Name = "list_items")]
    public static string ListItems()
    {
        return "ok";
    }
}
"""


def test_go_ordinary_new_tool_without_mcp_import_is_not_an_agent_tool(tmp_path: Path) -> None:
    (tmp_path / "hardware.go").write_text(GO_ORDINARY_NEW_TOOL)

    assert _tool_names(tmp_path) == set()


def test_php_hash_commented_out_mcp_tool_attribute_is_not_a_tool(tmp_path: Path) -> None:
    (tmp_path / "McpElements.php").write_text(PHP_HASH_COMMENTED_ATTRIBUTE)

    assert _tool_names(tmp_path) == set()


def test_csharp_bracket_inside_description_still_finds_the_tool(tmp_path: Path) -> None:
    (tmp_path / "EchoTool.cs").write_text(CSHARP_BRACKET_IN_DESCRIPTION)

    assert _tool_names(tmp_path) == {"Echo"}


def test_csharp_bracket_before_the_declared_name_still_finds_the_tool(tmp_path: Path) -> None:
    (tmp_path / "ItemTools.cs").write_text(CSHARP_BRACKET_BEFORE_NAME)

    assert _tool_names(tmp_path) == {"list_items"}
