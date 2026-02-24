"""Tests for tool permission classification and PermissionProfile building."""


from agent_bom.models import PermissionProfile
from agent_bom.permissions import (
    _infer_category,
    build_permission_profile,
    build_tool_permissions,
    classify_risk_level,
    classify_tool,
    command_is_shell,
    command_runs_as_root,
)

# ─── classify_tool ───────────────────────────────────────────────────────────


class TestClassifyTool:
    def test_destructive_by_name(self):
        assert classify_tool("delete_file") == "destructive"
        assert classify_tool("remove_user") == "destructive"
        assert classify_tool("drop_table") == "destructive"
        assert classify_tool("purge_cache") == "destructive"

    def test_destructive_by_description(self):
        assert classify_tool("cleanup", "destroy all temp files") == "destructive"

    def test_execute_by_name(self):
        assert classify_tool("exec_command") == "execute"
        assert classify_tool("run_script") == "execute"
        assert classify_tool("shell_exec") == "execute"
        assert classify_tool("eval_code") == "execute"

    def test_write_by_name(self):
        assert classify_tool("create_file") == "write"
        assert classify_tool("update_record") == "write"
        assert classify_tool("upload_data") == "write"
        assert classify_tool("push_commit") == "write"
        assert classify_tool("deploy_app") == "write"

    def test_read_by_default(self):
        assert classify_tool("get_status") == "read"
        assert classify_tool("list_files") == "read"
        assert classify_tool("search_logs") == "read"
        assert classify_tool("fetch_data") == "read"

    def test_unknown_defaults_to_read(self):
        assert classify_tool("foobar") == "read"
        assert classify_tool("xyz_unknown_tool") == "read"

    def test_destructive_takes_precedence_over_write(self):
        # "remove" is destructive even though combined text might match write
        assert classify_tool("remove_and_create") == "destructive"

    def test_execute_takes_precedence_over_write(self):
        assert classify_tool("run_deploy") == "execute"

    def test_description_contributes(self):
        assert classify_tool("process", "execute a shell command") == "execute"
        assert classify_tool("manage", "create new resources") == "write"


# ─── classify_risk_level ─────────────────────────────────────────────────────


class TestClassifyRiskLevel:
    def test_high_dangerous_with_creds(self):
        assert classify_risk_level(["delete_record"], ["API_KEY"]) == "high"
        assert classify_risk_level(["exec_command"], ["TOKEN"]) == "high"

    def test_high_write_with_creds(self):
        assert classify_risk_level(["create_file", "upload"], ["SECRET"]) == "high"

    def test_medium_write_no_creds(self):
        assert classify_risk_level(["create_file", "update_record"], []) == "medium"

    def test_medium_creds_only(self):
        assert classify_risk_level(["list_items"], ["API_KEY"]) == "medium"

    def test_medium_dangerous_no_creds(self):
        assert classify_risk_level(["delete_file"], []) == "medium"

    def test_low_read_only_no_creds(self):
        assert classify_risk_level(["get_status", "list_files"], []) == "low"

    def test_low_empty(self):
        assert classify_risk_level([], []) == "low"


# ─── build_tool_permissions ──────────────────────────────────────────────────


class TestBuildToolPermissions:
    def test_string_tools(self):
        result = build_tool_permissions(["read_file", "delete_record", "exec_cmd"])
        assert result["read_file"] == "read"
        assert result["delete_record"] == "destructive"
        assert result["exec_cmd"] == "execute"

    def test_empty_list(self):
        assert build_tool_permissions([]) == {}

    def test_object_tools(self):
        class FakeTool:
            def __init__(self, name, description=""):
                self.name = name
                self.description = description

        tools = [FakeTool("create_item"), FakeTool("get_info")]
        result = build_tool_permissions(tools)
        assert result["create_item"] == "write"
        assert result["get_info"] == "read"


# ─── build_permission_profile ────────────────────────────────────────────────


class TestBuildPermissionProfile:
    def test_read_only_tools(self):
        profile = build_permission_profile(tools=["get_data", "list_items"])
        assert isinstance(profile, PermissionProfile)
        assert not profile.filesystem_write
        assert not profile.shell_access
        assert not profile.runs_as_root
        assert profile.privilege_level == "low"

    def test_write_tools_sets_filesystem_write(self):
        profile = build_permission_profile(tools=["create_file", "get_data"])
        assert profile.filesystem_write
        assert profile.privilege_level == "medium"

    def test_exec_tools_sets_shell_access(self):
        profile = build_permission_profile(tools=["exec_command"])
        assert profile.shell_access
        assert profile.privilege_level == "high"

    def test_sudo_command_sets_root(self):
        profile = build_permission_profile(
            tools=["get_data"], command="sudo", args=["node", "server.js"],
        )
        assert profile.runs_as_root
        assert profile.privilege_level == "high"

    def test_shell_command_sets_shell_access(self):
        profile = build_permission_profile(
            tools=[], command="bash", args=["-c", "echo hello"],
        )
        assert profile.shell_access
        assert profile.privilege_level == "high"

    def test_credentials_set_network_access(self):
        profile = build_permission_profile(
            tools=["get_data"], credential_env_vars=["API_KEY"],
        )
        assert profile.network_access
        assert profile.privilege_level == "medium"

    def test_no_args_defaults(self):
        profile = build_permission_profile()
        assert not profile.runs_as_root
        assert not profile.shell_access
        assert not profile.filesystem_write
        assert not profile.network_access


# ─── command_runs_as_root ────────────────────────────────────────────────────


class TestCommandRunsAsRoot:
    def test_sudo_command(self):
        assert command_runs_as_root("sudo", ["node", "server.js"])

    def test_sudo_in_args(self):
        assert command_runs_as_root("node", ["sudo", "server.js"])

    def test_normal_command(self):
        assert not command_runs_as_root("node", ["server.js"])
        assert not command_runs_as_root("npx", ["-y", "@some/package"])

    def test_empty(self):
        assert not command_runs_as_root("", [])


# ─── command_is_shell ────────────────────────────────────────────────────────


class TestCommandIsShell:
    def test_bash(self):
        assert command_is_shell("bash", ["-c", "echo hi"])

    def test_sh(self):
        assert command_is_shell("sh", [])

    def test_zsh(self):
        assert command_is_shell("zsh", [])

    def test_powershell(self):
        assert command_is_shell("powershell", ["-Command", "Get-Process"])

    def test_full_path(self):
        assert command_is_shell("/bin/bash", ["-c", "ls"])
        assert command_is_shell("/usr/bin/zsh", [])

    def test_shell_in_args(self):
        assert command_is_shell("env", ["bash", "-c", "echo hi"])

    def test_not_shell(self):
        assert not command_is_shell("node", ["server.js"])
        assert not command_is_shell("npx", ["-y", "something"])
        assert not command_is_shell("python", ["-m", "mcp_server"])


# ─── _infer_category ─────────────────────────────────────────────────────────


class TestInferCategory:
    def test_filesystem(self):
        assert _infer_category("local-fs", "filesystem access") == "filesystem"

    def test_database(self):
        assert _infer_category("postgres-mcp", "PostgreSQL server") == "database"
        assert _infer_category("redis-tools", "Redis cache") == "database"

    def test_developer_tools(self):
        assert _infer_category("github-mcp", "GitHub integration") == "developer-tools"

    def test_cloud(self):
        assert _infer_category("aws-mcp", "AWS services") == "cloud"

    def test_ai_ml(self):
        assert _infer_category("openai-tools", "LLM integration") == "ai-ml"

    def test_communication(self):
        assert _infer_category("slack-mcp", "Slack messaging") == "communication"

    def test_web(self):
        assert _infer_category("browser-tools", "web scraping") == "web"

    def test_security(self):
        assert _infer_category("vault-mcp", "secret management") == "security"

    def test_monitoring(self):
        assert _infer_category("datadog-mcp", "monitoring metrics") == "monitoring"

    def test_general_fallback(self):
        assert _infer_category("xyz-unknown", "something random") == "general"
