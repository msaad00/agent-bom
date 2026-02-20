import * as vscode from "vscode";
import { execFile } from "child_process";
import { promisify } from "util";
import * as path from "path";
import * as fs from "fs";

const execFileAsync = promisify(execFile);

let diagnosticCollection: vscode.DiagnosticCollection;
let statusBarItem: vscode.StatusBarItem;
let lastSarifData: SarifLog | null = null;

// ── SARIF types ──────────────────────────────────────────────────────────────

interface SarifRule {
  id: string;
  shortDescription?: { text: string };
  helpUri?: string;
}

interface SarifResult {
  ruleId: string;
  level?: string;
  message: { text: string };
  locations?: Array<{
    physicalLocation?: {
      artifactLocation?: { uri: string };
    };
  }>;
}

interface SarifRun {
  tool: {
    driver: {
      name: string;
      version?: string;
      rules?: SarifRule[];
    };
  };
  results?: SarifResult[];
}

interface SarifLog {
  runs?: SarifRun[];
}

// ── Activation ───────────────────────────────────────────────────────────────

export function activate(context: vscode.ExtensionContext): void {
  diagnosticCollection =
    vscode.languages.createDiagnosticCollection("agent-bom");
  context.subscriptions.push(diagnosticCollection);

  statusBarItem = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Left,
    100
  );
  statusBarItem.command = "agent-bom.showResults";
  statusBarItem.text = "$(shield) agent-bom";
  statusBarItem.tooltip = "Click to show scan results";
  context.subscriptions.push(statusBarItem);

  context.subscriptions.push(
    vscode.commands.registerCommand("agent-bom.scanWorkspace", () =>
      scanWorkspace()
    ),
    vscode.commands.registerCommand("agent-bom.showResults", () =>
      showResults()
    )
  );
}

// ── Scan command ─────────────────────────────────────────────────────────────

async function scanWorkspace(): Promise<void> {
  const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
  if (!workspaceFolder) {
    vscode.window.showWarningMessage("agent-bom: No workspace folder open.");
    return;
  }

  const sarifPath = path.join(
    workspaceFolder.uri.fsPath,
    ".agent-bom-results.sarif"
  );

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: "agent-bom: Scanning workspace...",
      cancellable: false,
    },
    async () => {
      try {
        await execFileAsync("agent-bom", [
          "scan",
          "--project",
          workspaceFolder.uri.fsPath,
          "-f",
          "sarif",
          "-o",
          sarifPath,
        ]);
      } catch (error: unknown) {
        // Exit code 1 means vulns found — still parse SARIF
        const err = error as { code?: number; status?: number; message?: string };
        if (err.code !== 1 && err.status !== 1) {
          vscode.window.showErrorMessage(
            `agent-bom scan failed: ${err.message ?? String(error)}`
          );
          return;
        }
      }

      try {
        const sarifContent = fs.readFileSync(sarifPath, "utf-8");
        lastSarifData = JSON.parse(sarifContent) as SarifLog;
        populateDiagnostics(
          lastSarifData,
          workspaceFolder.uri.fsPath
        );
      } catch (parseError: unknown) {
        const err = parseError as { message?: string };
        vscode.window.showErrorMessage(
          `agent-bom: Failed to parse SARIF: ${err.message ?? String(parseError)}`
        );
      }
    }
  );
}

// ── Diagnostics from SARIF ───────────────────────────────────────────────────

function populateDiagnostics(sarif: SarifLog, workspacePath: string): void {
  diagnosticCollection.clear();

  const results = sarif?.runs?.[0]?.results ?? [];
  const rules = sarif?.runs?.[0]?.tool?.driver?.rules ?? [];
  const ruleMap = new Map<string, SarifRule>();
  for (const rule of rules) {
    ruleMap.set(rule.id, rule);
  }

  const diagsByFile = new Map<string, vscode.Diagnostic[]>();

  for (const result of results) {
    const ruleId = result.ruleId;
    const rule = ruleMap.get(ruleId);
    const message = result.message?.text ?? `Vulnerability: ${ruleId}`;
    const level = result.level ?? "warning";

    let severity: vscode.DiagnosticSeverity;
    switch (level) {
      case "error":
        severity = vscode.DiagnosticSeverity.Error;
        break;
      case "warning":
        severity = vscode.DiagnosticSeverity.Warning;
        break;
      case "note":
        severity = vscode.DiagnosticSeverity.Information;
        break;
      default:
        severity = vscode.DiagnosticSeverity.Warning;
    }

    const location = result.locations?.[0]?.physicalLocation;
    let filePath = location?.artifactLocation?.uri ?? "";
    if (filePath && !path.isAbsolute(filePath)) {
      filePath = path.join(workspacePath, filePath);
    }
    if (!filePath) {
      continue;
    }

    const range = new vscode.Range(0, 0, 0, 0);
    const diagnostic = new vscode.Diagnostic(range, message, severity);
    diagnostic.source = "agent-bom";

    if (rule?.helpUri) {
      diagnostic.code = {
        value: ruleId,
        target: vscode.Uri.parse(rule.helpUri),
      };
    } else {
      diagnostic.code = ruleId;
    }

    const existing = diagsByFile.get(filePath) ?? [];
    existing.push(diagnostic);
    diagsByFile.set(filePath, existing);
  }

  for (const [filePath, diags] of diagsByFile) {
    try {
      const uri = vscode.Uri.file(filePath);
      diagnosticCollection.set(uri, diags);
    } catch {
      // Skip files that can't be resolved
    }
  }

  // Update status bar
  const vulnCount = results.length;
  if (vulnCount > 0) {
    statusBarItem.text = `$(shield) agent-bom: ${vulnCount} vuln(s)`;
    statusBarItem.backgroundColor = new vscode.ThemeColor(
      "statusBarItem.warningBackground"
    );
  } else {
    statusBarItem.text = "$(shield) agent-bom: clean";
    statusBarItem.backgroundColor = undefined;
  }
  statusBarItem.show();

  vscode.window.showInformationMessage(
    `agent-bom: Found ${vulnCount} vulnerability/ies.`
  );
}

// ── Results webview ──────────────────────────────────────────────────────────

function showResults(): void {
  if (!lastSarifData) {
    vscode.window.showInformationMessage(
      'agent-bom: No scan results. Run "agent-bom: Scan Workspace" first.'
    );
    return;
  }

  const panel = vscode.window.createWebviewPanel(
    "agentBomResults",
    "agent-bom Scan Results",
    vscode.ViewColumn.One,
    { enableScripts: false }
  );

  const results = lastSarifData?.runs?.[0]?.results ?? [];
  const rules = lastSarifData?.runs?.[0]?.tool?.driver?.rules ?? [];
  const version =
    lastSarifData?.runs?.[0]?.tool?.driver?.version ?? "unknown";

  let tableRows = "";
  for (const result of results) {
    const level = result.level ?? "warning";
    const color =
      level === "error"
        ? "#e74c3c"
        : level === "warning"
          ? "#f39c12"
          : "#3498db";
    const message = escapeHtml(result.message?.text ?? "");
    tableRows += `<tr>
      <td><strong>${escapeHtml(result.ruleId)}</strong></td>
      <td><span style="color:${color}">${level.toUpperCase()}</span></td>
      <td>${message}</td>
    </tr>`;
  }

  panel.webview.html = `<!DOCTYPE html>
<html>
<head>
  <style>
    body { font-family: var(--vscode-font-family); padding: 20px; }
    h1 { color: var(--vscode-editor-foreground); }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid var(--vscode-panel-border); padding: 8px; text-align: left; }
    th { background: var(--vscode-editor-selectionBackground); }
    .summary { margin: 16px 0; padding: 12px; background: var(--vscode-editor-selectionBackground); border-radius: 4px; }
  </style>
</head>
<body>
  <h1>agent-bom Scan Results</h1>
  <div class="summary">
    <strong>Version:</strong> ${escapeHtml(version)} |
    <strong>Findings:</strong> ${results.length} |
    <strong>Rules:</strong> ${rules.length}
  </div>
  <table>
    <thead><tr><th>ID</th><th>Severity</th><th>Message</th></tr></thead>
    <tbody>${tableRows || '<tr><td colspan="3">No vulnerabilities found.</td></tr>'}</tbody>
  </table>
</body>
</html>`;
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// ── Deactivation ─────────────────────────────────────────────────────────────

export function deactivate(): void {
  diagnosticCollection?.dispose();
  statusBarItem?.dispose();
}
