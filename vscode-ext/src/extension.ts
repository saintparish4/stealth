import * as vscode from "vscode";
import {
  LanguageClient,
  LanguageClientOptions,
  ServerOptions,
  TransportKind,
} from "vscode-languageclient/node";

let client: LanguageClient | undefined;
let statusBarItem: vscode.StatusBarItem;

export async function activate(
  context: vscode.ExtensionContext,
): Promise<void> {
  statusBarItem = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Left,
    -10,
  );
  statusBarItem.name = "Stealth Scanner";
  statusBarItem.command = "workbench.actions.view.problems";
  context.subscriptions.push(statusBarItem);

  const binaryPath = resolveBinaryPath();

  const serverOptions: ServerOptions = {
    run: { command: binaryPath, transport: TransportKind.stdio },
    debug: { command: binaryPath, transport: TransportKind.stdio },
  };

  const clientOptions: LanguageClientOptions = {
    documentSelector: [{ scheme: "file", language: "solidity" }],
    diagnosticCollectionName: "stealth",
  };

  client = new LanguageClient(
    "stealth-lsp",
    "Stealth Scanner",
    serverOptions,
    clientOptions,
  );

  context.subscriptions.push(
    vscode.languages.onDidChangeDiagnostics(() => updateStatusBar()),
  );

  await client.start();
  updateStatusBar();
}

export async function deactivate(): Promise<void> {
  if (client) {
    await client.stop();
    client = undefined;
  }
  statusBarItem?.dispose();
}

function resolveBinaryPath(): string {
  const config = vscode.workspace.getConfiguration("stealth");
  const explicit = config.get<string>("binaryPath", "").trim();
  if (explicit) {
    return explicit;
  }
  return "stealth-lsp";
}

function updateStatusBar(): void {
  const diagnostics = vscode.languages.getDiagnostics();
  let count = 0;

  for (const [uri, diags] of diagnostics) {
    if (!uri.path.endsWith(".sol")) continue;
    count += diags.filter((d) => d.source === "stealth").length;
  }

  if (count === 0) {
    statusBarItem.text = "$(shield) Stealth: 0 issues";
    statusBarItem.backgroundColor = undefined;
  } else {
    statusBarItem.text = `$(shield) Stealth: ${count} issue${count !== 1 ? "s" : ""}`;
    statusBarItem.backgroundColor = new vscode.ThemeColor(
      "statusBarItem.warningBackground",
    );
  }
  statusBarItem.show();
}
