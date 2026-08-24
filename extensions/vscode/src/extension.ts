// Ladex VS Code extension — a thin client that launches the Python engine over stdio.
//
// It deliberately contains no detection logic: it starts `ladex serve` (the same engine the
// CLI and PR check use) and lets the language server publish diagnostics. "One engine, three
// surfaces" — the editor can never disagree with the gate.

import * as vscode from "vscode";
import {
  LanguageClient,
  LanguageClientOptions,
  ServerOptions,
  TransportKind,
} from "vscode-languageclient/node";

let client: LanguageClient | undefined;

export function activate(context: vscode.ExtensionContext): void {
  const config = vscode.workspace.getConfiguration("ladex");
  const command = config.get<string>("serverCommand", "ladex");
  const args = config.get<string[]>("serverArgs", ["serve"]);

  const serverOptions: ServerOptions = {
    run: { command, args, transport: TransportKind.stdio },
    debug: { command, args, transport: TransportKind.stdio },
  };

  const clientOptions: LanguageClientOptions = {
    documentSelector: [{ scheme: "file", language: "python" }],
    diagnosticCollectionName: "ladex",
  };

  client = new LanguageClient(
    "ladex",
    "Ladex",
    serverOptions,
    clientOptions,
  );

  // Surface a clear error if the engine isn't on PATH, rather than failing silently.
  client.start().catch((err: unknown) => {
    void vscode.window.showErrorMessage(
      `Ladex: could not start '${command} ${args.join(" ")}'. ` +
        `Install the ladex CLI and ensure it is on PATH. (${String(err)})`,
    );
  });

  context.subscriptions.push({
    dispose: () => {
      void client?.stop();
    },
  });
}

export function deactivate(): Thenable<void> | undefined {
  return client?.stop();
}
