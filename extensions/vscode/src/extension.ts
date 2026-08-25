// Ladex VS Code extension — a thin client that launches the Python engine over stdio.
//
// It contains no detection logic. It resolves the engine in this order:
//   1. an explicit `ladex.serverCommand` set by the user (wins),
//   2. a binary bundled inside the extension at `bin/ladex[.exe]` (per-platform VSIX),
//   3. a `ladex` on the user's PATH (BYO engine).
// "One engine, three surfaces" — the editor runs the same engine the CLI and PR check use.

import { spawnSync } from "child_process";
import * as fs from "fs";
import * as path from "path";

import * as vscode from "vscode";
import {
  LanguageClient,
  LanguageClientOptions,
  ServerOptions,
  TransportKind,
} from "vscode-languageclient/node";

let client: LanguageClient | undefined;

interface Server {
  command: string;
  args: string[];
  bundled: boolean;
}

function resolveServer(context: vscode.ExtensionContext): Server {
  const config = vscode.workspace.getConfiguration("ladex");
  const configured = (config.get<string>("serverCommand", "ladex") || "ladex").trim();
  const configuredArgs = config.get<string[]>("serverArgs", ["serve"]);

  // 1. An explicit, non-default serverCommand always wins.
  if (configured && configured !== "ladex") {
    return { command: configured, args: configuredArgs, bundled: false };
  }

  // 2. A binary bundled with this (platform-specific) build.
  const exe = process.platform === "win32" ? "ladex.exe" : "ladex";
  const bundled = context.asAbsolutePath(path.join("bin", exe));
  if (fs.existsSync(bundled)) {
    ensureRunnable(bundled);
    return { command: bundled, args: ["serve"], bundled: true };
  }

  // 3. Fall back to a `ladex` on PATH.
  return { command: configured, args: configuredArgs, bundled: false };
}

/** Make a bundled binary executable, and clear macOS quarantine so Gatekeeper won't block it. */
function ensureRunnable(bin: string): void {
  if (process.platform === "win32") {
    return;
  }
  try {
    fs.chmodSync(bin, 0o755);
  } catch {
    /* best effort */
  }
  if (process.platform === "darwin") {
    try {
      spawnSync("xattr", ["-d", "com.apple.quarantine", bin]);
    } catch {
      /* best effort — only matters for unsigned bundled binaries */
    }
  }
}

export function activate(context: vscode.ExtensionContext): void {
  const server = resolveServer(context);
  const serverOptions: ServerOptions = {
    run: { command: server.command, args: server.args, transport: TransportKind.stdio },
    debug: { command: server.command, args: server.args, transport: TransportKind.stdio },
  };

  const clientOptions: LanguageClientOptions = {
    documentSelector: [{ scheme: "file", language: "python" }],
    diagnosticCollectionName: "ladex",
  };

  client = new LanguageClient("ladex", "Ladex", serverOptions, clientOptions);

  client.start().catch((err: unknown) => {
    const hint = server.bundled
      ? "the bundled engine failed to start"
      : `install the ladex CLI (pip install ladex) or set 'ladex.serverCommand' — tried '${server.command}'`;
    void vscode.window.showErrorMessage(`Ladex: could not start the engine — ${hint}. (${String(err)})`);
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
