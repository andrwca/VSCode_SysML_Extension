/**
 * Threat Model Editor — a custom text editor that provides a visual
 * drag-and-drop canvas for building SysML v2 threat models.
 *
 * This file contains only the VS Code provider wiring and HTML generation.
 * Domain logic is delegated to sibling modules:
 *   - toolboxLoader    — .threat/ file scanning & metadata
 *   - documentParser   — SysML text → ParsedModel
 *   - documentEditor   — document mutations (drop, delete, flow, new file)
 *   - positionManager  — .view.sysml layout persistence
 */

import * as vscode from 'vscode';
import { handleCreateFlow, handleDelete, handleDeleteFlow, handleDrop, handleNewFile, handleUpdateProperties } from './documentEditor';
import { parseDocument } from './documentParser';
import { handleMove, loadPositions } from './positionManager';
import { loadToolbox } from './toolboxLoader';
import type { NodePosition, ParsedModel, ToolboxCategory } from './types';

export class ThreatModelEditorProvider implements vscode.CustomTextEditorProvider {
  public static readonly viewType = 'sysml.threatModelEditor';

  constructor(private readonly _context: vscode.ExtensionContext) { }

  public static register(context: vscode.ExtensionContext): vscode.Disposable {
    return vscode.window.registerCustomEditorProvider(
      ThreatModelEditorProvider.viewType,
      new ThreatModelEditorProvider(context),
      { webviewOptions: { retainContextWhenHidden: true } },
    );
  }

  async resolveCustomTextEditor(
    document: vscode.TextDocument,
    webviewPanel: vscode.WebviewPanel,
    _token: vscode.CancellationToken,
  ): Promise<void> {
    webviewPanel.webview.options = {
      enableScripts: true,
      localResourceRoots: [
        vscode.Uri.joinPath(this._context.extensionUri, 'media'),
      ],
    };

    const toolbox = await loadToolbox(this._context.extensionUri);
    await this._ensureToolboxLibrary(document.uri);
    const model = parseDocument(document.getText());
    const positions = await loadPositions(document.uri);

    webviewPanel.webview.html = this._getHtml(
      webviewPanel.webview, toolbox, model, positions,
    );

    // Message dispatch
    const msgDisposable = webviewPanel.webview.onDidReceiveMessage(async (msg) => {
      if (!msg || typeof msg !== 'object') { return; }
      switch (msg.command) {
        case 'drop': {
          // Resolve toolbox item params from cached toolbox
          const allItems = toolbox.flatMap(c => c.items);
          const item = allItems.find(i => i.sysmlType === msg.sysmlType);
          await handleDrop(document, {
            ...msg,
            usageKeyword: item?.usageKeyword ?? msg.usageKeyword ?? 'part',
            params: item?.params ?? [],
          });
          break;
        }
        case 'move': await handleMove(document.uri, msg); break;
        case 'delete': await handleDelete(document, msg); break;
        case 'newFile': await handleNewFile(document, msg); break;
        case 'createFlow': await handleCreateFlow(document, msg); break;
        case 'deleteFlow': await handleDeleteFlow(document, msg); break;
        case 'updateProperties': {
          const allItems = toolbox.flatMap(c => c.items);
          // Find the element's type from the document model
          const currentModel = parseDocument(document.getText());
          const allElements = [
            ...currentModel.components, ...currentModel.actors,
            ...currentModel.threats, ...currentModel.mitigations,
          ];
          const el = allElements.find(e => e.name === msg.partName);
          const item = el ? allItems.find(i => i.sysmlType === el.type) : undefined;
          await handleUpdateProperties(document, {
            partName: msg.partName,
            attrValues: msg.attributes ?? {},
            params: item?.params ?? [],
          });
          break;
        }
        case 'requestUpdate': await this._sendUpdate(webviewPanel, document); break;
      }
    });

    // Sync document changes → webview (debounced to avoid stale position reads)
    let changeTimer: ReturnType<typeof setTimeout> | undefined;
    const changeDisposable = vscode.workspace.onDidChangeTextDocument((e) => {
      if (e.document.uri.toString() === document.uri.toString() && e.contentChanges.length > 0) {
        if (changeTimer) { clearTimeout(changeTimer); }
        changeTimer = setTimeout(() => { void this._sendUpdate(webviewPanel, document); }, 100);
      }
    });

    webviewPanel.onDidDispose(() => {
      msgDisposable.dispose();
      changeDisposable.dispose();
    });
  }

  private async _sendUpdate(panel: vscode.WebviewPanel, document: vscode.TextDocument): Promise<void> {
    const model = parseDocument(document.getText());
    const positions = await loadPositions(document.uri);
    panel.webview.postMessage({ type: 'update', model, positions });
  }

  // ── Toolbox library sync ────────────────────────────────────────

  /**
   * Ensure the `.threat/` toolbox SysML definitions are available in the
   * workspace so the LSP can resolve imports (e.g. `ThreatModelToolbox::*`).
   * Copies files once into a `.sysml-lib/` folder next to the document.
   */
  private async _ensureToolboxLibrary(docUri: vscode.Uri): Promise<void> {
    const wsFolder = vscode.workspace.getWorkspaceFolder(docUri);
    if (!wsFolder) { return; }

    const libDir = vscode.Uri.joinPath(wsFolder.uri, '.sysml-lib');
    const markerUri = vscode.Uri.joinPath(libDir, '.toolbox-synced');

    // Skip if already copied
    try {
      await vscode.workspace.fs.stat(markerUri);
      return;
    } catch { /* not yet synced */ }

    const srcDir = vscode.Uri.joinPath(this._context.extensionUri, '.threat');
    try {
      const entries = await vscode.workspace.fs.readDirectory(srcDir);
      await vscode.workspace.fs.createDirectory(libDir);
      for (const [name, type] of entries) {
        if (type === vscode.FileType.File && name.endsWith('.sysml')) {
          const src = vscode.Uri.joinPath(srcDir, name);
          const dst = vscode.Uri.joinPath(libDir, name);
          await vscode.workspace.fs.copy(src, dst, { overwrite: true });
        }
      }
      // Write marker file
      await vscode.workspace.fs.writeFile(markerUri, Buffer.from(''));

      // Add .sysml-lib/ to .gitignore if not already present
      await this._ensureGitignoreEntry(wsFolder.uri, '.sysml-lib/');
    } catch (err) {
      // Non-fatal: editor still works, just LSP won't resolve toolbox types
      const outputChannel = vscode.window.createOutputChannel('SysML');
      outputChannel.appendLine(`Threat Model: failed to sync toolbox library: ${err}`);
    }
  }

  private async _ensureGitignoreEntry(wsUri: vscode.Uri, entry: string): Promise<void> {
    const gitignoreUri = vscode.Uri.joinPath(wsUri, '.gitignore');
    let content = '';
    try {
      content = Buffer.from(await vscode.workspace.fs.readFile(gitignoreUri)).toString('utf-8');
    } catch { /* no .gitignore yet */ }

    if (!content.split('\n').some(line => line.trim() === entry.trim())) {
      const suffix = content.endsWith('\n') || content === '' ? '' : '\n';
      content += `${suffix}${entry}\n`;
      await vscode.workspace.fs.writeFile(gitignoreUri, Buffer.from(content, 'utf-8'));
    }
  }

  // ── HTML generation ────────────────────────────────────────────

  private _getHtml(
    webview: vscode.Webview,
    toolbox: ToolboxCategory[],
    model: ParsedModel,
    positions: NodePosition[],
  ): string {
    const nonce = this._nonce();

    const scriptUri = webview.asWebviewUri(
      vscode.Uri.joinPath(this._context.extensionUri, 'media', 'webview', 'threatModelApp.js'),
    );
    const appCssUri = webview.asWebviewUri(
      vscode.Uri.joinPath(this._context.extensionUri, 'media', 'webview', 'threatModelApp.css'),
    );
    const cssUri = webview.asWebviewUri(
      vscode.Uri.joinPath(this._context.extensionUri, 'media', 'webview', 'threatModelEditor.css'),
    );

    const toolboxJson = JSON.stringify(toolbox);
    const modelJson = JSON.stringify(model);
    const positionsJson = JSON.stringify(positions);

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy"
  content="default-src 'none'; style-src ${webview.cspSource} 'unsafe-inline'; script-src 'nonce-${nonce}'; img-src ${webview.cspSource} data:;">
<link rel="stylesheet" href="${appCssUri}">
<link rel="stylesheet" href="${cssUri}">
</head>
<body>
<div id="root"></div>
<script nonce="${nonce}">
  // Inject initial data for the React app
  window.__INITIAL_MODEL__ = ${modelJson};
  window.__INITIAL_POSITIONS__ = ${positionsJson};
  window.__INITIAL_TOOLBOX__ = ${toolboxJson};
</script>
<script nonce="${nonce}" src="${scriptUri}"></script>
</body>
</html>`;
  }

  private _nonce(): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let v = '';
    for (let i = 0; i < 32; i++) { v += chars.charAt(Math.floor(Math.random() * chars.length)); }
    return v;
  }
}
