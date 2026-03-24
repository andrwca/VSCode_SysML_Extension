/**
 * Threat Model Editor — a custom text editor that provides a visual
 * drag-and-drop canvas for building SysML v2 threat models.
 *
 * Features:
 * - Toolbox loaded from .threat/*.sysml files (bundled with extension)
 * - Drag-and-drop from toolbox onto a Cytoscape/ELK canvas
 * - Bidirectional sync: canvas ↔ SysML text document
 * - Layout positions persisted in a companion <file>.view.sysml
 */

import * as path from 'path';
import * as vscode from 'vscode';

// ── Types ────────────────────────────────────────────────────────

interface ToolboxItem {
  id: string;
  category: string;
  name: string;
  defType: string;       // 'part def', 'concern def', etc.
  usageKeyword: string;  // 'part', 'concern', 'requirement', etc.
  sysmlType: string;     // 'WebApplication', 'ThreatActor', etc.
  description: string;
  icon: string;
  importPackage: string; // which package to import
}

interface ToolboxCategory {
  id: string;
  label: string;
  icon: string;
  description: string;
  items: ToolboxItem[];
}

interface NodePosition {
  partName: string;
  x: number;
  y: number;
}

interface ParsedElement {
  name: string;
  type: string;
  description: string;
  boundary?: string;
  attributes: Record<string, string>;
}

interface ParsedFlow {
  name: string;
  dataType: string;
  from: string;          // last segment of the path (e.g. 'appService')
  fromPath: string;      // full SysML path (e.g. 'basicWebApp.azurePlatformBoundary.appService')
  to: string;
  toPath: string;
  description: string;
  stride?: { category: string; severity: string; likelihood: string };
}

interface ParsedSequence {
  name: string;
  description: string;
  flows: ParsedFlow[];
}

interface ParsedModel {
  packageName: string;
  boundaries: { name: string; description: string; children: string[] }[];
  components: ParsedElement[];
  actors: ParsedElement[];
  threats: ParsedElement[];
  mitigations: ParsedElement[];
  sequences: ParsedSequence[];
}

// ── Icon map ─────────────────────────────────────────────────────

const TYPE_ICONS: Record<string, string> = {
  WebApplication: '🌐',
  IdentityProvider: '🔑',
  DataStore: '🗄️',
  SecretStore: '🔒',
  MonitoringService: '📊',
  Gateway: '🛡️',
  ExternalSystem: '🔗',
  ThreatActor: '👤',
  TrustBoundary: '🔲',
  Threat: '⚠️',
  SecurityRequirement: '✅',
  Component: '📦',
};

// ── Provider ─────────────────────────────────────────────────────

export class ThreatModelEditorProvider implements vscode.CustomTextEditorProvider {
  public static readonly viewType = 'sysml.threatModelEditor';
  private _toolboxCache: ToolboxCategory[] | undefined;

  constructor(private readonly _context: vscode.ExtensionContext) { }

  public static register(context: vscode.ExtensionContext): vscode.Disposable {
    return vscode.window.registerCustomEditorProvider(
      ThreatModelEditorProvider.viewType,
      new ThreatModelEditorProvider(context),
      { webviewOptions: { retainContextWhenHidden: true } },
    );
  }

  // ── Entry point ────────────────────────────────────────────────

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

    const toolbox = await this._loadToolbox();
    const model = this._parseDocument(document.getText());
    const positions = await this._loadPositions(document.uri);

    webviewPanel.webview.html = this._getHtml(
      webviewPanel.webview, toolbox, model, positions,
    );

    // Handle messages from the webview
    const msgDisposable = webviewPanel.webview.onDidReceiveMessage(async (msg) => {
      if (!msg || typeof msg !== 'object') { return; }
      switch (msg.command) {
        case 'drop':
          await this._handleDrop(document, msg);
          break;
        case 'move':
          await this._handleMove(document.uri, msg);
          break;
        case 'delete':
          await this._handleDelete(document, msg);
          break;
        case 'newFile':
          await this._handleNewFile(document, msg);
          break;
        case 'createFlow':
          await this._handleCreateFlow(document, msg);
          break;
        case 'deleteFlow':
          await this._handleDeleteFlow(document, msg);
          break;
        case 'requestUpdate':
          await this._sendUpdate(webviewPanel, document);
          break;
      }
    });

    // Sync document → webview
    const changeDisposable = vscode.workspace.onDidChangeTextDocument(async (e) => {
      if (e.document.uri.toString() === document.uri.toString() && e.contentChanges.length > 0) {
        await this._sendUpdate(webviewPanel, document);
      }
    });

    webviewPanel.onDidDispose(() => {
      msgDisposable.dispose();
      changeDisposable.dispose();
    });
  }

  private async _sendUpdate(panel: vscode.WebviewPanel, document: vscode.TextDocument): Promise<void> {
    const model = this._parseDocument(document.getText());
    const positions = await this._loadPositions(document.uri);
    panel.webview.postMessage({ type: 'update', model, positions });
  }

  // ── Toolbox loading (fully driven by .threat/*.sysml metadata) ──

  /**
   * Scan all `.threat/*.sysml` files, parse their `@toolbox-*` metadata
   * headers and SysML definitions, and build the toolbox categories.
   *
   * File-level metadata (in `// @toolbox-*` comments at the top):
   *   @toolbox-category   — unique id for grouping (e.g. "components")
   *   @toolbox-label      — display name shown in the panel
   *   @toolbox-icon       — emoji icon for the category header
   *   @toolbox-description — tooltip / subtitle text
   *   @toolbox-order      — numeric sort key (lower = first)
   *   @toolbox-hidden     — "true" to exclude from the drag-and-drop toolbox
   *
   * Per-definition metadata (comment immediately before the def):
   *   // @toolbox-icon: 🌐    — override the default icon for this item
   */
  private async _loadToolbox(): Promise<ToolboxCategory[]> {
    if (this._toolboxCache) { return this._toolboxCache; }

    const threatDir = vscode.Uri.joinPath(this._context.extensionUri, '.threat');
    const categories: ToolboxCategory[] = [];

    // Discover all .sysml files in the .threat directory
    let fileNames: string[];
    try {
      const dirEntries = await vscode.workspace.fs.readDirectory(threatDir);
      fileNames = dirEntries
        .filter(([name, type]) => name.endsWith('.sysml') && type === vscode.FileType.File)
        .map(([name]) => name);
    } catch (err) {
      console.error('Threat toolbox: cannot read .threat directory:', err);
      this._toolboxCache = [];
      return [];
    }

    for (const fileName of fileNames) {
      try {
        const fileUri = vscode.Uri.joinPath(threatDir, fileName);
        const raw = await vscode.workspace.fs.readFile(fileUri);
        const content = Buffer.from(raw).toString('utf-8');

        // Parse file-level metadata from leading comments
        const meta = this._parseFileMetadata(content);

        // Skip files marked as hidden (library / support files)
        if (meta.hidden) { continue; }
        // Skip files without a toolbox-category — they're not toolbox sources
        if (!meta.category) { continue; }

        const items = this._parseToolboxDefs(content, meta.category);
        if (items.length > 0) {
          categories.push({
            id: meta.category,
            label: meta.label || meta.category,
            icon: meta.icon || '📦',
            description: meta.description || '',
            items,
          });
        }
      } catch (err) {
        console.error(`Threat toolbox: failed to read ${fileName}:`, err);
      }
    }

    // Sort categories by their declared order
    categories.sort((a, b) => {
      const oa = this._categoryOrder.get(a.id) ?? 50;
      const ob = this._categoryOrder.get(b.id) ?? 50;
      return oa - ob;
    });

    this._toolboxCache = categories;
    return categories;
  }

  /** Transient map populated during loading to hold per-category sort keys. */
  private _categoryOrder = new Map<string, number>();

  /**
   * Extract `@toolbox-*` key-value pairs from leading comment lines.
   * Stops parsing as soon as a non-comment / non-blank line is hit.
   */
  private _parseFileMetadata(text: string): {
    category: string; label: string; icon: string;
    description: string; order: number; hidden: boolean;
  } {
    const meta = { category: '', label: '', icon: '', description: '', order: 50, hidden: false };
    for (const line of text.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed.startsWith('//') && trimmed.length > 0) { break; }
      const m = trimmed.match(/^\/\/\s*@toolbox-(\w+)\s*:\s*(.+)$/);
      if (m) {
        const key = m[1].toLowerCase();
        const val = m[2].trim();
        switch (key) {
          case 'category': meta.category = val; break;
          case 'label': meta.label = val; break;
          case 'icon': meta.icon = val; break;
          case 'description': meta.description = val; break;
          case 'order': meta.order = parseInt(val, 10) || 50; break;
          case 'hidden': meta.hidden = val === 'true'; break;
        }
      }
    }
    // Stash order for later sorting
    if (meta.category) {
      this._categoryOrder.set(meta.category, meta.order);
    }
    return meta;
  }

  /**
   * Parse all SysML definitions in a file and produce toolbox items.
   * Reads `// @toolbox-icon` comments immediately preceding each def,
   * plus the `doc` block inside each def for item descriptions.
   */
  private _parseToolboxDefs(text: string, category: string): ToolboxItem[] {
    const items: ToolboxItem[] = [];
    const pkgMatch = text.match(/package\s+(\w+)/);
    const importPkg = pkgMatch?.[1] ?? '';

    // Split text into lines for look-behind icon scanning
    const lines = text.split('\n');

    // Match definitions: [abstract] part/concern/requirement/allocation/occurrence def Name [:> Parent] {
    const defRe = /((?:abstract\s+)?(?:part|concern|requirement|allocation|enum|item|port|metadata|occurrence)\s+def)\s+(\w+)(?:\s*:>\s*(\w+))?\s*\{/g;
    let m: RegExpExecArray | null;
    while ((m = defRe.exec(text)) !== null) {
      const defType = m[1].replace(/^abstract\s+/, '');
      const name = m[2];
      const parent = m[3];

      // Skip abstract base types (not directly usable)
      if (m[1].startsWith('abstract')) { continue; }

      const blockEnd = this._findBlockEnd(text, m.index + m[0].length - 1);
      const body = text.substring(m.index + m[0].length, blockEnd);
      const description = this._extractDoc(body);

      // Look for a `// @toolbox-icon: X` comment on the line(s) before the def
      const defLine = text.substring(0, m.index).split('\n').length - 1;
      let itemIcon = '';
      for (let i = defLine; i >= Math.max(0, defLine - 3); i--) {
        const iconMatch = lines[i]?.trim().match(/^\/\/\s*@toolbox-icon\s*:\s*(.+)$/);
        if (iconMatch) { itemIcon = iconMatch[1].trim(); break; }
      }

      // Determine usage keyword from the def keyword
      let usageKeyword = 'part';
      if (defType.startsWith('concern')) { usageKeyword = 'concern'; }
      else if (defType.startsWith('requirement')) { usageKeyword = 'requirement'; }
      else if (defType.startsWith('allocation')) { usageKeyword = 'allocation'; }
      else if (defType.startsWith('occurrence')) { usageKeyword = 'occurrence'; }

      items.push({
        id: `${category}-${name}`,
        category,
        name,
        defType,
        usageKeyword,
        sysmlType: name,
        description: description || `A ${name} element`,
        icon: itemIcon || (TYPE_ICONS[name] ?? TYPE_ICONS[parent ?? ''] ?? '📦'),
        importPackage: importPkg,
      });
    }
    return items;
  }

  // ── Document parsing ───────────────────────────────────────────

  private _parseDocument(text: string): ParsedModel {
    const cleaned = text.replace(/\/\/(?!\s*===).*$/gm, '');
    const model: ParsedModel = {
      packageName: '',
      boundaries: [],
      components: [],
      actors: [],
      threats: [],
      mitigations: [],
      sequences: [],
    };

    const pkgMatch = cleaned.match(/package\s+(\w+)\s*\{/);
    if (pkgMatch) { model.packageName = pkgMatch[1]; }

    // Trust boundaries
    this._findTypedBlocks(cleaned, 'TrustBoundary').forEach(({ name, body }) => {
      const children: string[] = [];

      const componentTypes = ['WebApplication', 'IdentityProvider', 'DataStore',
        'MonitoringService', 'Gateway', 'ExternalSystem', 'SecretStore'];
      for (const ctype of componentTypes) {
        this._findTypedBlocks(body, ctype).forEach(({ name: cname, body: cbody }) => {
          children.push(cname);
          model.components.push({
            name: cname,
            type: ctype,
            description: this._getAttr(cbody, 'description') || this._extractDoc(cbody),
            boundary: name,
            attributes: this._extractAttributes(cbody),
          });
        });
      }

      this._findTypedBlocks(body, 'ThreatActor').forEach(({ name: aname, body: abody }) => {
        children.push(aname);
        model.actors.push({
          name: aname,
          type: 'ThreatActor',
          description: this._getAttr(abody, 'description') || this._extractDoc(abody),
          boundary: name,
          attributes: this._extractAttributes(abody),
        });
      });

      model.boundaries.push({
        name,
        description: this._getAttr(body, 'description') || this._extractDoc(body),
        children,
      });
    });

    // Top-level components (not inside boundaries)
    const topComponentTypes = ['WebApplication', 'IdentityProvider', 'DataStore',
      'MonitoringService', 'Gateway', 'ExternalSystem', 'SecretStore'];
    for (const ctype of topComponentTypes) {
      this._findTopLevelTypedBlocks(cleaned, ctype, model.boundaries).forEach(({ name: cname, body: cbody }) => {
        if (!model.components.find(c => c.name === cname)) {
          model.components.push({
            name: cname,
            type: ctype,
            description: this._getAttr(cbody, 'description') || this._extractDoc(cbody),
            attributes: this._extractAttributes(cbody),
          });
        }
      });
    }

    // Threats
    this._findTypedBlocks(cleaned, 'Threat').forEach(({ name, body }) => {
      const targetMatch = body.match(/subject\s+:>>\s*target\s*=\s*([\w.]+)/);
      model.threats.push({
        name,
        type: 'Threat',
        description: this._extractDoc(body),
        attributes: {
          ...this._extractAttributes(body),
          targetComponent: targetMatch ? (targetMatch[1].split('.').pop() ?? '') : '',
        },
      });
    });

    // Mitigations
    this._findTypedBlocks(cleaned, 'SecurityRequirement').forEach(({ name, body }) => {
      model.mitigations.push({
        name,
        type: 'SecurityRequirement',
        description: this._extractDoc(body),
        attributes: this._extractAttributes(body),
      });
    });

    // Data flow sequences (occurrence def blocks containing succession flows)
    this._findOccurrenceBlocks(cleaned).forEach(({ name, body }) => {
      const flows = this._parseSuccessionFlows(body);
      if (flows.length > 0) {
        model.sequences.push({
          name,
          description: this._extractDoc(body),
          flows,
        });
      }
    });

    return model;
  }

  private _findTypedBlocks(text: string, typeName: string): { name: string; body: string }[] {
    const results: { name: string; body: string }[] = [];
    const re = new RegExp(
      `(?:part|concern|requirement|allocation)\\s+(\\w+)\\s*:\\s*${typeName}\\b`, 'g',
    );
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      const name = m[1];
      const braceStart = text.indexOf('{', m.index + m[0].length);
      if (braceStart === -1) { continue; }
      const braceEnd = this._findBlockEnd(text, braceStart);
      results.push({ name, body: text.substring(braceStart + 1, braceEnd) });
    }
    return results;
  }

  /** Find typed blocks that are NOT inside any boundary block. */
  private _findTopLevelTypedBlocks(
    text: string,
    typeName: string,
    boundaries: ParsedModel['boundaries'],
  ): { name: string; body: string }[] {
    const boundaryNames = new Set(boundaries.flatMap(b => b.children));
    return this._findTypedBlocks(text, typeName).filter(b => !boundaryNames.has(b.name));
  }

  /** Find `occurrence def Name { … }` blocks (data flow sequences). */
  private _findOccurrenceBlocks(text: string): { name: string; body: string }[] {
    const results: { name: string; body: string }[] = [];
    const re = /occurrence\s+def\s+(\w+)\s*\{/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      const braceStart = m.index + m[0].length - 1;
      const braceEnd = this._findBlockEnd(text, braceStart);
      results.push({ name: m[1], body: text.substring(braceStart + 1, braceEnd) });
    }
    return results;
  }

  /**
   * Parse `[then] succession flow <name> of <DataType> from <path> to <path> { … }` blocks.
   */
  private _parseSuccessionFlows(body: string): ParsedFlow[] {
    const flows: ParsedFlow[] = [];
    const flowRe = /(?:then\s+)?succession\s+flow\s+(\w+)\s+of\s+(\w+)\s+from\s+([\w.]+)\s+to\s+([\w.]+)\s*\{/g;
    let m: RegExpExecArray | null;
    while ((m = flowRe.exec(body)) !== null) {
      const flowName = m[1];
      const dataType = m[2];
      const fromPath = m[3];
      const toPath = m[4];

      const braceStart = m.index + m[0].length - 1;
      const braceEnd = this._findBlockEnd(body, braceStart);
      const flowBody = body.substring(braceStart + 1, braceEnd);

      const desc = this._extractDoc(flowBody);

      // Parse optional @StrideTag
      let stride: ParsedFlow['stride'];
      const strideMatch = flowBody.match(/@StrideTag\s*\{([^}]*)\}/);
      if (strideMatch) {
        const tagBody = strideMatch[1];
        const cat = tagBody.match(/category\s*=\s*StrideCategoryKind::(\w+)/);
        const sev = tagBody.match(/severity\s*=\s*SeverityKind::(\w+)/);
        const lik = tagBody.match(/likelihood\s*=\s*LikelihoodKind::(\w+)/);
        stride = {
          category: cat?.[1] ?? '',
          severity: sev?.[1] ?? '',
          likelihood: lik?.[1] ?? '',
        };
      }

      flows.push({
        name: flowName,
        dataType,
        fromPath,
        from: fromPath.split('.').pop() ?? fromPath,
        toPath,
        to: toPath.split('.').pop() ?? toPath,
        description: desc,
        stride,
      });
    }
    return flows;
  }

  private _findBlockEnd(text: string, openBrace: number): number {
    let depth = 1;
    let pos = openBrace + 1;
    while (pos < text.length && depth > 0) {
      if (text[pos] === '{') { depth++; }
      else if (text[pos] === '}') { depth--; }
      pos++;
    }
    return pos - 1;
  }

  private _getAttr(block: string, attr: string): string {
    const re = new RegExp(`:>>\\s*${attr}\\s*=\\s*(?:(\\w+)::(\\w+)|"([^"]*)"|(true|false))`);
    const m = block.match(re);
    if (m) { return m[3] ?? m[2] ?? m[4] ?? ''; }
    return '';
  }

  private _extractDoc(block: string): string {
    const m = block.match(/doc\s+\/\*\s*([\s\S]*?)\*\//);
    return m ? m[1].replace(/^\s*\*\s?/gm, '').trim() : '';
  }

  private _extractAttributes(block: string): Record<string, string> {
    const attrs: Record<string, string> = {};
    const attrRe = /:>>\s*(\w+)\s*=\s*(?:(\w+)::(\w+)|"([^"]*)"|(\w+))/g;
    let m: RegExpExecArray | null;
    while ((m = attrRe.exec(block)) !== null) {
      attrs[m[1]] = m[4] ?? m[3] ?? m[5] ?? '';
    }
    return attrs;
  }

  // ── Drop handling ──────────────────────────────────────────────

  private async _handleDrop(
    document: vscode.TextDocument,
    msg: { sysmlType: string; partName: string; x: number; y: number; boundary?: string },
  ): Promise<void> {
    const sysmlCode = this._generateSysmlForDrop(msg.sysmlType, msg.partName);
    if (!sysmlCode) { return; }

    // Step 1: ensure import exists (separate edit to avoid offset conflicts)
    const text = document.getText();
    if (!text.includes('import ThreatModelToolbox::')) {
      const importEdit = new vscode.WorkspaceEdit();
      const pkgMatch = text.match(/package\s+\w+\s*\{/);
      if (pkgMatch && pkgMatch.index !== undefined) {
        const afterBrace = pkgMatch.index + pkgMatch[0].length;
        importEdit.insert(document.uri, document.positionAt(afterBrace), '\n\tprivate import ThreatModelToolbox::*;\n');
        await vscode.workspace.applyEdit(importEdit);
      }
    }

    // Step 2: re-read text after possible import insertion
    const freshText = document.getText();
    const insertOffset = this._findInsertionPoint(freshText, msg.boundary);
    if (insertOffset < 0) { return; }

    // Determine indentation at insertion point
    const lineStart = freshText.lastIndexOf('\n', insertOffset - 1) + 1;
    const lineText = freshText.substring(lineStart, insertOffset);
    const baseIndent = lineText.match(/^(\s*)/)?.[1] ?? '\t';
    const indentedCode = sysmlCode
      .split('\n')
      .map(line => `${baseIndent}\t${line}`)
      .join('\n');

    const edit = new vscode.WorkspaceEdit();
    const insertPos = document.positionAt(insertOffset);
    edit.insert(document.uri, insertPos, `\n${indentedCode}\n`);
    await vscode.workspace.applyEdit(edit);

    // Save position
    await this._savePosition(document.uri, msg.partName, msg.x, msg.y);
  }

  private _generateSysmlForDrop(sysmlType: string, partName: string): string | undefined {
    const templates: Record<string, (name: string) => string> = {
      WebApplication: (n) => [
        `part ${n} : WebApplication {`,
        `\t:>> description = "${this._camelToTitle(n)}";`,
        `\t:>> isPubliclyAccessible = false;`,
        `\t:>> authentication = AuthenticationKind::none;`,
        `\t:>> encryption = EncryptionKind::none;`,
        `}`,
      ].join('\n'),
      IdentityProvider: (n) => [
        `part ${n} : IdentityProvider {`,
        `\t:>> description = "${this._camelToTitle(n)}";`,
        `\t:>> isPubliclyAccessible = false;`,
        `\t:>> authentication = AuthenticationKind::oauthToken;`,
        `\t:>> encryption = EncryptionKind::both;`,
        `}`,
      ].join('\n'),
      DataStore: (n) => [
        `part ${n} : DataStore {`,
        `\t:>> description = "${this._camelToTitle(n)}";`,
        `\t:>> isPubliclyAccessible = false;`,
        `\t:>> authentication = AuthenticationKind::apiKey;`,
        `\t:>> encryption = EncryptionKind::both;`,
        `\t:>> dataClassification = DataClassificationKind::confidential;`,
        `}`,
      ].join('\n'),
      SecretStore: (n) => [
        `part ${n} : SecretStore {`,
        `\t:>> description = "${this._camelToTitle(n)}";`,
        `\t:>> isPubliclyAccessible = false;`,
        `\t:>> authentication = AuthenticationKind::managedIdentity;`,
        `\t:>> encryption = EncryptionKind::both;`,
        `}`,
      ].join('\n'),
      MonitoringService: (n) => [
        `part ${n} : MonitoringService {`,
        `\t:>> description = "${this._camelToTitle(n)}";`,
        `\t:>> isPubliclyAccessible = false;`,
        `\t:>> authentication = AuthenticationKind::apiKey;`,
        `\t:>> encryption = EncryptionKind::both;`,
        `}`,
      ].join('\n'),
      Gateway: (n) => [
        `part ${n} : Gateway {`,
        `\t:>> description = "${this._camelToTitle(n)}";`,
        `\t:>> isPubliclyAccessible = true;`,
        `\t:>> authentication = AuthenticationKind::none;`,
        `\t:>> encryption = EncryptionKind::inTransit;`,
        `}`,
      ].join('\n'),
      ExternalSystem: (n) => [
        `part ${n} : ExternalSystem {`,
        `\t:>> description = "${this._camelToTitle(n)}";`,
        `\t:>> isPubliclyAccessible = true;`,
        `\t:>> authentication = AuthenticationKind::none;`,
        `\t:>> encryption = EncryptionKind::none;`,
        `}`,
      ].join('\n'),
      ThreatActor: (n) => [
        `part ${n} : ThreatActor {`,
        `\t:>> description = "${this._camelToTitle(n)}";`,
        `\t:>> motivation = ActorMotivationKind::financial;`,
        `\t:>> capability = ActorCapabilityKind::opportunistic;`,
        `}`,
      ].join('\n'),
      TrustBoundary: (n) => [
        `part ${n} : TrustBoundary {`,
        `\t:>> description = "${this._camelToTitle(n)}";`,
        `}`,
      ].join('\n'),
      Threat: (n) => [
        `concern ${n} : Threat {`,
        `\tdoc /* Describe the threat. */`,
        `\t:>> strideCategory = StrideCategoryKind::spoofing;`,
        `\t:>> severity = SeverityKind::medium;`,
        `\t:>> likelihood = LikelihoodKind::possible;`,
        `\t:>> targetDescription = "";`,
        `}`,
      ].join('\n'),
      SecurityRequirement: (n) => [
        `requirement ${n} : SecurityRequirement {`,
        `\tdoc /* Describe the security control. */`,
        `\t:>> isImplemented = false;`,
        `}`,
      ].join('\n'),
      Mitigation: (n) => [
        `allocation ${n} : Mitigation {`,
        `\tdoc /* Bind a requirement to a component. */`,
        `}`,
      ].join('\n'),
    };

    const fn = templates[sysmlType];
    return fn ? fn(partName) : undefined;
  }

  /**
   * Find the best offset to insert a new element.
   * If a boundary name is given, insert at the end of that boundary block.
   * Otherwise insert at the end of the first top-level part block, or
   * just before the final package closing brace.
   */
  private _findInsertionPoint(text: string, boundary?: string): number {
    if (boundary) {
      const re = new RegExp(`part\\s+${boundary}\\s*:\\s*TrustBoundary\\s*\\{`);
      const m = text.match(re);
      if (m && m.index !== undefined) {
        const braceStart = text.indexOf('{', m.index + m[0].length - 1);
        const braceEnd = this._findBlockEnd(text, braceStart);
        return braceEnd; // Insert before the closing brace
      }
    }

    // Try to find a top-level part block inside the package
    // (match part name, optional type, with possible whitespace/newlines before brace)
    const pkgMatch = text.match(/package\s+\w+\s*\{/);
    if (pkgMatch && pkgMatch.index !== undefined) {
      const pkgBraceStart = pkgMatch.index + pkgMatch[0].length - 1;
      const pkgBody = text.substring(pkgBraceStart + 1);

      // Find the first `part <name>` declaration within the package body
      const partRe = /part\s+(\w+)\s*(?::\s*\w+)?/;
      const partMatch = pkgBody.match(partRe);
      if (partMatch && partMatch.index !== undefined) {
        const absStart = pkgBraceStart + 1 + partMatch.index;
        // Find the opening brace after the part declaration
        const braceStart = text.indexOf('{', absStart + partMatch[0].length);
        if (braceStart !== -1) {
          const braceEnd = this._findBlockEnd(text, braceStart);
          return braceEnd; // Insert before the closing brace of the architecture block
        }
      }

      // No part block — insert before the package closing brace
      const pkgBraceEnd = this._findBlockEnd(text, pkgBraceStart);
      return pkgBraceEnd;
    }

    // Fallback: before the final closing brace of the package
    const lastBrace = text.lastIndexOf('}');
    return lastBrace > 0 ? lastBrace : text.length;
  }

  /** @deprecated Import is now handled inline in _handleDrop to avoid offset conflicts. */
  private _ensureImport(edit: vscode.WorkspaceEdit, document: vscode.TextDocument): void {
    const text = document.getText();
    if (text.includes('import ThreatModelToolbox::')) { return; }
    // Add import after package declaration opening brace
    const pkgMatch = text.match(/package\s+\w+\s*\{/);
    if (pkgMatch && pkgMatch.index !== undefined) {
      const afterBrace = pkgMatch.index + pkgMatch[0].length;
      const importLine = '\n\tprivate import ThreatModelToolbox::*;\n';
      edit.insert(document.uri, document.positionAt(afterBrace), importLine);
    }
  }

  // ── Delete handling ────────────────────────────────────────────

  private async _handleDelete(
    document: vscode.TextDocument,
    msg: { partName: string },
  ): Promise<void> {
    const text = document.getText();
    // Find the part/concern/requirement block by name
    const re = new RegExp(
      `\\n?[ \\t]*(?:part|concern|requirement|allocation)\\s+${msg.partName}\\s*:[^{]*\\{`,
    );
    const m = text.match(re);
    if (!m || m.index === undefined) { return; }

    const braceStart = text.indexOf('{', m.index + m[0].length - 1);
    const braceEnd = this._findBlockEnd(text, braceStart);
    // Delete from the match start to after the closing brace + newline
    const deleteEnd = Math.min(braceEnd + 2, text.length);
    const edit = new vscode.WorkspaceEdit();
    edit.delete(
      document.uri,
      new vscode.Range(
        document.positionAt(m.index),
        document.positionAt(deleteEnd),
      ),
    );
    await vscode.workspace.applyEdit(edit);

    // Remove from view file
    await this._removePosition(document.uri, msg.partName);
  }

  // ── Flow handling ──────────────────────────────────────────────

  private async _handleCreateFlow(
    document: vscode.TextDocument,
    msg: {
      flowName: string; sequenceName: string; dataType: string;
      fromPart: string; toPart: string; addStride: boolean;
    },
  ): Promise<void> {
    const text = document.getText();

    // Resolve full SysML paths for from/to by searching the document
    const fromPath = this._resolvePartPath(text, msg.fromPart);
    const toPath = this._resolvePartPath(text, msg.toPart);

    const flowCode = this._generateFlowSysml(
      msg.flowName, msg.dataType, fromPath, toPath, msg.addStride,
    );

    // Check if the sequence already exists
    const seqRe = new RegExp(`occurrence\\s+def\\s+${msg.sequenceName}\\s*\\{`);
    const seqMatch = text.match(seqRe);

    if (seqMatch && seqMatch.index !== undefined) {
      // Append flow inside existing sequence block
      const braceStart = text.indexOf('{', seqMatch.index + seqMatch[0].length - 1);
      const braceEnd = this._findBlockEnd(text, braceStart);

      // Check if there are already flows inside — if so, use "then" prefix
      const seqBody = text.substring(braceStart + 1, braceEnd);
      const hasPriorFlows = /succession\s+flow\s+\w+/.test(seqBody);
      const finalCode = hasPriorFlows
        ? flowCode.replace('succession flow', 'then succession flow')
        : flowCode;

      const edit = new vscode.WorkspaceEdit();
      edit.insert(document.uri, document.positionAt(braceEnd), `\n\t\t${finalCode}\n`);
      await vscode.workspace.applyEdit(edit);
    } else {
      // Create a new occurrence def block with the flow inside
      const seqCode = [
        ``,
        `\toccurrence def ${msg.sequenceName} {`,
        `\t\tdoc /* Data flow sequence. */`,
        ``,
        `\t\t${flowCode}`,
        `\t}`,
      ].join('\n');

      // Insert after the main architecture part block (at package level)
      const insertOffset = this._findSequenceInsertionPoint(text);
      const edit = new vscode.WorkspaceEdit();
      edit.insert(document.uri, document.positionAt(insertOffset), `\n${seqCode}\n`);
      await vscode.workspace.applyEdit(edit);
    }
  }

  private async _handleDeleteFlow(
    document: vscode.TextDocument,
    msg: { flowName: string },
  ): Promise<void> {
    const text = document.getText();
    // Match: [then] succession flow <name> of <Type> from <path> to <path> { … }
    const flowRe = new RegExp(
      `\\n?[ \\t]*(?:then\\s+)?succession\\s+flow\\s+${msg.flowName}\\s+of\\s+\\w+\\s+from\\s+[\\w.]+\\s+to\\s+[\\w.]+\\s*\\{`,
    );
    const m = text.match(flowRe);
    if (!m || m.index === undefined) { return; }

    const braceStart = text.indexOf('{', m.index + m[0].length - 1);
    const braceEnd = this._findBlockEnd(text, braceStart);
    const deleteEnd = Math.min(braceEnd + 2, text.length);

    const edit = new vscode.WorkspaceEdit();
    edit.delete(
      document.uri,
      new vscode.Range(
        document.positionAt(m.index),
        document.positionAt(deleteEnd),
      ),
    );
    await vscode.workspace.applyEdit(edit);
  }

  /**
   * Generate SysML for a succession flow.
   */
  private _generateFlowSysml(
    flowName: string, dataType: string,
    fromPath: string, toPath: string, addStride: boolean,
  ): string {
    const lines = [
      `succession flow ${flowName} of ${dataType}`,
      `\tfrom ${fromPath}`,
      `\tto ${toPath} {`,
      `\tdoc /* Describe this data flow. */`,
    ];

    if (addStride) {
      lines.push(
        `\t@StrideTag {`,
        `\t\tcategory = StrideCategoryKind::spoofing;`,
        `\t\tseverity = SeverityKind::medium;`,
        `\t\tlikelihood = LikelihoodKind::possible;`,
        `\t}`,
      );
    }

    lines.push(`}`);
    return lines.join('\n\t\t');
  }

  /**
   * Resolve a part name to its full dotted path in the document.
   * E.g. "appService" → "basicWebApp.azurePlatformBoundary.appService"
   */
  private _resolvePartPath(text: string, partName: string): string {
    // Build a path map by walking package → part → part nesting
    const pathMap = new Map<string, string>();

    const walkBlock = (blockText: string, prefix: string) => {
      const partRe = /part\s+(\w+)\s*(?::\s*\w+)?\s*\{/g;
      let m: RegExpExecArray | null;
      while ((m = partRe.exec(blockText)) !== null) {
        const name = m[1];
        const fullPath = prefix ? `${prefix}.${name}` : name;
        pathMap.set(name, fullPath);
        const braceStart = m.index + m[0].length - 1;
        const braceEnd = this._findBlockEnd(blockText, braceStart);
        const innerBody = blockText.substring(braceStart + 1, braceEnd);
        walkBlock(innerBody, fullPath);
      }
    };

    const pkgMatch = text.match(/package\s+\w+\s*\{/);
    if (pkgMatch && pkgMatch.index !== undefined) {
      const braceStart = pkgMatch.index + pkgMatch[0].length - 1;
      const braceEnd = this._findBlockEnd(text, braceStart);
      walkBlock(text.substring(braceStart + 1, braceEnd), '');
    }

    return pathMap.get(partName) ?? partName;
  }

  /**
   * Find where to insert a new occurrence def (after the main architecture block,
   * at the package level).
   */
  private _findSequenceInsertionPoint(text: string): number {
    // Look for existing occurrence def blocks — insert after the last one
    const occRe = /occurrence\s+def\s+\w+\s*\{/g;
    let lastOccEnd = -1;
    let m: RegExpExecArray | null;
    while ((m = occRe.exec(text)) !== null) {
      const braceStart = m.index + m[0].length - 1;
      const braceEnd = this._findBlockEnd(text, braceStart);
      lastOccEnd = braceEnd + 1;
    }
    if (lastOccEnd > 0) { return lastOccEnd; }

    // Otherwise, insert after the first top-level part block at package level
    const pkgMatch = text.match(/package\s+\w+\s*\{/);
    if (pkgMatch && pkgMatch.index !== undefined) {
      const pkgBraceStart = pkgMatch.index + pkgMatch[0].length - 1;
      const pkgBody = text.substring(pkgBraceStart + 1);
      const partRe = /part\s+\w+\s*(?::\s*\w+)?\s*(?:\{|$)/;
      const partMatch = pkgBody.match(partRe);
      if (partMatch && partMatch.index !== undefined) {
        const absStart = pkgBraceStart + 1 + partMatch.index;
        const braceIdx = text.indexOf('{', absStart + partMatch[0].length - 1);
        if (braceIdx !== -1) {
          const braceEnd = this._findBlockEnd(text, braceIdx);
          return braceEnd + 1;
        }
      }
      // Before package closing brace
      return this._findBlockEnd(text, pkgBraceStart);
    }
    return text.lastIndexOf('}');
  }

  // ── New file scaffolding ───────────────────────────────────────

  private async _handleNewFile(
    document: vscode.TextDocument,
    msg: { packageName: string },
  ): Promise<void> {
    const name = msg.packageName || 'NewThreatModel';
    const template = [
      `package ${name} {`,
      `\tdoc /* ${this._camelToTitle(name)} — created with SysML Threat Model Editor. */`,
      ``,
      `\tprivate import ThreatModelToolbox::*;`,
      ``,
      `\tpart architecture {`,
      `\t\tdoc /* Main architecture container. */`,
      `\t}`,
      `}`,
      ``,
    ].join('\n');

    const edit = new vscode.WorkspaceEdit();
    edit.replace(
      document.uri,
      new vscode.Range(
        document.positionAt(0),
        document.positionAt(document.getText().length),
      ),
      template,
    );
    await vscode.workspace.applyEdit(edit);
  }

  // ── Position / view.sysml management ───────────────────────────

  private _getViewUri(docUri: vscode.Uri): vscode.Uri {
    const dir = path.dirname(docUri.fsPath);
    const base = path.basename(docUri.fsPath, '.sysml');
    return vscode.Uri.file(path.join(dir, `${base}.view.sysml`));
  }

  async _loadPositions(docUri: vscode.Uri): Promise<NodePosition[]> {
    const viewUri = this._getViewUri(docUri);
    try {
      const raw = Buffer.from(await vscode.workspace.fs.readFile(viewUri)).toString('utf-8');
      return this._parseViewFile(raw);
    } catch {
      return [];
    }
  }

  private _parseViewFile(text: string): NodePosition[] {
    const positions: NodePosition[] = [];
    // Match: @NodeLayout { x = <num>; y = <num>; } followed by part <name>;
    const re = /@NodeLayout\s*\{\s*x\s*=\s*([\d.]+)\s*;\s*y\s*=\s*([\d.]+)\s*;\s*\}\s*\n\s*part\s+(\w+)\s*;/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      positions.push({
        partName: m[3],
        x: parseFloat(m[1]),
        y: parseFloat(m[2]),
      });
    }
    return positions;
  }

  private async _handleMove(
    docUri: vscode.Uri,
    msg: { partName: string; x: number; y: number },
  ): Promise<void> {
    await this._savePosition(docUri, msg.partName, msg.x, msg.y);
  }

  private async _savePosition(docUri: vscode.Uri, partName: string, x: number, y: number): Promise<void> {
    const positions = await this._loadPositions(docUri);
    const existing = positions.find(p => p.partName === partName);
    if (existing) {
      existing.x = Math.round(x);
      existing.y = Math.round(y);
    } else {
      positions.push({ partName, x: Math.round(x), y: Math.round(y) });
    }
    await this._writeViewFile(docUri, positions);
  }

  private async _removePosition(docUri: vscode.Uri, partName: string): Promise<void> {
    const positions = await this._loadPositions(docUri);
    const filtered = positions.filter(p => p.partName !== partName);
    await this._writeViewFile(docUri, filtered);
  }

  private async _writeViewFile(docUri: vscode.Uri, positions: NodePosition[]): Promise<void> {
    const viewUri = this._getViewUri(docUri);
    const baseName = path.basename(docUri.fsPath, '.sysml');
    const pkgName = baseName.replace(/[^a-zA-Z0-9]/g, '_');

    const lines: string[] = [
      `package ${pkgName}_View {`,
      `\tdoc /* Diagram layout for ${baseName}.sysml — auto-generated by Threat Model Editor. */`,
      ``,
      `\tmetadata def NodeLayout {`,
      `\t\tattribute x : ScalarValues::Real;`,
      `\t\tattribute y : ScalarValues::Real;`,
      `\t}`,
      ``,
      `\tpart diagramPositions {`,
    ];

    for (const pos of positions) {
      lines.push(`\t\t@NodeLayout { x = ${pos.x}; y = ${pos.y}; }`);
      lines.push(`\t\tpart ${pos.partName};`);
      lines.push(``);
    }

    lines.push(`\t}`);
    lines.push(`}`);
    lines.push(``);

    await vscode.workspace.fs.writeFile(viewUri, Buffer.from(lines.join('\n'), 'utf-8'));
  }

  // ── Helpers ────────────────────────────────────────────────────

  private _camelToTitle(s: string): string {
    return s.replace(/([A-Z])/g, ' $1').replace(/^./, c => c.toUpperCase()).trim();
  }

  private _esc(s: string): string {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  private _nonce(): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let v = '';
    for (let i = 0; i < 32; i++) { v += chars.charAt(Math.floor(Math.random() * chars.length)); }
    return v;
  }

  // ── HTML ───────────────────────────────────────────────────────

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
}
