/**
 * Threat Model Panel — a webview rendering a SysML-based threat model
 * as an interactive architecture + threat overview.
 *
 * Displays:
 * - Architecture diagram with trust boundaries and components
 * - Data flows between components with STRIDE tags
 * - Threat actors with motivation and capability
 * - Threat assessment table (STRIDE, severity, likelihood)
 * - Risk heat map (severity × likelihood)
 * - Mitigation checklist with implementation status
 */

import * as vscode from 'vscode';

// ── Parsed threat model types ──

interface ThreatActor {
  name: string;
  description: string;
  motivation: string;
  capability: string;
  boundary: string;
}

interface Component {
  name: string;
  type: string;
  description: string;
  isPubliclyAccessible: boolean;
  authentication: string;
  encryption: string;
  dataClassification?: string;
  boundary: string;
}

interface TrustBoundary {
  name: string;
  description: string;
  components: string[];
  actors: string[];
}

interface DataFlow {
  name: string;
  from: string;
  to: string;
  itemType: string;
  description: string;
  stride?: { category: string; severity: string; likelihood: string };
}

interface Threat {
  name: string;
  description: string;
  strideCategory: string;
  severity: string;
  likelihood: string;
  targetDescription: string;
  targetComponent: string;
}

interface Mitigation {
  name: string;
  description: string;
  isImplemented: boolean;
  targetThreat: string;
}

interface ThreatModel {
  packageName: string;
  packageDoc: string;
  boundaries: TrustBoundary[];
  actors: ThreatActor[];
  components: Component[];
  dataFlows: DataFlow[];
  threats: Threat[];
  mitigations: Mitigation[];
}

export class ThreatModelPanel {
  public static currentPanel: ThreatModelPanel | undefined;

  private readonly _panel: vscode.WebviewPanel;
  private readonly _extensionUri: vscode.Uri;
  private readonly _disposables: vscode.Disposable[] = [];
  private _fileUris: vscode.Uri[] = [];

  private constructor(panel: vscode.WebviewPanel, extensionUri: vscode.Uri, fileUris: vscode.Uri[]) {
    this._panel = panel;
    this._extensionUri = extensionUri;
    this._fileUris = fileUris;
    this._panel.onDidDispose(() => this.dispose(), null, this._disposables);

    this._panel.webview.onDidReceiveMessage(
      (msg: unknown) => {
        if (!msg || typeof msg !== 'object') { return; }
        const m = msg as { command?: string; uri?: string };
        if (m.command === 'openFile' && m.uri) {
          const uri = vscode.Uri.parse(m.uri);
          vscode.window.showTextDocument(uri, { preview: false });
        }
      },
      null,
      this._disposables,
    );

    void this._render();
  }

  static async createOrShow(extensionUri: vscode.Uri, fileUris: vscode.Uri[]): Promise<void> {
    if (ThreatModelPanel.currentPanel) {
      ThreatModelPanel.currentPanel._fileUris = fileUris;
      ThreatModelPanel.currentPanel._panel.reveal(vscode.ViewColumn.Active);
      await ThreatModelPanel.currentPanel._render();
      return;
    }

    const panel = vscode.window.createWebviewPanel(
      'sysmlThreatModel',
      'SysML Threat Model',
      vscode.ViewColumn.Active,
      {
        enableScripts: true,
        enableCommandUris: true,
        localResourceRoots: [
          vscode.Uri.joinPath(extensionUri, 'media'),
        ],
      },
    );

    ThreatModelPanel.currentPanel = new ThreatModelPanel(panel, extensionUri, fileUris);
  }

  dispose(): void {
    ThreatModelPanel.currentPanel = undefined;
    this._panel.dispose();
    for (const d of this._disposables) { d.dispose(); }
  }

  // ── Parsing ────────────────────────────────────────────────────

  private async _readFiles(): Promise<string> {
    let combined = '';
    for (const uri of this._fileUris) {
      try {
        const doc = await vscode.workspace.openTextDocument(uri);
        combined += `${doc.getText()}\n`;
      } catch { /* skip unreadable */ }
    }
    return combined;
  }

  /**
   * Parse the SysML text to extract threat-model-specific structures.
   * Uses regex because the generic LSP DTOs may not capture all the
   * redefined feature values (`:>> attr = value`) we need.
   */
  private _parse(text: string): ThreatModel {
    // Remove single-line comments but keep doc comments
    const cleaned = text.replace(/\/\/(?!\s*===).*$/gm, '');

    const model: ThreatModel = {
      packageName: '',
      packageDoc: '',
      boundaries: [],
      actors: [],
      components: [],
      dataFlows: [],
      threats: [],
      mitigations: [],
    };

    // Package name and doc
    const pkgMatch = cleaned.match(/package\s+(\w+)\s*\{/);
    if (pkgMatch) { model.packageName = pkgMatch[1]; }
    const pkgDocMatch = cleaned.match(/package\s+\w+\s*\{[^}]*?doc\s+\/\*\s*([\s\S]*?)\*\//);
    if (pkgDocMatch) { model.packageDoc = pkgDocMatch[1].replace(/^\s*\*\s?/gm, '').trim(); }

    // Helper to extract a redefined attribute value
    const getAttr = (block: string, attr: string): string => {
      const re = new RegExp(`:>>\\s*${attr}\\s*=\\s*(?:(\\w+)::(\\w+)|"([^"]*)"|(true|false))`);
      const m = block.match(re);
      if (m) { return m[2] ?? m[3] ?? m[4] ?? ''; }
      return '';
    };

    const getDoc = (block: string): string => {
      const m = block.match(/doc\s+\/\*\s*([\s\S]*?)\*\//);
      return m ? m[1].replace(/^\s*\*\s?/gm, '').trim() : '';
    };

    // Extract trust boundaries and contained components/actors
    // We need to find part X : TrustBoundary { ... } blocks
    this._findTypedBlocks(cleaned, 'TrustBoundary').forEach(({ name, body }) => {
      const boundary: TrustBoundary = {
        name,
        description: getAttr(body, 'description') || getDoc(body),
        components: [],
        actors: [],
      };

      // Find components inside boundary.
      // Map Azure-specific subtypes (from ThreatModelToolbox) to their base category.
      const azureTypeMap: Record<string, string> = {
        AzureAppService: 'WebApplication', AzureFunctions: 'WebApplication',
        AzureContainerApps: 'WebApplication', AzureKubernetesService: 'WebApplication',
        AzureVirtualMachine: 'WebApplication',
        AzureEntraId: 'IdentityProvider', AzureEntraID: 'IdentityProvider',
        AzureManagedIdentity: 'IdentityProvider',
        AzureSQLDatabase: 'DataStore', AzureCosmosDB: 'DataStore',
        AzureBlobStorage: 'DataStore', AzureTableStorage: 'DataStore',
        AzureRedisCache: 'DataStore', AzureDataLakeStorage: 'DataStore',
        AzurePostgreSQL: 'DataStore', AzureMySQL: 'DataStore',
        AzureKeyVault: 'SecretStore',
        AzureMonitor: 'MonitoringService', AzureApplicationInsights: 'MonitoringService',
        AzureLogAnalytics: 'MonitoringService', AzureSentinel: 'MonitoringService',
        AzureApplicationGateway: 'Gateway', AzureFrontDoor: 'Gateway',
        AzureLoadBalancer: 'Gateway', AzureFirewall: 'Gateway',
        AzureTrafficManager: 'Gateway', AzureAPIManagement: 'Gateway',
        AzureVPNGateway: 'Gateway',
        AzureOpenAI: 'ExternalSystem', AzureCognitiveServices: 'ExternalSystem',
      };
      const baseTypes = ['WebApplication', 'IdentityProvider', 'DataStore',
        'MonitoringService', 'Gateway', 'ExternalSystem', 'SecretStore'];
      const allComponentTypes = [...baseTypes, ...Object.keys(azureTypeMap)];
      for (const ctype of allComponentTypes) {
        this._findTypedBlocks(body, ctype).forEach(({ name: cname, body: cbody }) => {
          boundary.components.push(cname);
          const baseType = azureTypeMap[ctype] ?? ctype;
          model.components.push({
            name: cname,
            type: baseType,
            description: getAttr(cbody, 'description') || getDoc(cbody),
            isPubliclyAccessible: getAttr(cbody, 'isPubliclyAccessible') === 'true',
            authentication: getAttr(cbody, 'authentication'),
            encryption: getAttr(cbody, 'encryption'),
            dataClassification: getAttr(cbody, 'dataClassification') || undefined,
            boundary: name,
          });
        });
      }

      // Find threat actors inside boundary (both ThreatActor and Actor types)
      for (const actorType of ['ThreatActor', 'Actor']) {
        this._findTypedBlocks(body, actorType).forEach(({ name: aname, body: abody }) => {
          boundary.actors.push(aname);
          model.actors.push({
            name: aname,
            description: getAttr(abody, 'description') || getDoc(abody),
            motivation: getAttr(abody, 'motivation'),
            capability: getAttr(abody, 'capability'),
            boundary: name,
          });
        });
      }

      model.boundaries.push(boundary);
    });

    // Extract data flows from occurrence defs
    const flowRe = /(?:then\s+)?succession\s+flow\s+(\w+)\s+of\s+(\w+)\s*\n\s*from\s+[\w.]+\.(\w+)\s*\n\s*to\s+[\w.]+\.(\w+)\s*\{([\s\S]*?)\}/g;
    let fm: RegExpExecArray | null;
    while ((fm = flowRe.exec(cleaned)) !== null) {
      const flowBody = fm[5];
      const strideMatch = flowBody.match(/@StrideTag\s*\{([\s\S]*?)\}/);
      let stride: DataFlow['stride'];
      if (strideMatch) {
        stride = {
          category: getAttr(strideMatch[1], 'category') || '',
          severity: getAttr(strideMatch[1], 'severity') || '',
          likelihood: getAttr(strideMatch[1], 'likelihood') || '',
        };
      }
      model.dataFlows.push({
        name: fm[1],
        from: fm[3],
        to: fm[4],
        itemType: fm[2],
        description: getDoc(flowBody),
        stride,
      });
    }

    // Extract threats (concern ... : Threat)
    this._findTypedBlocks(cleaned, 'Threat').forEach(({ name: tname, body: tbody }) => {
      // Extract target component from subject :>> target = path.to.component
      const targetMatch = tbody.match(/subject\s+:>>\s*target\s*=\s*([\w.]+)/);
      const targetComponent = targetMatch
        ? targetMatch[1].split('.').pop() ?? ''
        : '';
      model.threats.push({
        name: tname,
        description: getDoc(tbody),
        strideCategory: getAttr(tbody, 'strideCategory'),
        severity: getAttr(tbody, 'severity'),
        likelihood: getAttr(tbody, 'likelihood'),
        targetDescription: getAttr(tbody, 'targetDescription'),
        targetComponent,
      });
    });

    // Extract mitigations (requirement ... : SecurityRequirement)
    this._findTypedBlocks(cleaned, 'SecurityRequirement').forEach(({ name: mname, body: mbody }) => {
      const targetMatch = mbody.match(/subject\s+:>>\s*target\s*=\s*([\w.]+)/);
      const targetThreat = targetMatch ? targetMatch[1] : '';
      model.mitigations.push({
        name: mname,
        description: getDoc(mbody),
        isImplemented: getAttr(mbody, 'isImplemented') === 'true',
        targetThreat,
      });
    });

    return model;
  }

  /**
   * Find blocks like `part/concern/requirement NAME : TYPE { ... }`
   * with proper brace matching.
   */
  private _findTypedBlocks(text: string, typeName: string): { name: string; body: string }[] {
    const results: { name: string; body: string }[] = [];
    const re = new RegExp(`(?:part|concern|requirement|allocation)\\s+(\\w+)\\s*:\\s*(?:\\w+\\.)?${typeName}\\b`, 'g');
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      const name = m[1];
      // Find the opening brace
      const afterMatch = text.indexOf('{', m.index + m[0].length);
      if (afterMatch === -1) { continue; }
      // Brace-match to find the closing brace
      let depth = 1;
      let pos = afterMatch + 1;
      while (pos < text.length && depth > 0) {
        if (text[pos] === '{') { depth++; }
        else if (text[pos] === '}') { depth--; }
        pos++;
      }
      const body = text.substring(afterMatch + 1, pos - 1);
      results.push({ name, body });
    }
    return results;
  }

  // ── Rendering ──────────────────────────────────────────────────

  private async _render(): Promise<void> {
    const text = await this._readFiles();
    if (!text.trim()) {
      this._panel.webview.html = this._emptyHtml('No SysML threat model files found');
      return;
    }
    const model = this._parse(text);
    if (model.boundaries.length === 0 && model.components.length === 0 && model.threats.length === 0) {
      this._panel.webview.html = this._emptyHtml('No threat model elements found in the SysML files');
      return;
    }
    this._panel.webview.html = this._buildHtml(model);
  }

  private _emptyHtml(message: string): string {
    return `<!DOCTYPE html>
<html><head>
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline';">
<style>
body { font-family: var(--vscode-font-family, sans-serif); color: var(--vscode-foreground);
       background: var(--vscode-editor-background); padding: 40px; display: flex;
       align-items: center; justify-content: center; height: 80vh; }
p { opacity: 0.6; font-style: italic; text-align: center; font-size: 14px; }
</style></head><body><p>${this._esc(message)}</p></body></html>`;
  }

  private _esc(s: string): string {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  private _nonce(): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let v = '';
    for (let i = 0; i < 16; i++) { v += chars.charAt(Math.floor(Math.random() * chars.length)); }
    return v;
  }

  // STRIDE colour helper
  private _strideColor(cat: string): string {
    const map: Record<string, string> = {
      spoofing: '#e57373',
      tampering: '#ff8a65',
      repudiation: '#ffb74d',
      informationDisclosure: '#4fc3f7',
      denialOfService: '#ba68c8',
      elevationOfPrivilege: '#ef5350',
    };
    return map[cat] ?? '#90a4ae';
  }

  private _strideLabel(cat: string): string {
    const map: Record<string, string> = {
      spoofing: 'Spoofing',
      tampering: 'Tampering',
      repudiation: 'Repudiation',
      informationDisclosure: 'Info Disclosure',
      denialOfService: 'Denial of Service',
      elevationOfPrivilege: 'Elevation of Privilege',
    };
    return map[cat] ?? cat;
  }

  private _severityColor(sev: string): string {
    const map: Record<string, string> = {
      critical: '#ef5350',
      high: '#ff8a65',
      medium: '#ffb74d',
      low: '#4fc3f7',
      informational: '#81c784',
    };
    return map[sev] ?? '#90a4ae';
  }

  private _likelihoodColor(lh: string): string {
    const map: Record<string, string> = {
      almostCertain: '#ef5350',
      likely: '#ff8a65',
      possible: '#ffb74d',
      unlikely: '#4fc3f7',
      rare: '#81c784',
    };
    return map[lh] ?? '#90a4ae';
  }

  private _componentIcon(type: string): string {
    const map: Record<string, string> = {
      WebApplication: '🌐',
      IdentityProvider: '🔑',
      DataStore: '🗄️',
      MonitoringService: '📊',
      Gateway: '🛡️',
      ExternalSystem: '🔗',
      SecretStore: '🔒',
    };
    return map[type] ?? '📦';
  }

  private _buildHtml(model: ThreatModel): string {
    const nonce = this._nonce();
    const webview = this._panel.webview;

    // Vendor script URIs for Cytoscape + ELK
    const cytoscapeUri = webview.asWebviewUri(vscode.Uri.joinPath(this._extensionUri, 'media', 'vendor', 'cytoscape.min.js'));
    const elkUri = webview.asWebviewUri(vscode.Uri.joinPath(this._extensionUri, 'media', 'vendor', 'elk.bundled.js'));
    const cytoscapeElkUri = webview.asWebviewUri(vscode.Uri.joinPath(this._extensionUri, 'media', 'vendor', 'cytoscape-elk.js'));

    // ── Stats ──
    const totalThreats = model.threats.length;
    const criticalThreats = model.threats.filter(t => t.severity === 'critical').length;
    const highThreats = model.threats.filter(t => t.severity === 'high').length;
    const mediumThreats = model.threats.filter(t => t.severity === 'medium').length;
    const implementedMitigations = model.mitigations.filter(m => m.isImplemented).length;
    const totalMitigations = model.mitigations.length;
    const mitigationPct = totalMitigations > 0 ? Math.round((implementedMitigations / totalMitigations) * 100) : 0;

    // ── STRIDE distribution ──
    const strideCounts = new Map<string, number>();
    for (const t of model.threats) {
      strideCounts.set(t.strideCategory, (strideCounts.get(t.strideCategory) ?? 0) + 1);
    }

    // ── Risk matrix ──
    const severities = ['critical', 'high', 'medium', 'low', 'informational'];
    const likelihoods = ['almostCertain', 'likely', 'possible', 'unlikely', 'rare'];
    const riskMatrix: Record<string, Record<string, number>> = {};
    for (const s of severities) {
      riskMatrix[s] = {};
      for (const l of likelihoods) {
        riskMatrix[s][l] = model.threats.filter(t => t.severity === s && t.likelihood === l).length;
      }
    }

    // ── Build Cytoscape graph data (JSON-safe) ──
    const cyData = this._buildCytoscapeData(model);
    const cyDataJson = JSON.stringify(cyData);

    // ── Build threats table rows ──
    const threatRows = model.threats.map(t => `
            <tr>
                <td class="threat-name">${this._esc(this._camelToTitle(t.name))}</td>
                <td><span class="stride-badge" style="background:${this._strideColor(t.strideCategory)}">${this._esc(this._strideLabel(t.strideCategory))}</span></td>
                <td><span class="sev-badge" style="background:${this._severityColor(t.severity)}">${this._esc(t.severity)}</span></td>
                <td><span class="lh-badge" style="background:${this._likelihoodColor(t.likelihood)}">${this._esc(t.likelihood)}</span></td>
                <td>${this._esc(t.targetDescription || t.targetComponent)}</td>
                <td class="threat-desc">${this._esc(t.description)}</td>
            </tr>`).join('');

    // ── Mitigations list ──
    const mitigationItems = model.mitigations.map(m => `
            <div class="mit-item ${m.isImplemented ? 'mit-done' : 'mit-pending'}">
                <span class="mit-check">${m.isImplemented ? '✅' : '⬜'}</span>
                <div class="mit-body">
                    <div class="mit-name">${this._esc(this._camelToTitle(m.name))}</div>
                    <div class="mit-desc">${this._esc(m.description)}</div>
                    <div class="mit-target">Mitigates: ${this._esc(this._camelToTitle(m.targetThreat))}</div>
                </div>
            </div>`).join('');

    // ── Actors cards ──
    const actorCards = model.actors.map(a => `
            <div class="actor-card">
                <div class="actor-icon">👤</div>
                <div class="actor-name">${this._esc(this._camelToTitle(a.name))}</div>
                <div class="actor-desc">${this._esc(a.description)}</div>
                <div class="actor-tags">
                    <span class="tag">Motivation: ${this._esc(a.motivation)}</span>
                    <span class="tag">Capability: ${this._esc(a.capability)}</span>
                </div>
            </div>`).join('');

    // ── Severity summary ──
    const riskScore = criticalThreats * 4 + highThreats * 3 + mediumThreats * 2;
    const maxRiskScore = totalThreats * 4;
    const riskPct = maxRiskScore > 0 ? Math.round((riskScore / maxRiskScore) * 100) : 0;
    const riskLevel = riskPct >= 75 ? 'Critical' : riskPct >= 50 ? 'High' : riskPct >= 25 ? 'Medium' : 'Low';
    const riskColor = riskPct >= 75 ? '#ef5350' : riskPct >= 50 ? '#ff8a65' : riskPct >= 25 ? '#ffb74d' : '#81c784';

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${webview.cspSource} 'unsafe-inline'; script-src 'nonce-${nonce}'; img-src ${webview.cspSource} data:;">
<script nonce="${nonce}" src="${cytoscapeUri}"></script>
<script nonce="${nonce}" src="${elkUri}"></script>
<script nonce="${nonce}" src="${cytoscapeElkUri}"></script>
<style>
:root {
    --bg: var(--vscode-editor-background);
    --fg: var(--vscode-foreground);
    --border: var(--vscode-panel-border, #444);
    --subtle: var(--vscode-descriptionForeground, #888);
    --header-bg: var(--vscode-sideBarSectionHeader-background, #252526);
    --accent: var(--vscode-textLink-foreground, #3794ff);
    --success: #89d185;
    --warning: #dca06e;
    --error: #f48771;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
    font-family: var(--vscode-font-family, 'Segoe UI', sans-serif);
    font-size: var(--vscode-font-size, 13px);
    color: var(--fg); background: var(--bg);
    padding: 24px; line-height: 1.5;
    max-width: 1100px; margin: 0 auto;
}

/* ── Header ── */
.tm-header { margin-bottom: 28px; }
.tm-header h1 { font-size: 22px; font-weight: 700; display: flex; align-items: center; gap: 10px; }
.tm-header .subtitle { font-size: 12px; color: var(--subtle); margin-top: 4px; max-width: 700px; }

/* ── Summary cards ── */
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-bottom: 28px; }
.card { background: var(--header-bg); border-radius: 10px; padding: 18px; border: 1px solid var(--border); }
.card-label { font-size: 10px; text-transform: uppercase; letter-spacing: 0.8px; color: var(--subtle); margin-bottom: 6px; }
.card-value { font-size: 30px; font-weight: 700; }
.card-detail { font-size: 11px; color: var(--subtle); margin-top: 4px; }
.coverage-bar { height: 8px; border-radius: 4px; background: var(--border); overflow: hidden; margin-top: 8px; }
.coverage-fill { height: 100%; border-radius: 4px; transition: width 0.3s; }

/* ── Section ── */
.section { margin-bottom: 32px; }
.section-title {
    font-size: 13px; text-transform: uppercase; letter-spacing: 0.8px;
    color: var(--subtle); margin-bottom: 14px;
    border-bottom: 1px solid var(--border); padding-bottom: 6px;
    display: flex; align-items: center; gap: 8px;
}
.section-title .icon { font-size: 16px; }

/* ── Architecture diagram (Cytoscape) ── */
.arch-container {
    background: var(--header-bg); border-radius: 10px; border: 1px solid var(--border);
    padding: 0; overflow: hidden;
}
#cy-arch { width: 100%; height: 420px; }

/* ── STRIDE distribution ── */
.stride-bars { display: flex; gap: 8px; flex-wrap: wrap; }
.stride-bar-item { flex: 1; min-width: 100px; text-align: center; }
.stride-bar-visual { height: 48px; border-radius: 6px; display: flex; align-items: flex-end; justify-content: center; position: relative; }
.stride-bar-fill { border-radius: 6px; width: 100%; position: absolute; bottom: 0; min-height: 28px; transition: height 0.3s; }
.stride-bar-count { position: relative; z-index: 1; font-weight: 700; font-size: 16px; padding: 4px 0; }
.stride-bar-label { font-size: 10px; color: var(--subtle); margin-top: 4px; text-transform: uppercase; }

/* ── Risk matrix ── */
.risk-matrix { display: inline-grid; gap: 2px; }
.risk-cell {
    width: 44px; height: 36px; border-radius: 4px; display: flex; align-items: center; justify-content: center;
    font-size: 13px; font-weight: 700; color: var(--bg);
}
.risk-cell.empty { background: transparent; color: var(--subtle); font-size: 10px; font-weight: 400; text-align: center; }
.risk-header { font-size: 9px; text-transform: uppercase; color: var(--subtle); text-align: center; white-space: nowrap; overflow: hidden; }
.risk-matrix-wrapper { display: flex; gap: 20px; align-items: flex-start; flex-wrap: wrap; }
.risk-legend { font-size: 11px; color: var(--subtle); line-height: 1.8; }

/* ── Threat actors ── */
.actor-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 12px; }
.actor-card { background: var(--header-bg); border-radius: 10px; padding: 16px; border: 1px solid var(--border); }
.actor-icon { font-size: 28px; margin-bottom: 6px; }
.actor-name { font-size: 14px; font-weight: 600; margin-bottom: 4px; }
.actor-desc { font-size: 12px; color: var(--subtle); margin-bottom: 8px; }
.actor-tags { display: flex; gap: 6px; flex-wrap: wrap; }
.tag { font-size: 10px; padding: 2px 8px; border-radius: 10px; background: var(--border); color: var(--fg); text-transform: capitalize; }

/* ── Data flows ── */
.flow-list { display: grid; gap: 8px; }
.flow-item {
    background: var(--header-bg); border-radius: 8px; padding: 12px 16px;
    border: 1px solid var(--border); display: flex; align-items: center; gap: 12px;
}
.flow-arrow { font-size: 14px; color: var(--accent); flex-shrink: 0; }
.flow-endpoints { font-size: 12px; font-weight: 600; white-space: nowrap; }
.flow-type { font-size: 10px; padding: 2px 8px; border-radius: 10px; background: var(--border); color: var(--subtle); }
.flow-desc { font-size: 11px; color: var(--subtle); flex: 1; }
.flow-stride { flex-shrink: 0; }

/* ── Threats table ── */
.threats-table { width: 100%; border-collapse: collapse; font-size: 12px; }
.threats-table th {
    text-align: left; font-size: 10px; text-transform: uppercase;
    letter-spacing: 0.6px; color: var(--subtle); padding: 8px;
    border-bottom: 2px solid var(--border); position: sticky; top: 0; background: var(--bg);
}
.threats-table td { padding: 10px 8px; border-bottom: 1px solid var(--border); vertical-align: top; }
.threats-table tr:hover { background: var(--header-bg); }
.threat-name { font-weight: 600; white-space: nowrap; }
.threat-desc { color: var(--subtle); max-width: 300px; }
.stride-badge, .sev-badge, .lh-badge {
    display: inline-block; padding: 2px 10px; border-radius: 10px;
    font-size: 10px; font-weight: 600; color: #111; text-transform: capitalize; white-space: nowrap;
}

/* ── Mitigations ── */
.mit-list { display: grid; gap: 8px; }
.mit-item {
    background: var(--header-bg); border-radius: 8px; padding: 12px 16px;
    border: 1px solid var(--border); display: flex; gap: 12px; align-items: flex-start;
}
.mit-item.mit-done { border-left: 3px solid var(--success); }
.mit-item.mit-pending { border-left: 3px solid var(--warning); }
.mit-check { font-size: 18px; flex-shrink: 0; margin-top: 2px; }
.mit-name { font-weight: 600; font-size: 13px; margin-bottom: 2px; }
.mit-desc { font-size: 12px; color: var(--subtle); }
.mit-target { font-size: 10px; color: var(--accent); margin-top: 4px; }

/* ── Tabs ── */
.tabs { display: flex; gap: 0; border-bottom: 2px solid var(--border); margin-bottom: 20px; }
.tab {
    padding: 8px 18px; cursor: pointer; font-size: 12px; font-weight: 600;
    color: var(--subtle); border-bottom: 2px solid transparent; margin-bottom: -2px;
    transition: color 0.2s, border-color 0.2s; user-select: none;
}
.tab:hover { color: var(--fg); }
.tab.active { color: var(--accent); border-bottom-color: var(--accent); }
.tab-content { display: none; }
.tab-content.active { display: block; }
</style>
</head>
<body>

<!-- Header -->
<div class="tm-header">
    <h1>🛡️ ${this._esc(model.packageName || 'Threat Model')}</h1>
    ${model.packageDoc ? `<div class="subtitle">${this._esc(model.packageDoc)}</div>` : ''}
</div>

<!-- Summary Cards -->
<div class="cards">
    <div class="card">
        <div class="card-label">Overall Risk</div>
        <div class="card-value" style="color:${riskColor}">${this._esc(riskLevel)}</div>
        <div class="card-detail">Risk score: ${riskScore} / ${maxRiskScore}</div>
        <div class="coverage-bar">
            <div class="coverage-fill" style="width:${riskPct}%; background:${riskColor}"></div>
        </div>
    </div>
    <div class="card">
        <div class="card-label">Threats</div>
        <div class="card-value">${totalThreats}</div>
        <div class="card-detail">${criticalThreats} critical · ${highThreats} high · ${mediumThreats} medium</div>
    </div>
    <div class="card">
        <div class="card-label">Components</div>
        <div class="card-value">${model.components.length}</div>
        <div class="card-detail">${model.boundaries.length} trust boundaries · ${model.actors.length} actors</div>
    </div>
    <div class="card">
        <div class="card-label">Mitigation Coverage</div>
        <div class="card-value">${mitigationPct}%</div>
        <div class="card-detail">${implementedMitigations} of ${totalMitigations} implemented</div>
        <div class="coverage-bar">
            <div class="coverage-fill" style="width:${mitigationPct}%; background:${mitigationPct >= 80 ? 'var(--success)' : mitigationPct >= 50 ? 'var(--warning)' : 'var(--error)'}"></div>
        </div>
    </div>
</div>

<!-- Tabs -->
<div class="tabs">
    <div class="tab active" data-tab="architecture">Architecture</div>
    <div class="tab" data-tab="threats">Threats</div>
    <div class="tab" data-tab="mitigations">Mitigations</div>
    <div class="tab" data-tab="risk">Risk Matrix</div>
</div>

<!-- Architecture Tab -->
<div class="tab-content active" id="tab-architecture">

    <!-- Architecture Diagram (Cytoscape + ELK) -->
    <div class="section">
        <div class="section-title"><span class="icon">🏗️</span> Architecture Overview</div>
        <div class="arch-container"><div id="cy-arch"></div></div>
    </div>

    <!-- Threat Actors -->
    ${model.actors.length > 0 ? `
    <div class="section">
        <div class="section-title"><span class="icon">👤</span> Threat Actors</div>
        <div class="actor-cards">${actorCards}</div>
    </div>` : ''}

    <!-- Data Flows -->
    ${model.dataFlows.length > 0 ? `
    <div class="section">
        <div class="section-title"><span class="icon">🔀</span> Data Flows</div>
        <div class="flow-list">
            ${model.dataFlows.map(f => `
            <div class="flow-item">
                <div class="flow-endpoints">${this._esc(this._camelToTitle(f.from))}</div>
                <div class="flow-arrow">→</div>
                <div class="flow-endpoints">${this._esc(this._camelToTitle(f.to))}</div>
                <span class="flow-type">${this._esc(f.itemType)}</span>
                <div class="flow-desc">${this._esc(f.description)}</div>
                ${f.stride ? `<span class="stride-badge flow-stride" style="background:${this._strideColor(f.stride.category)}">${this._esc(this._strideLabel(f.stride.category))}</span>` : ''}
            </div>`).join('')}
        </div>
    </div>` : ''}
</div>

<!-- Threats Tab -->
<div class="tab-content" id="tab-threats">

    <!-- STRIDE Distribution -->
    <div class="section">
        <div class="section-title"><span class="icon">📊</span> STRIDE Distribution</div>
        <div class="stride-bars">
            ${['spoofing', 'tampering', 'repudiation', 'informationDisclosure', 'denialOfService', 'elevationOfPrivilege'].map(cat => {
      const count = strideCounts.get(cat) ?? 0;
      const maxCount = Math.max(...strideCounts.values(), 1);
      const pct = Math.round((count / maxCount) * 100);
      return `
            <div class="stride-bar-item">
                <div class="stride-bar-visual">
                    <div class="stride-bar-fill" style="height:${Math.max(pct, 5)}%; background:${this._strideColor(cat)}; opacity:0.7;"></div>
                    <div class="stride-bar-count">${count}</div>
                </div>
                <div class="stride-bar-label">${this._esc(this._strideLabel(cat))}</div>
            </div>`;
    }).join('')}
        </div>
    </div>

    <!-- Threats Table -->
    <div class="section">
        <div class="section-title"><span class="icon">⚠️</span> Threat Assessment</div>
        <table class="threats-table">
            <thead>
                <tr>
                    <th>Threat</th>
                    <th>STRIDE</th>
                    <th>Severity</th>
                    <th>Likelihood</th>
                    <th>Target</th>
                    <th>Description</th>
                </tr>
            </thead>
            <tbody>${threatRows}</tbody>
        </table>
    </div>
</div>

<!-- Mitigations Tab -->
<div class="tab-content" id="tab-mitigations">
    <div class="section">
        <div class="section-title"><span class="icon">🔧</span> Security Controls (${implementedMitigations}/${totalMitigations} implemented)</div>
        <div class="mit-list">${mitigationItems}</div>
    </div>
</div>

<!-- Risk Matrix Tab -->
<div class="tab-content" id="tab-risk">
    <div class="section">
        <div class="section-title"><span class="icon">🎯</span> Risk Heat Map (Severity × Likelihood)</div>
        <div class="risk-matrix-wrapper">
            <div>
                <div class="risk-matrix" style="grid-template-columns: 80px repeat(${likelihoods.length}, 44px);">
                    <div class="risk-cell empty"></div>
                    ${likelihoods.map(l => `<div class="risk-header">${this._esc(this._camelToTitle(l))}</div>`).join('')}
                    ${severities.map(s => `
                        <div class="risk-header" style="text-align:right; padding-right:8px; line-height:36px;">${this._esc(s)}</div>
                        ${likelihoods.map(l => {
      const count = riskMatrix[s]?.[l] ?? 0;
      const intensity = this._riskIntensity(s, l);
      return `<div class="risk-cell" style="background:${intensity}">${count || ''}</div>`;
    }).join('')}
                    `).join('')}
                </div>
            </div>
            <div class="risk-legend">
                <strong>Risk Level Legend</strong><br>
                🟥 Critical risk — immediate action required<br>
                🟧 High risk — prioritize mitigation<br>
                🟨 Medium risk — plan remediation<br>
                🟩 Low risk — accept or monitor
            </div>
        </div>
    </div>
</div>

<script nonce="${nonce}">
(function() {
    const vscode = acquireVsCodeApi();

    // ── Tab switching ──
    const tabs = document.querySelectorAll('.tab');
    const contents = document.querySelectorAll('.tab-content');
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            const target = tab.getAttribute('data-tab');
            tabs.forEach(t => t.classList.remove('active'));
            contents.forEach(c => c.classList.remove('active'));
            tab.classList.add('active');
            const el = document.getElementById('tab-' + target);
            if (el) el.classList.add('active');
        });
    });

    // ── Cytoscape architecture diagram ──
    const graphData = ${cyDataJson};

    // Colour helpers
    const strideColors = {
        spoofing: '#e57373', tampering: '#ff8a65', repudiation: '#ffb74d',
        informationDisclosure: '#4fc3f7', denialOfService: '#ba68c8', elevationOfPrivilege: '#ef5350'
    };

    // Build Cytoscape elements with compound parents for boundaries
    const cyElements = [];

    // Boundary compound nodes
    graphData.boundaries.forEach(b => {
        cyElements.push({
            group: 'nodes',
            data: {
                id: 'boundary-' + b.name,
                label: b.label,
                nodeType: 'boundary',
            }
        });
    });

    // Actor nodes
    graphData.actors.forEach(a => {
        cyElements.push({
            group: 'nodes',
            data: {
                id: 'actor-' + a.name,
                label: a.label,
                nodeType: 'actor',
                parent: 'boundary-' + a.boundary
            }
        });
    });

    // Component nodes
    graphData.components.forEach(c => {
        cyElements.push({
            group: 'nodes',
            data: {
                id: 'comp-' + c.name,
                label: c.label,
                nodeType: 'component',
                compType: c.type,
                icon: c.icon,
                threatCount: c.threatCount,
                isPublic: c.isPublic,
                parent: 'boundary-' + c.boundary
            }
        });
    });

    // Data flow edges
    graphData.flows.forEach(f => {
        const srcId = graphData.components.find(c => c.name === f.from)
            ? 'comp-' + f.from
            : 'actor-' + f.from;
        const tgtId = graphData.components.find(c => c.name === f.to)
            ? 'comp-' + f.to
            : 'actor-' + f.to;
        const edgeData = {
            id: 'flow-' + f.name,
            source: srcId,
            target: tgtId,
            label: f.itemType,
            flowName: f.name,
            seq: f.seq,
        };
        if (f.strideCategory) {
            edgeData.strideCategory = f.strideCategory;
            edgeData.strideLabel = f.strideLabel;
        }
        cyElements.push({ group: 'edges', data: edgeData });
    });

    // Colour palette
    const fgColor = getComputedStyle(document.documentElement).getPropertyValue('--fg').trim() || '#ccc';
    const subtleColor = getComputedStyle(document.documentElement).getPropertyValue('--subtle').trim() || '#888';
    const headerBg = getComputedStyle(document.documentElement).getPropertyValue('--header-bg').trim() || '#252526';
    const borderColor = getComputedStyle(document.documentElement).getPropertyValue('--border').trim() || '#444';

    const cy = cytoscape({
        container: document.getElementById('cy-arch'),
        elements: cyElements,
        minZoom: 0.3,
        maxZoom: 3,
        wheelSensitivity: 0.3,
        boxSelectionEnabled: false,
        style: [
            // ── Boundary (compound parent) ──
            {
                selector: 'node[nodeType="boundary"]',
                style: {
                    'shape': 'roundrectangle',
                    'background-color': 'transparent',
                    'background-opacity': 0,
                    'border-width': 2,
                    'border-style': 'dashed',
                    'border-color': fgColor,
                    'border-opacity': 0.35,
                    'label': 'data(label)',
                    'text-valign': 'top',
                    'text-halign': 'center',
                    'font-size': 12,
                    'font-weight': 600,
                    'color': fgColor,
                    'text-opacity': 0.6,
                    'text-margin-y': -5,
                    'padding': '40px',
                    'compound-sizing-wrt-labels': 'include',
                }
            },
            // ── Actor ──
            {
                selector: 'node[nodeType="actor"]',
                style: {
                    'shape': 'roundrectangle',
                    'width': 140,
                    'height': 55,
                    'background-color': headerBg,
                    'border-width': 2,
                    'border-color': '#e57373',
                    'label': 'data(label)',
                    'text-valign': 'center',
                    'text-halign': 'center',
                    'font-size': 11,
                    'font-weight': 600,
                    'color': fgColor,
                    'text-wrap': 'wrap',
                    'text-max-width': '120px',
                }
            },
            // ── Component ──
            {
                selector: 'node[nodeType="component"]',
                style: {
                    'shape': 'roundrectangle',
                    'width': 170,
                    'height': 60,
                    'background-color': headerBg,
                    'border-width': 1,
                    'border-color': borderColor,
                    'label': 'data(label)',
                    'text-valign': 'center',
                    'text-halign': 'center',
                    'font-size': 11,
                    'font-weight': 600,
                    'color': fgColor,
                    'text-wrap': 'wrap',
                    'text-max-width': '150px',
                }
            },
            // ── Component with threats ──
            {
                selector: 'node[nodeType="component"][threatCount > 0]',
                style: {
                    'border-width': 2,
                    'border-color': '#ff8a65',
                }
            },
            // ── Default edge ──
            {
                selector: 'edge',
                style: {
                    'width': 2,
                    'line-color': borderColor,
                    'line-opacity': 0.7,
                    'target-arrow-color': borderColor,
                    'target-arrow-shape': 'triangle',
                    'arrow-scale': 1,
                    'curve-style': 'bezier',
                    'label': function(ele) { return ele.data('seq') + '. ' + ele.data('label'); },
                    'font-size': 10,
                    'color': fgColor,
                    'text-margin-y': -10,
                    'text-opacity': 0.95,
                    'text-background-color': headerBg,
                    'text-background-opacity': 0.9,
                    'text-background-padding': '4px',
                    'text-background-shape': 'roundrectangle',
                }
            },
            // ── STRIDE-tagged edge ──
            {
                selector: 'edge[strideCategory]',
                style: {
                    'width': 2.5,
                    'line-opacity': 0.85,
                    'line-color': function(ele) { return strideColors[ele.data('strideCategory')] || '#ff8a65'; },
                    'target-arrow-color': function(ele) { return strideColors[ele.data('strideCategory')] || '#ff8a65'; },
                    'label': function(ele) { return ele.data('seq') + '. ' + ele.data('label') + '  \u26A0 ' + ele.data('strideLabel'); },
                    'color': function(ele) { return strideColors[ele.data('strideCategory')] || '#ff8a65'; },
                    'text-opacity': 1,
                    'font-weight': 600,
                    'text-background-color': headerBg,
                    'text-background-opacity': 0.95,
                    'text-background-padding': '4px',
                    'text-background-shape': 'roundrectangle',
                }
            },
        ],
        layout: { name: 'preset' },
    });

    // ── Run ELK directly to get both node positions AND edge bend points ──
    const elk = new ELK();

    // Build ELK graph from Cytoscape elements
    function buildElkGraph() {
        const boundaryChildren = {};
        graphData.boundaries.forEach(b => {
            boundaryChildren[b.name] = [];
        });

        // Collect leaf nodes per boundary
        cy.nodes().forEach(n => {
            if (n.data('nodeType') === 'boundary') return;
            const parentId = n.data('parent');
            if (!parentId) return;
            const bName = parentId.replace('boundary-', '');
            if (boundaryChildren[bName]) {
                const w = n.data('nodeType') === 'actor' ? 140 : 170;
                const h = n.data('nodeType') === 'actor' ? 55 : 60;
                boundaryChildren[bName].push({ id: n.id(), width: w, height: h });
            }
        });

        const children = graphData.boundaries.map(b => ({
            id: 'boundary-' + b.name,
            layoutOptions: {
                'elk.algorithm': 'layered',
                'elk.direction': 'RIGHT',
                'elk.spacing.nodeNode': '50',
                'elk.layered.spacing.nodeNodeBetweenLayers': '100',
                'elk.spacing.edgeNode': '30',
                'elk.spacing.edgeEdge': '20',
                'elk.padding': '[top=40,left=40,bottom=40,right=40]',
            },
            children: boundaryChildren[b.name] || [],
        }));

        const edges = [];
        cy.edges().forEach(e => {
            edges.push({ id: e.id(), sources: [e.data('source')], targets: [e.data('target')] });
        });

        return {
            id: 'root',
            layoutOptions: {
                'elk.algorithm': 'layered',
                'elk.direction': 'RIGHT',
                'elk.hierarchyHandling': 'INCLUDE_CHILDREN',
                'elk.spacing.nodeNode': '50',
                'elk.layered.spacing.nodeNodeBetweenLayers': '100',
                'elk.spacing.edgeNode': '30',
                'elk.spacing.edgeEdge': '20',
                'elk.layered.nodePlacement.strategy': 'NETWORK_SIMPLEX',
                'elk.layered.considerModelOrder.strategy': 'NODES_AND_EDGES',
                'elk.layered.crossingMinimization.strategy': 'LAYER_SWEEP',
                'elk.padding': '[top=50,left=50,bottom=50,right=50]',
            },
            children: children,
            edges: edges,
        };
    }

    const elkGraph = buildElkGraph();

    elk.layout(elkGraph).then(function(result) {
        // Collect all node positions from the hierarchical result
        const positions = {};
        function collectPositions(node, offsetX, offsetY) {
            if (node.children) {
                node.children.forEach(function(child) {
                    const cx = offsetX + (child.x || 0);
                    const cy = offsetY + (child.y || 0);
                    // Position is top-left in ELK, convert to center for Cytoscape
                    positions[child.id] = {
                        x: cx + (child.width || 0) / 2,
                        y: cy + (child.height || 0) / 2,
                    };
                    collectPositions(child, cx, cy);
                });
            }
        }
        collectPositions(result, 0, 0);

        // Apply node positions
        cy.nodes().forEach(function(n) {
            if (n.data('nodeType') === 'boundary') return;
            const pos = positions[n.id()];
            if (pos) {
                n.position(pos);
            }
        });

        cy.fit(undefined, 30);
    });
})();
</script>

</body>
</html>`;
  }

  private _riskIntensity(severity: string, likelihood: string): string {
    const sevScore: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, informational: 1 };
    const lhScore: Record<string, number> = { almostCertain: 5, likely: 4, possible: 3, unlikely: 2, rare: 1 };
    const combined = (sevScore[severity] ?? 1) * (lhScore[likelihood] ?? 1);
    // 1-25 scale → color
    if (combined >= 20) { return '#ef5350'; }
    if (combined >= 12) { return '#ff8a65'; }
    if (combined >= 6) { return '#ffb74d'; }
    if (combined >= 3) { return 'rgba(129, 199, 132, 0.7)'; }
    return 'rgba(129, 199, 132, 0.3)';
  }

  private _camelToTitle(s: string): string {
    return s.replace(/([A-Z])/g, ' $1').replace(/^./, c => c.toUpperCase()).trim();
  }

  // ── Cytoscape graph data builder ─────────────────────────────

  private _buildCytoscapeData(model: ThreatModel): {
    boundaries: { name: string; label: string }[];
    actors: { name: string; label: string; boundary: string }[];
    components: { name: string; label: string; type: string; icon: string; boundary: string; threatCount: number; isPublic: boolean }[];
    flows: { seq: number; name: string; from: string; to: string; itemType: string; strideCategory?: string; strideLabel?: string }[];
  } {
    const boundaries = model.boundaries.map(b => ({
      name: b.name,
      label: this._camelToTitle(b.name),
    }));

    const actors = model.actors.map(a => ({
      name: a.name,
      label: `👤 ${this._camelToTitle(a.name)}`,
      boundary: a.boundary,
    }));

    const components = model.components.map(c => ({
      name: c.name,
      label: `${this._componentIcon(c.type)} ${this._camelToTitle(c.name)}`,
      type: c.type,
      icon: this._componentIcon(c.type),
      boundary: c.boundary,
      threatCount: model.threats.filter(t => t.targetComponent === c.name).length,
      isPublic: c.isPubliclyAccessible,
    }));

    const flows = model.dataFlows.map((f, i) => ({
      seq: i + 1,
      name: f.name,
      from: f.from,
      to: f.to,
      itemType: f.itemType,
      strideCategory: f.stride?.category,
      strideLabel: f.stride ? this._strideLabel(f.stride.category) : undefined,
    }));

    return { boundaries, actors, components, flows };
  }
}
