import * as vscode from 'vscode';

// ── Toolbox types ────────────────────────────────────────────────

export interface ToolboxParam {
  name: string;
  type: 'string' | 'boolean' | 'enum';
  enumType?: string;      // e.g. 'AuthenticationKind'
  enumValues?: string[];  // e.g. ['none', 'apiKey', ...]
  default?: string;       // default value for new elements
}

export interface ToolboxItem {
  id: string;
  category: string;
  name: string;
  defType: string;       // 'part def', 'concern def', etc.
  usageKeyword: string;  // 'part', 'concern', 'requirement', etc.
  sysmlType: string;     // 'WebApplication', 'ThreatActor', etc.
  description: string;
  icon: string;
  importPackage: string; // which package to import
  params: ToolboxParam[];
}

export interface ToolboxCategory {
  id: string;
  label: string;
  icon: string;
  description: string;
  items: ToolboxItem[];
}

// ── Model types ──────────────────────────────────────────────────

export interface NodePosition {
  partName: string;
  x: number;
  y: number;
  width?: number;
  height?: number;
}

export interface ParsedElement {
  name: string;
  type: string;
  description: string;
  boundary?: string;
  attributes: Record<string, string>;
}

export interface ParsedFlow {
  name: string;
  dataType: string;
  from: string;          // last segment of the path (e.g. 'appService')
  fromPath: string;      // full SysML path (e.g. 'basicWebApp.azurePlatformBoundary.appService')
  to: string;
  toPath: string;
  description: string;
  stride?: { category: string; severity: string; likelihood: string };
}

export interface ParsedSequence {
  name: string;
  description: string;
  flows: ParsedFlow[];
}

export interface ParsedModel {
  packageName: string;
  boundaries: { name: string; description: string; children: string[] }[];
  components: ParsedElement[];
  actors: ParsedElement[];
  threats: ParsedElement[];
  mitigations: ParsedElement[];
  sequences: ParsedSequence[];
}

// ── Icon map ─────────────────────────────────────────────────────

export const TYPE_ICONS: Record<string, string> = {
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

// ── Extension context type (avoids importing vscode in pure modules) ──

export type ExtensionUri = vscode.Uri;
