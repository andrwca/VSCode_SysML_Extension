/** Shared types between the extension host and the webview. */

export interface ToolboxParam {
  name: string;
  type: 'string' | 'boolean' | 'enum';
  enumType?: string;
  enumValues?: string[];
  default?: string;
}

export interface ToolboxItem {
  id: string;
  category: string;
  name: string;
  defType: string;
  usageKeyword: string;
  sysmlType: string;
  description: string;
  icon: string;
  importPackage: string;
  params: ToolboxParam[];
}

export interface ToolboxCategory {
  id: string;
  label: string;
  icon: string;
  description: string;
  items: ToolboxItem[];
}

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
  from: string;
  fromPath: string;
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

/** Messages from webview → extension. */
export type WebviewMessage =
  | { command: 'drop'; sysmlType: string; partName: string; x: number; y: number; boundary?: string; attrValues?: Record<string, string> }
  | { command: 'move'; partName: string; x: number; y: number; width?: number; height?: number }
  | { command: 'delete'; partName: string }
  | { command: 'deleteFlow'; flowName: string }
  | { command: 'newFile'; packageName: string }
  | { command: 'createFlow'; sequenceName: string; flowName: string; dataType: string; fromPart: string; toPart: string; addStride: boolean }
  | { command: 'updateProperties'; partName: string; attributes: Record<string, string> }
  | { command: 'requestUpdate' };

/** Messages from extension → webview. */
export type ExtensionMessage =
  | { type: 'update'; model: ParsedModel; positions: NodePosition[] };

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

/** Map flow occurrence types → item data types. */
export const FLOW_DATA_TYPE_MAP: Record<string, string> = {
  HttpFlow: 'HttpRequest',
  AuthFlow: 'AuthToken',
  DatabaseFlow: 'DatabaseQuery',
  TelemetryFlow: 'TelemetryPayload',
  SecretFlow: 'Credential',
  GenericFlow: 'HttpRequest',
};

export const DATA_TYPES = [
  'HttpRequest', 'HttpResponse', 'AuthToken',
  'DatabaseQuery', 'DatabaseResult', 'TelemetryPayload', 'Credential',
] as const;
