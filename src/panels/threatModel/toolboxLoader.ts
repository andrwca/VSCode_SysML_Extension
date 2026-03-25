/**
 * Toolbox loader — scans `.threat/*.sysml` files for `@toolbox-*` metadata
 * and builds the categorised drag-and-drop toolbox.
 */

import * as vscode from 'vscode';
import { extractDoc, findBlockEnd } from './documentParser';
import type { ToolboxCategory, ToolboxItem, ToolboxParam } from './types';
import { TYPE_ICONS } from './types';

/** Transient map to hold per-category sort keys during loading. */
const categoryOrder = new Map<string, number>();

let cache: ToolboxCategory[] | undefined;

/** Clear the cached toolbox (e.g. when .threat files change). */
export function clearToolboxCache(): void { cache = undefined; }

/** Resolved enum defs: enumTypeName → variant names. */
let enumMap: Map<string, string[]> | undefined;

/** Abstract base def bodies: typeName → body text. */
let abstractBodies: Map<string, string> | undefined;

/**
 * Load all toolbox categories from `.threat/*.sysml` files bundled
 * with the extension.
 */
export async function loadToolbox(extensionUri: vscode.Uri): Promise<ToolboxCategory[]> {
  if (cache) { return cache; }

  const threatDir = vscode.Uri.joinPath(extensionUri, '.threat');
  const categories: ToolboxCategory[] = [];

  let fileNames: string[];
  try {
    const dirEntries = await vscode.workspace.fs.readDirectory(threatDir);
    fileNames = dirEntries
      .filter(([name, type]) => name.endsWith('.sysml') && type === vscode.FileType.File)
      .map(([name]) => name);
  } catch (err) {
    console.error('Threat toolbox: cannot read .threat directory:', err);
    cache = [];
    return [];
  }

  // First pass: read all file contents for enum + abstract resolution
  const fileContents = new Map<string, string>();
  for (const fileName of fileNames) {
    try {
      const fileUri = vscode.Uri.joinPath(threatDir, fileName);
      const raw = await vscode.workspace.fs.readFile(fileUri);
      fileContents.set(fileName, Buffer.from(raw).toString('utf-8'));
    } catch (err) {
      console.error(`Threat toolbox: failed to read ${fileName}:`, err);
    }
  }

  // Build enum map and abstract body map from ALL file contents
  enumMap = new Map();
  abstractBodies = new Map();
  for (const content of fileContents.values()) {
    parseEnumDefs(content, enumMap);
    parseAbstractDefs(content, abstractBodies);
  }

  // Second pass: build toolbox categories
  for (const [, content] of fileContents) {
    const meta = parseFileMetadata(content);
    if (meta.hidden || !meta.category) { continue; }

    const items = parseToolboxDefs(content, meta.category);
    if (items.length > 0) {
      categories.push({
        id: meta.category,
        label: meta.label || meta.category,
        icon: meta.icon || '📦',
        description: meta.description || '',
        items,
      });
    }
  }

  categories.sort((a, b) => {
    const oa = categoryOrder.get(a.id) ?? 50;
    const ob = categoryOrder.get(b.id) ?? 50;
    return oa - ob;
  });

  // Phase 4: only include items that are part defs (components, boundaries, actors)
  const filtered = categories
    .map(cat => ({
      ...cat,
      items: cat.items.filter(item => item.usageKeyword === 'part'),
    }))
    .filter(cat => cat.items.length > 0);

  cache = filtered;
  return filtered;
}

// ── Enum & abstract resolution ───────────────────────────────────

function parseEnumDefs(text: string, map: Map<string, string[]>): void {
  const re = /enum\s+def\s+(\w+)\s*\{/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const name = m[1];
    const braceStart = m.index + m[0].length - 1;
    const braceEnd = findBlockEnd(text, braceStart);
    const body = text.substring(braceStart + 1, braceEnd);
    const variants: string[] = [];
    const enumRe = /enum\s+(\w+)\s*;/g;
    let ev: RegExpExecArray | null;
    while ((ev = enumRe.exec(body)) !== null) {
      variants.push(ev[1]);
    }
    if (variants.length > 0) { map.set(name, variants); }
  }
}

function parseAbstractDefs(text: string, map: Map<string, string>): void {
  const re = /abstract\s+(?:part|concern|requirement)\s+def\s+(\w+)\s*\{/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const name = m[1];
    const braceStart = m.index + m[0].length - 1;
    const braceEnd = findBlockEnd(text, braceStart);
    map.set(name, text.substring(braceStart + 1, braceEnd));
  }
}

// ── Attribute parsing ────────────────────────────────────────────

const BOOLEAN_DEFAULTS: Record<string, string> = {
  isPubliclyAccessible: 'false',
  isImplemented: 'false',
  isParameterised: 'false',
  isEncrypted: 'false',
};

function parseAttributesFromBody(body: string): ToolboxParam[] {
  const params: ToolboxParam[] = [];
  const attrRe = /attribute\s+(\w+)\s*:\s*([\w:.]+)/g;
  let m: RegExpExecArray | null;
  while ((m = attrRe.exec(body)) !== null) {
    const attrName = m[1];
    const rawType = m[2];

    // Skip 'description' — handled specially in SysML generation
    if (attrName === 'description') { continue; }

    const typeName = rawType.replace(/^ScalarValues::/, '');

    if (typeName === 'Boolean') {
      params.push({
        name: attrName,
        type: 'boolean',
        default: BOOLEAN_DEFAULTS[attrName] ?? 'false',
      });
    } else if (enumMap?.has(typeName)) {
      const variants = enumMap.get(typeName) ?? [];
      params.push({
        name: attrName,
        type: 'enum',
        enumType: typeName,
        enumValues: variants,
        default: variants[0],
      });
    } else {
      params.push({
        name: attrName,
        type: 'string',
        default: '',
      });
    }
  }
  return params;
}

// ── File metadata parsing ────────────────────────────────────────

interface FileMetadata {
  category: string; label: string; icon: string;
  description: string; order: number; hidden: boolean;
}

function parseFileMetadata(text: string): FileMetadata {
  const meta: FileMetadata = { category: '', label: '', icon: '', description: '', order: 50, hidden: false };
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
  if (meta.category) {
    categoryOrder.set(meta.category, meta.order);
  }
  return meta;
}

// ── Definition parsing ───────────────────────────────────────────

function parseToolboxDefs(text: string, category: string): ToolboxItem[] {
  const items: ToolboxItem[] = [];
  const pkgMatch = text.match(/package\s+(\w+)/);
  const importPkg = pkgMatch?.[1] ?? '';
  const lines = text.split('\n');

  const defRe = /((?:abstract\s+)?(?:part|concern|requirement|allocation|enum|item|port|metadata|occurrence)\s+def)\s+(\w+)(?:\s*:>\s*(\w+))?\s*\{/g;
  let m: RegExpExecArray | null;
  while ((m = defRe.exec(text)) !== null) {
    if (m[1].startsWith('abstract')) { continue; }

    const defType = m[1].replace(/^abstract\s+/, '');
    const name = m[2];
    const parent = m[3];

    const blockEnd = findBlockEnd(text, m.index + m[0].length - 1);
    const body = text.substring(m.index + m[0].length, blockEnd);
    const description = extractDoc(body);

    // Look for `// @toolbox-icon: X` on preceding lines
    const defLine = text.substring(0, m.index).split('\n').length - 1;
    let itemIcon = '';
    for (let i = defLine; i >= Math.max(0, defLine - 3); i--) {
      const iconMatch = lines[i]?.trim().match(/^\/\/\s*@toolbox-icon\s*:\s*(.+)$/);
      if (iconMatch) { itemIcon = iconMatch[1].trim(); break; }
    }

    let usageKeyword = 'part';
    if (defType.startsWith('concern')) { usageKeyword = 'concern'; }
    else if (defType.startsWith('requirement')) { usageKeyword = 'requirement'; }
    else if (defType.startsWith('allocation')) { usageKeyword = 'allocation'; }
    else if (defType.startsWith('occurrence')) { usageKeyword = 'occurrence'; }

    // Build params: merge parent abstract attributes + own attributes
    const params: ToolboxParam[] = [];
    if (parent && abstractBodies?.has(parent)) {
      const parentBody = abstractBodies.get(parent);
      if (parentBody) { params.push(...parseAttributesFromBody(parentBody)); }
    }
    params.push(...parseAttributesFromBody(body));

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
      params,
    });
  }
  return items;
}
