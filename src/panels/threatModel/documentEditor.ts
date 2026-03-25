/**
 * Document editor — all operations that mutate the SysML text document:
 * drop new elements, delete elements, create/delete flows, scaffold new files.
 */

import * as vscode from 'vscode';
import { camelToTitle, findBlockEnd } from './documentParser';
import { removePosition, savePosition } from './positionManager';
import type { ToolboxParam } from './types';

// ── Drop handling ────────────────────────────────────────────────

export async function handleDrop(
  document: vscode.TextDocument,
  msg: {
    sysmlType: string; partName: string; x: number; y: number;
    boundary?: string; usageKeyword?: string; params?: ToolboxParam[];
    attrValues?: Record<string, string>;
  },
): Promise<void> {
  const sysmlCode = generateSysmlFromTemplate(
    {
      sysmlType: msg.sysmlType,
      usageKeyword: msg.usageKeyword ?? 'part',
      params: msg.params ?? [],
    },
    msg.partName,
    msg.attrValues,
  );

  // Step 1: persist position BEFORE editing the document so the change
  // listener will find it when it re-reads positions.
  await savePosition(document.uri, msg.partName, msg.x, msg.y);

  // Step 2: ensure import exists (separate edit to avoid offset conflicts)
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

  // Step 3: re-read text after possible import insertion
  const freshText = document.getText();
  const insertOffset = findInsertionPoint(freshText, msg.boundary);
  if (insertOffset < 0) { return; }

  const lineStart = freshText.lastIndexOf('\n', insertOffset - 1) + 1;
  const lineText = freshText.substring(lineStart, insertOffset);
  const baseIndent = lineText.match(/^(\s*)/)?.[1] ?? '\t';
  const indentedCode = sysmlCode
    .split('\n')
    .map(line => `${baseIndent}\t${line}`)
    .join('\n');

  const edit = new vscode.WorkspaceEdit();
  edit.insert(document.uri, document.positionAt(insertOffset), `\n${indentedCode}\n`);
  await vscode.workspace.applyEdit(edit);
}

// ── Delete handling ──────────────────────────────────────────────

export async function handleDelete(
  document: vscode.TextDocument,
  msg: { partName: string },
): Promise<void> {
  const text = document.getText();
  const re = new RegExp(
    `\\n?[ \\t]*(?:part|concern|requirement|allocation)\\s+${msg.partName}\\s*:[^{]*\\{`,
  );
  const m = text.match(re);
  if (!m || m.index === undefined) { return; }

  const braceStart = text.indexOf('{', m.index + m[0].length - 1);
  const braceEnd = findBlockEnd(text, braceStart);
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
  await removePosition(document.uri, msg.partName);
}

// ── Flow creation ────────────────────────────────────────────────

export async function handleCreateFlow(
  document: vscode.TextDocument,
  msg: {
    flowName: string; sequenceName: string; dataType: string;
    fromPart: string; toPart: string; addStride: boolean;
  },
): Promise<void> {
  const text = document.getText();
  const fromPath = resolvePartPath(text, msg.fromPart);
  const toPath = resolvePartPath(text, msg.toPart);

  const flowCode = generateFlowSysml(
    msg.flowName, msg.dataType, fromPath, toPath, msg.addStride,
  );

  const seqRe = new RegExp(`occurrence\\s+def\\s+${msg.sequenceName}\\s*\\{`);
  const seqMatch = text.match(seqRe);

  if (seqMatch && seqMatch.index !== undefined) {
    const braceStart = text.indexOf('{', seqMatch.index + seqMatch[0].length - 1);
    const braceEnd = findBlockEnd(text, braceStart);

    const seqBody = text.substring(braceStart + 1, braceEnd);
    const hasPriorFlows = /succession\s+flow\s+\w+/.test(seqBody);
    const finalCode = hasPriorFlows
      ? flowCode.replace('succession flow', 'then succession flow')
      : flowCode;

    const edit = new vscode.WorkspaceEdit();
    edit.insert(document.uri, document.positionAt(braceEnd), `\n\t\t${finalCode}\n`);
    await vscode.workspace.applyEdit(edit);
  } else {
    const seqCode = [
      ``,
      `\toccurrence def ${msg.sequenceName} {`,
      `\t\tdoc /* Data flow sequence. */`,
      ``,
      `\t\t${flowCode}`,
      `\t}`,
    ].join('\n');

    const insertOffset = findSequenceInsertionPoint(text);
    const edit = new vscode.WorkspaceEdit();
    edit.insert(document.uri, document.positionAt(insertOffset), `\n${seqCode}\n`);
    await vscode.workspace.applyEdit(edit);
  }
}

// ── Flow deletion ────────────────────────────────────────────────

export async function handleDeleteFlow(
  document: vscode.TextDocument,
  msg: { flowName: string },
): Promise<void> {
  const text = document.getText();
  const flowRe = new RegExp(
    `\\n?[ \\t]*(?:then\\s+)?succession\\s+flow\\s+${msg.flowName}\\s+of\\s+\\w+\\s+from\\s+[\\w.]+\\s+to\\s+[\\w.]+\\s*\\{`,
  );
  const m = text.match(flowRe);
  if (!m || m.index === undefined) { return; }

  const braceStart = text.indexOf('{', m.index + m[0].length - 1);
  const braceEnd = findBlockEnd(text, braceStart);
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

// ── New file scaffolding ─────────────────────────────────────────

export async function handleNewFile(
  document: vscode.TextDocument,
  msg: { packageName: string },
): Promise<void> {
  const name = msg.packageName || 'NewThreatModel';
  const template = [
    `package ${name} {`,
    `\tdoc /* ${camelToTitle(name)} — created with SysML Threat Model Editor. */`,
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

// ── SysML code generation ────────────────────────────────────────

function generateSysmlFromTemplate(
  item: { sysmlType: string; usageKeyword: string; params: ToolboxParam[] },
  partName: string,
  attrValues?: Record<string, string>,
): string {
  const vals = attrValues ?? {};
  const lines: string[] = [];
  const description = vals.description ?? camelToTitle(partName);
  lines.push(`${item.usageKeyword} ${partName} : ${item.sysmlType} {`);
  lines.push(`\t:>> description = "${description}";`);

  for (const param of item.params) {
    const value = vals[param.name] ?? param.default ?? '';
    if (param.type === 'boolean') {
      lines.push(`\t:>> ${param.name} = ${value};`);
    } else if (param.type === 'enum') {
      lines.push(`\t:>> ${param.name} = ${param.enumType}::${value};`);
    } else {
      lines.push(`\t:>> ${param.name} = "${value}";`);
    }
  }

  lines.push(`}`);
  return lines.join('\n');
}

// ── Update properties ────────────────────────────────────────────

export async function handleUpdateProperties(
  document: vscode.TextDocument,
  msg: { partName: string; attrValues: Record<string, string>; params: ToolboxParam[] },
): Promise<void> {
  const text = document.getText();
  // Match the part/concern/requirement/allocation block
  const re = new RegExp(
    `((?:part|concern|requirement|allocation)\\s+${msg.partName}\\s*:[^{]*\\{)`,
  );
  const m = text.match(re);
  if (!m || m.index === undefined) { return; }

  const braceStart = text.indexOf('{', m.index + m[0].length - 1);
  const braceEnd = findBlockEnd(text, braceStart);
  const body = text.substring(braceStart + 1, braceEnd);

  // Determine indent from the line containing the opening brace
  const lineStart = text.lastIndexOf('\n', braceStart) + 1;
  const lineText = text.substring(lineStart, braceStart);
  const baseIndent = lineText.match(/^(\s*)/)?.[1] ?? '\t';

  let newBody = body;

  // Update description if provided
  if (msg.attrValues.description !== undefined) {
    const descRe = /:>>\s*description\s*=\s*"[^"]*"/;
    if (descRe.test(newBody)) {
      newBody = newBody.replace(descRe, `:>> description = "${msg.attrValues.description}"`);
    }
  }

  // Update each param
  for (const param of msg.params) {
    const value = msg.attrValues[param.name];
    if (value === undefined) { continue; }

    const attrRe = new RegExp(`:>>\\s*${param.name}\\s*=[^;]*;`);
    let replacement: string;
    if (param.type === 'boolean') {
      replacement = `:>> ${param.name} = ${value};`;
    } else if (param.type === 'enum') {
      replacement = `:>> ${param.name} = ${param.enumType}::${value};`;
    } else {
      replacement = `:>> ${param.name} = "${value}";`;
    }

    if (attrRe.test(newBody)) {
      newBody = newBody.replace(attrRe, replacement);
    } else {
      // Attribute doesn't exist yet — append before closing brace
      newBody += `\n${baseIndent}\t${replacement}`;
    }
  }

  if (newBody !== body) {
    const edit = new vscode.WorkspaceEdit();
    edit.replace(
      document.uri,
      new vscode.Range(
        document.positionAt(braceStart + 1),
        document.positionAt(braceEnd),
      ),
      newBody,
    );
    await vscode.workspace.applyEdit(edit);
  }
}

function generateFlowSysml(
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

// ── Insertion point helpers ──────────────────────────────────────

function findInsertionPoint(text: string, boundary?: string): number {
  if (boundary) {
    const re = new RegExp(`part\\s+${boundary}\\s*:\\s*TrustBoundary\\s*\\{`);
    const m = text.match(re);
    if (m && m.index !== undefined) {
      const braceStart = text.indexOf('{', m.index + m[0].length - 1);
      return findBlockEnd(text, braceStart);
    }
  }

  const pkgMatch = text.match(/package\s+\w+\s*\{/);
  if (pkgMatch && pkgMatch.index !== undefined) {
    const pkgBraceStart = pkgMatch.index + pkgMatch[0].length - 1;
    const pkgBody = text.substring(pkgBraceStart + 1);

    const partRe = /part\s+(\w+)\s*(?::\s*\w+)?/;
    const partMatch = pkgBody.match(partRe);
    if (partMatch && partMatch.index !== undefined) {
      const absStart = pkgBraceStart + 1 + partMatch.index;
      const braceStart = text.indexOf('{', absStart + partMatch[0].length);
      if (braceStart !== -1) {
        return findBlockEnd(text, braceStart);
      }
    }

    return findBlockEnd(text, pkgBraceStart);
  }

  const lastBrace = text.lastIndexOf('}');
  return lastBrace > 0 ? lastBrace : text.length;
}

function findSequenceInsertionPoint(text: string): number {
  const occRe = /occurrence\s+def\s+\w+\s*\{/g;
  let lastOccEnd = -1;
  let m: RegExpExecArray | null;
  while ((m = occRe.exec(text)) !== null) {
    const braceStart = m.index + m[0].length - 1;
    lastOccEnd = findBlockEnd(text, braceStart) + 1;
  }
  if (lastOccEnd > 0) { return lastOccEnd; }

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
        return findBlockEnd(text, braceIdx) + 1;
      }
    }
    return findBlockEnd(text, pkgBraceStart);
  }
  return text.lastIndexOf('}');
}

function resolvePartPath(text: string, partName: string): string {
  const pathMap = new Map<string, string>();

  const walkBlock = (blockText: string, prefix: string) => {
    const partRe = /part\s+(\w+)\s*(?::\s*\w+)?\s*\{/g;
    let m: RegExpExecArray | null;
    while ((m = partRe.exec(blockText)) !== null) {
      const name = m[1];
      const fullPath = prefix ? `${prefix}.${name}` : name;
      pathMap.set(name, fullPath);
      const braceStart = m.index + m[0].length - 1;
      const braceEnd = findBlockEnd(blockText, braceStart);
      walkBlock(blockText.substring(braceStart + 1, braceEnd), fullPath);
    }
  };

  const pkgMatch = text.match(/package\s+\w+\s*\{/);
  if (pkgMatch && pkgMatch.index !== undefined) {
    const braceStart = pkgMatch.index + pkgMatch[0].length - 1;
    const braceEnd = findBlockEnd(text, braceStart);
    walkBlock(text.substring(braceStart + 1, braceEnd), '');
  }

  return pathMap.get(partName) ?? partName;
}
