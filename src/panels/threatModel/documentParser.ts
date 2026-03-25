/**
 * SysML document parser — converts raw SysML text into a structured ParsedModel.
 * Also exports shared text utilities (findBlockEnd, extractDoc) used by other modules.
 */

import type { ParsedFlow, ParsedModel } from './types';

// ── Shared text utilities ────────────────────────────────────────

/** Find the matching closing brace for an opening brace at `openBrace`. */
export function findBlockEnd(text: string, openBrace: number): number {
  let depth = 1;
  let pos = openBrace + 1;
  while (pos < text.length && depth > 0) {
    if (text[pos] === '{') { depth++; }
    else if (text[pos] === '}') { depth--; }
    pos++;
  }
  return pos - 1;
}

/** Extract the `doc /* … *​/` block from a SysML body. */
export function extractDoc(block: string): string {
  const m = block.match(/doc\s+\/\*\s*([\s\S]*?)\*\//);
  return m ? m[1].replace(/^\s*\*\s?/gm, '').trim() : '';
}

/** Read a `:>> attr = "value"` or `:>> attr = Enum::value` assignment. */
export function getAttr(block: string, attr: string): string {
  const re = new RegExp(`:>>\\s*${attr}\\s*=\\s*(?:(\\w+)::(\\w+)|"([^"]*)"|(true|false))`);
  const m = block.match(re);
  if (m) { return m[3] ?? m[2] ?? m[4] ?? ''; }
  return '';
}

/** Extract all `:>> key = value` pairs from a block. */
export function extractAttributes(block: string): Record<string, string> {
  const attrs: Record<string, string> = {};
  const attrRe = /:>>\s*(\w+)\s*=\s*(?:(\w+)::(\w+)|"([^"]*)"|(\w+))/g;
  let m: RegExpExecArray | null;
  while ((m = attrRe.exec(block)) !== null) {
    attrs[m[1]] = m[4] ?? m[3] ?? m[5] ?? '';
  }
  return attrs;
}

/** Convert camelCase to title case. */
export function camelToTitle(s: string): string {
  return s.replace(/([A-Z])/g, ' $1').replace(/^./, c => c.toUpperCase()).trim();
}

// ── Block finders ────────────────────────────────────────────────

function findTypedBlocks(text: string, typeName: string): { name: string; body: string }[] {
  const results: { name: string; body: string }[] = [];
  const re = new RegExp(
    `(?:part|concern|requirement|allocation)\\s+(\\w+)\\s*:\\s*${typeName}\\b`, 'g',
  );
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const braceStart = text.indexOf('{', m.index + m[0].length);
    if (braceStart === -1) { continue; }
    const braceEnd = findBlockEnd(text, braceStart);
    results.push({ name: m[1], body: text.substring(braceStart + 1, braceEnd) });
  }
  return results;
}

function findTopLevelTypedBlocks(
  text: string,
  typeName: string,
  boundaryChildren: Set<string>,
): { name: string; body: string }[] {
  return findTypedBlocks(text, typeName).filter(b => !boundaryChildren.has(b.name));
}

function findOccurrenceBlocks(text: string): { name: string; body: string }[] {
  const results: { name: string; body: string }[] = [];
  const re = /occurrence\s+def\s+(\w+)\s*\{/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const braceStart = m.index + m[0].length - 1;
    const braceEnd = findBlockEnd(text, braceStart);
    results.push({ name: m[1], body: text.substring(braceStart + 1, braceEnd) });
  }
  return results;
}

function parseSuccessionFlows(body: string): ParsedFlow[] {
  const flows: ParsedFlow[] = [];
  const flowRe = /(?:then\s+)?succession\s+flow\s+(\w+)\s+of\s+(\w+)\s+from\s+([\w.]+)\s+to\s+([\w.]+)\s*\{/g;
  let m: RegExpExecArray | null;
  while ((m = flowRe.exec(body)) !== null) {
    const braceStart = m.index + m[0].length - 1;
    const braceEnd = findBlockEnd(body, braceStart);
    const flowBody = body.substring(braceStart + 1, braceEnd);

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
      name: m[1],
      dataType: m[2],
      fromPath: m[3],
      from: m[3].split('.').pop() ?? m[3],
      toPath: m[4],
      to: m[4].split('.').pop() ?? m[4],
      description: extractDoc(flowBody),
      stride,
    });
  }
  return flows;
}

// ── Main parser ──────────────────────────────────────────────────

const COMPONENT_TYPES = [
  'WebApplication', 'IdentityProvider', 'DataStore',
  'MonitoringService', 'Gateway', 'ExternalSystem', 'SecretStore',
];

export function parseDocument(text: string): ParsedModel {
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

  // Trust boundaries (with nested components and actors)
  findTypedBlocks(cleaned, 'TrustBoundary').forEach(({ name, body }) => {
    const children: string[] = [];

    for (const ctype of COMPONENT_TYPES) {
      findTypedBlocks(body, ctype).forEach(({ name: cname, body: cbody }) => {
        children.push(cname);
        model.components.push({
          name: cname,
          type: ctype,
          description: getAttr(cbody, 'description') || extractDoc(cbody),
          boundary: name,
          attributes: extractAttributes(cbody),
        });
      });
    }

    findTypedBlocks(body, 'ThreatActor').forEach(({ name: aname, body: abody }) => {
      children.push(aname);
      model.actors.push({
        name: aname,
        type: 'ThreatActor',
        description: getAttr(abody, 'description') || extractDoc(abody),
        boundary: name,
        attributes: extractAttributes(abody),
      });
    });

    model.boundaries.push({
      name,
      description: getAttr(body, 'description') || extractDoc(body),
      children,
    });
  });

  // Top-level components (not inside boundaries)
  const boundaryChildren = new Set(model.boundaries.flatMap(b => b.children));
  for (const ctype of COMPONENT_TYPES) {
    findTopLevelTypedBlocks(cleaned, ctype, boundaryChildren).forEach(({ name: cname, body: cbody }) => {
      if (!model.components.find(c => c.name === cname)) {
        model.components.push({
          name: cname,
          type: ctype,
          description: getAttr(cbody, 'description') || extractDoc(cbody),
          attributes: extractAttributes(cbody),
        });
      }
    });
  }

  // Threats
  findTypedBlocks(cleaned, 'Threat').forEach(({ name, body }) => {
    const targetMatch = body.match(/subject\s+:>>\s*target\s*=\s*([\w.]+)/);
    model.threats.push({
      name,
      type: 'Threat',
      description: extractDoc(body),
      attributes: {
        ...extractAttributes(body),
        targetComponent: targetMatch ? (targetMatch[1].split('.').pop() ?? '') : '',
      },
    });
  });

  // Mitigations
  findTypedBlocks(cleaned, 'SecurityRequirement').forEach(({ name, body }) => {
    const targetMatch = body.match(/subject\s+:>>\s*target\s*=\s*([\w.]+)/);
    model.mitigations.push({
      name,
      type: 'SecurityRequirement',
      description: extractDoc(body),
      attributes: {
        ...extractAttributes(body),
        targetThreat: targetMatch ? targetMatch[1] : '',
      },
    });
  });

  // Data flow sequences
  findOccurrenceBlocks(cleaned).forEach(({ name, body }) => {
    const flows = parseSuccessionFlows(body);
    if (flows.length > 0) {
      model.sequences.push({
        name,
        description: extractDoc(body),
        flows,
      });
    }
  });

  return model;
}
