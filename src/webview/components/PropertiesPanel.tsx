import { useCallback, useEffect, useState } from 'react';
import type { ParsedElement, ParsedModel, ToolboxCategory, ToolboxParam } from '../types';

interface PropertiesPanelProps {
  selectedNodeId: string | null;
  model: ParsedModel;
  toolbox: ToolboxCategory[];
  onUpdateProperties: (partName: string, attributes: Record<string, string>) => void;
}

function camelToTitle(s: string): string {
  return s.replace(/([A-Z])/g, ' $1').replace(/^./, c => c.toUpperCase()).trim();
}

/** Find the model element and its toolbox params by node id. */
function resolveSelection(
  nodeId: string,
  model: ParsedModel,
  toolbox: ToolboxCategory[],
): { element: ParsedElement; params: ToolboxParam[] } | null {
  // nodeId format: "comp-name", "actor-name", "boundary-name", "threat-name", "mit-name"
  const dash = nodeId.indexOf('-');
  if (dash < 0) { return null; }
  const prefix = nodeId.substring(0, dash);
  const name = nodeId.substring(dash + 1);

  let element: ParsedElement | undefined;
  switch (prefix) {
    case 'comp': element = model.components.find(c => c.name === name); break;
    case 'actor': element = model.actors.find(a => a.name === name); break;
    case 'boundary': {
      const b = model.boundaries.find(b => b.name === name);
      if (b) { element = { name: b.name, type: 'TrustBoundary', description: b.description, attributes: {} }; }
      break;
    }
    case 'threat': element = model.threats.find(t => t.name === name); break;
    case 'mit': element = model.mitigations.find(m => m.name === name); break;
  }
  if (!element) { return null; }

  // Find matching toolbox item for params
  const allItems = toolbox.flatMap(c => c.items);
  const toolboxItem = allItems.find(i => i.sysmlType === element!.type);

  return { element, params: toolboxItem?.params ?? [] };
}

export function PropertiesPanel({ selectedNodeId, model, toolbox, onUpdateProperties }: PropertiesPanelProps) {
  const [localValues, setLocalValues] = useState<Record<string, string>>({});
  const [dirty, setDirty] = useState(false);

  const resolved = selectedNodeId ? resolveSelection(selectedNodeId, model, toolbox) : null;

  // Reset local values when selection changes
  useEffect(() => {
    if (resolved) {
      const vals: Record<string, string> = {};
      vals.description = resolved.element.description || '';
      for (const p of resolved.params) {
        vals[p.name] = resolved.element.attributes[p.name] ?? p.default ?? '';
      }
      setLocalValues(vals);
      setDirty(false);
    }
  }, [selectedNodeId, resolved?.element.name]);

  const handleChange = useCallback((key: string, value: string) => {
    setLocalValues(prev => ({ ...prev, [key]: value }));
    setDirty(true);
  }, []);

  const handleApply = useCallback(() => {
    if (!resolved || !dirty) { return; }
    onUpdateProperties(resolved.element.name, localValues);
    setDirty(false);
  }, [resolved, dirty, localValues, onUpdateProperties]);

  if (!resolved) {
    return (
      <div className="properties-panel">
        <div className="properties-header">Properties</div>
        <div className="properties-empty">Select an element to view its properties.</div>
      </div>
    );
  }

  const { element, params } = resolved;

  return (
    <div className="properties-panel">
      <div className="properties-header">Properties</div>
      <div className="properties-body">
        <div className="prop-section">
          <div className="prop-type-badge">{element.type}</div>
          <div className="prop-name">{localValues.description || camelToTitle(element.name)}</div>
          <div className="prop-part-name">{element.name}</div>
        </div>

        <div className="prop-field">
          <label>Display Name</label>
          <input
            type="text"
            value={localValues.description ?? ''}
            onChange={e => handleChange('description', e.target.value)}
            placeholder="Display name…"
          />
        </div>

        {params.map(p => (
          <div className="prop-field" key={p.name}>
            <label>{camelToTitle(p.name)}</label>
            {p.type === 'boolean' ? (
              <label className="prop-checkbox">
                <input
                  type="checkbox"
                  checked={localValues[p.name] === 'true'}
                  onChange={e => handleChange(p.name, e.target.checked ? 'true' : 'false')}
                />
                {localValues[p.name] === 'true' ? 'Yes' : 'No'}
              </label>
            ) : p.type === 'enum' && p.enumValues ? (
              <select
                value={localValues[p.name] ?? ''}
                onChange={e => handleChange(p.name, e.target.value)}
              >
                {p.enumValues.map(v => (
                  <option key={v} value={v}>{v}</option>
                ))}
              </select>
            ) : (
              <input
                type="text"
                value={localValues[p.name] ?? ''}
                onChange={e => handleChange(p.name, e.target.value)}
                placeholder={camelToTitle(p.name)}
              />
            )}
          </div>
        ))}

        <div className="prop-actions">
          <button className="primary" disabled={!dirty} onClick={handleApply}>
            Apply
          </button>
        </div>
      </div>
    </div>
  );
}
