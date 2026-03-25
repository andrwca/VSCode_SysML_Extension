import '@xyflow/react/dist/style.css';
import { useCallback, useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';

import { ThreatModelCanvas } from './components/Canvas';
import { FlowDialog } from './components/Dialogs';
import { PropertiesPanel } from './components/PropertiesPanel';
import { Toolbox } from './components/Toolbox';
import type {
  ExtensionMessage,
  NodePosition,
  ParsedModel,
  ToolboxCategory,
  ToolboxItem,
  WebviewMessage,
} from './types';

// VS Code API
declare function acquireVsCodeApi(): {
  postMessage(msg: WebviewMessage): void;
  getState(): unknown;
  setState(state: unknown): void;
};
const vscode = acquireVsCodeApi();

// ── Initial data injected by the extension ──
declare const __INITIAL_MODEL__: ParsedModel;
declare const __INITIAL_POSITIONS__: NodePosition[];
declare const __INITIAL_TOOLBOX__: ToolboxCategory[];

/** Convert a camelCase type name to a readable title: "WebApplication" → "Web Application". */
function typeToTitle(s: string): string {
  return s.replace(/([A-Z])/g, ' $1').replace(/^./, c => c.toUpperCase()).trim();
}

/** Convert a display name to a camelCase SysML identifier: "Web Application 1" → "webApplication1". */
function displayNameToPartName(displayName: string): string {
  return displayName
    .replace(/[^\w\s]/g, '')
    .split(/\s+/)
    .map((w, i) => i === 0 ? w.charAt(0).toLowerCase() + w.slice(1) : w.charAt(0).toUpperCase() + w.slice(1))
    .join('');
}

/** Generate a unique display name like "Web Application 1" and derive the partName from it. */
function autoNameFromType(sysmlType: string, model: ParsedModel): { displayName: string; partName: string } {
  const titleBase = typeToTitle(sysmlType);
  const all = [
    ...model.components, ...model.actors, ...model.threats, ...model.mitigations,
  ].map(e => e.name);
  const boundaryNames = model.boundaries.map(b => b.name);
  const existing = new Set([...all, ...boundaryNames]);
  let i = 1;
  let partName = displayNameToPartName(`${titleBase} ${i}`);
  while (existing.has(partName)) { i++; partName = displayNameToPartName(`${titleBase} ${i}`); }
  return { displayName: `${titleBase} ${i}`, partName };
}

function App() {
  const [model, setModel] = useState<ParsedModel>(__INITIAL_MODEL__);
  const [positions, setPositions] = useState<NodePosition[]>(__INITIAL_POSITIONS__);
  const toolbox = __INITIAL_TOOLBOX__;

  // ── Selection state ──
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);

  // ── Flow dialog state ──
  const [flowDialogOpen, setFlowDialogOpen] = useState(false);
  const [flowEndpoints, setFlowEndpoints] = useState<{ from: string; to: string } | null>(null);
  const [flowTypeHint, setFlowTypeHint] = useState<string | undefined>(undefined);

  // ── Listen for updates from extension ──
  useEffect(() => {
    const handler = (event: MessageEvent<ExtensionMessage>) => {
      const msg = event.data;
      if (msg.type === 'update') {
        setModel(msg.model);
        setPositions(msg.positions);
      }
    };
    window.addEventListener('message', handler);
    return () => window.removeEventListener('message', handler);
  }, []);

  // ── Toolbox drop handler — auto-name, no dialog ──
  const handleDrop = useCallback((
    sysmlType: string, _usageKeyword: string,
    x: number, y: number, boundary?: string, itemJson?: string,
  ) => {
    const { displayName, partName } = autoNameFromType(sysmlType, model);

    // Parse the full toolbox item if available
    let item: ToolboxItem | undefined;
    if (itemJson) {
      try { item = JSON.parse(itemJson); } catch { /* ignore */ }
    }

    // Build default attrValues from params, seed description with display name
    const attrValues: Record<string, string> = { description: displayName };
    if (item?.params) {
      for (const p of item.params) {
        if (p.default !== undefined) { attrValues[p.name] = p.default; }
      }
    }

    vscode.postMessage({
      command: 'drop',
      sysmlType,
      partName,
      x, y,
      boundary,
      attrValues,
    });
  }, [model]);

  // ── ReactFlow native connect (drag handle → handle) ──
  const handleConnect = useCallback((fromPart: string, toPart: string) => {
    setFlowEndpoints({ from: fromPart, to: toPart });
    setFlowTypeHint(undefined);
    setFlowDialogOpen(true);
  }, []);

  // ── Flow dialog confirm ──
  const handleFlowConfirm = useCallback((data: {
    sequenceName: string; flowName: string; dataType: string;
    fromPart: string; toPart: string; addStride: boolean;
  }) => {
    setFlowDialogOpen(false);
    setFlowEndpoints(null);
    setFlowTypeHint(undefined);
    vscode.postMessage({ command: 'createFlow', ...data });
  }, []);

  // ── Node move ──
  const handleNodeMove = useCallback((partName: string, x: number, y: number, width?: number, height?: number) => {
    vscode.postMessage({ command: 'move', partName, x, y, width, height });
  }, []);

  // ── Delete ──
  const handleDeleteNode = useCallback((partName: string) => {
    vscode.postMessage({ command: 'delete', partName });
  }, []);
  const handleDeleteFlow = useCallback((flowName: string) => {
    vscode.postMessage({ command: 'deleteFlow', flowName });
  }, []);

  // ── Update properties ──
  const handleUpdateProperties = useCallback((partName: string, attributes: Record<string, string>) => {
    vscode.postMessage({ command: 'updateProperties', partName, attributes });
  }, []);

  // Auto-layout placeholder
  const handleAutoLayout = useCallback(() => {
    vscode.postMessage({ command: 'requestUpdate' });
  }, []);

  const isEmpty = model.components.length === 0 && model.actors.length === 0
    && model.boundaries.length === 0 && model.threats.length === 0
    && model.mitigations.length === 0;

  return (
    <div className="editor-root">
      <Toolbox categories={toolbox} />
      <div className="canvas-wrapper">
        {isEmpty && (
          <div className="empty-overlay">
            <div className="empty-state">
              <div className="icon">🛡️</div>
              <p>Drag elements from the toolbox to start building your threat model.</p>
            </div>
          </div>
        )}
        <ThreatModelCanvas
          model={model}
          positions={positions}
          toolbox={toolbox}
          onNodeMove={handleNodeMove}
          onDrop={handleDrop}
          onDeleteNode={handleDeleteNode}
          onDeleteFlow={handleDeleteFlow}
          onConnect={handleConnect}
          onAutoLayout={handleAutoLayout}
          onSelectionChange={setSelectedNodeId}
        />
      </div>

      <PropertiesPanel
        selectedNodeId={selectedNodeId}
        model={model}
        toolbox={toolbox}
        onUpdateProperties={handleUpdateProperties}
      />

      <FlowDialog
        open={flowDialogOpen}
        endpoints={flowEndpoints}
        flowTypeHint={flowTypeHint}
        model={model}
        onConfirm={handleFlowConfirm}
        onCancel={() => { setFlowDialogOpen(false); setFlowEndpoints(null); setFlowTypeHint(undefined); }}
      />
    </div>
  );
}

// ── Mount ──
const root = createRoot(document.getElementById('root')!);
root.render(<App />);
