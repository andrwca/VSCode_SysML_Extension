import '@xyflow/react/dist/style.css';
import { useCallback, useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';

import { ThreatModelCanvas } from './components/Canvas';
import { FlowDialog, NameDialog } from './components/Dialogs';
import { Toolbox } from './components/Toolbox';
import type {
  ExtensionMessage,
  NodePosition,
  ParsedModel,
  ToolboxCategory,
  WebviewMessage,
} from './types';
import { FLOW_DATA_TYPE_MAP } from './types';

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

function App() {
  const [model, setModel] = useState<ParsedModel>(__INITIAL_MODEL__);
  const [positions, setPositions] = useState<NodePosition[]>(__INITIAL_POSITIONS__);
  const toolbox = __INITIAL_TOOLBOX__;

  // ── Name dialog state ──
  const [nameDialogOpen, setNameDialogOpen] = useState(false);
  const [pendingDrop, setPendingDrop] = useState<{ sysmlType: string; x: number; y: number } | null>(null);

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

  // ── Toolbox drop handler ──
  const handleDrop = useCallback((sysmlType: string, usageKeyword: string, x: number, y: number) => {
    if (usageKeyword === 'occurrence') {
      // Flow type → open flow dialog with pre-selected data type
      setFlowEndpoints(null);
      setFlowTypeHint(FLOW_DATA_TYPE_MAP[sysmlType] || 'HttpRequest');
      setFlowDialogOpen(true);
    } else {
      // Node type → open name dialog
      setPendingDrop({ sysmlType, x, y });
      setNameDialogOpen(true);
    }
  }, []);

  // ── Name dialog confirm ──
  const handleNameConfirm = useCallback((name: string, boundary?: string) => {
    setNameDialogOpen(false);
    if (!pendingDrop) return;
    vscode.postMessage({
      command: 'drop',
      sysmlType: pendingDrop.sysmlType,
      partName: name,
      x: pendingDrop.x,
      y: pendingDrop.y,
      boundary,
    });
    setPendingDrop(null);
  }, [pendingDrop]);

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
  const handleNodeMove = useCallback((partName: string, x: number, y: number) => {
    vscode.postMessage({ command: 'move', partName, x, y });
  }, []);

  // ── Delete ──
  const handleDeleteNode = useCallback((partName: string) => {
    vscode.postMessage({ command: 'delete', partName });
  }, []);
  const handleDeleteFlow = useCallback((flowName: string) => {
    vscode.postMessage({ command: 'deleteFlow', flowName });
  }, []);

  // ── New file ──
  const handleNewFile = useCallback(() => {
    const name = prompt('Package name for the threat model:', 'NewThreatModel');
    if (name) { vscode.postMessage({ command: 'newFile', packageName: name }); }
  }, []);

  // Auto-layout placeholder
  const handleAutoLayout = useCallback(() => {
    // ELK layout is done by re-requesting positions from the extension
    vscode.postMessage({ command: 'requestUpdate' });
  }, []);

  const isEmpty = model.components.length === 0 && model.actors.length === 0
    && model.boundaries.length === 0 && model.threats.length === 0
    && model.mitigations.length === 0;

  return (
    <div className="editor-root">
      <Toolbox categories={toolbox} onNewFile={handleNewFile} />
      <div className="canvas-wrapper">
        {isEmpty && (
          <div className="empty-overlay">
            <div className="empty-state">
              <div className="icon">🛡️</div>
              <p>Drag elements from the toolbox to start building your threat model, or scaffold a new one.</p>
              <button onClick={handleNewFile}>Create New Threat Model</button>
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
        />
      </div>

      <NameDialog
        open={nameDialogOpen}
        sysmlType={pendingDrop?.sysmlType || ''}
        boundaries={model.boundaries}
        onConfirm={handleNameConfirm}
        onCancel={() => { setNameDialogOpen(false); setPendingDrop(null); }}
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
