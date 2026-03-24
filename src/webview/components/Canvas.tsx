import {
  Background,
  Connection,
  Controls,
  Edge,
  EdgeTypes,
  MarkerType,
  MiniMap,
  Node,
  NodeChange,
  NodeTypes,
  Panel,
  ReactFlow,
  ReactFlowProvider,
  useEdgesState,
  useNodesState,
  useReactFlow
} from '@xyflow/react';
import React, { DragEvent, useCallback, useMemo, useRef } from 'react';
import type { NodePosition, ParsedModel, ToolboxCategory } from '../types';
import { TYPE_ICONS } from '../types';
import { StrideLabelEdge } from './CustomEdges';
import { ActorNode, BoundaryNode, ComponentNode, MitigationNode, ThreatNode } from './CustomNodes';

interface CanvasProps {
  model: ParsedModel;
  positions: NodePosition[];
  toolbox: ToolboxCategory[];
  onNodeMove: (partName: string, x: number, y: number) => void;
  onDrop: (sysmlType: string, usageKeyword: string, x: number, y: number) => void;
  onDeleteNode: (partName: string) => void;
  onDeleteFlow: (flowName: string) => void;
  onConnect: (fromPart: string, toPart: string) => void;
  onAutoLayout: () => void;
}

const nodeTypes: NodeTypes = {
  boundary: BoundaryNode,
  component: ComponentNode,
  actor: ActorNode,
  threat: ThreatNode,
  mitigation: MitigationNode,
};

const edgeTypes: EdgeTypes = {
  strideEdge: StrideLabelEdge,
};

function camelToTitle(s: string): string {
  return s.replace(/([A-Z])/g, ' $1').replace(/^./, c => c.toUpperCase()).trim();
}

export function ThreatModelCanvas(props: CanvasProps) {
  return (
    <ReactFlowProvider>
      <CanvasInner {...props} />
    </ReactFlowProvider>
  );
}

function CanvasInner({
  model, positions, toolbox, onNodeMove, onDrop, onDeleteNode,
  onDeleteFlow, onConnect,
}: CanvasProps) {
  const reactFlowWrapper = useRef<HTMLDivElement>(null);
  const { screenToFlowPosition } = useReactFlow();

  // ── Build nodes ──
  const initialNodes = useMemo(() => {
    const nodes: Node[] = [];

    // Boundaries as group nodes
    model.boundaries.forEach(b => {
      const pos = positions.find(p => p.partName === b.name);
      nodes.push({
        id: `boundary-${b.name}`,
        type: 'boundary',
        position: pos ? { x: pos.x, y: pos.y } : { x: 0, y: 0 },
        data: { label: camelToTitle(b.name), description: b.description },
        style: { width: 400, height: 300 },
      });
    });

    // Components
    model.components.forEach(c => {
      const icon = TYPE_ICONS[c.type] || '📦';
      const pos = positions.find(p => p.partName === c.name);
      nodes.push({
        id: `comp-${c.name}`,
        type: 'component',
        position: pos ? { x: pos.x, y: pos.y } : { x: Math.random() * 400, y: Math.random() * 300 },
        data: { label: `${icon} ${camelToTitle(c.name)}`, partName: c.name, componentType: c.type, description: c.description },
        parentId: c.boundary ? `boundary-${c.boundary}` : undefined,
        extent: c.boundary ? 'parent' as const : undefined,
      });
    });

    // Actors
    model.actors.forEach(a => {
      const pos = positions.find(p => p.partName === a.name);
      nodes.push({
        id: `actor-${a.name}`,
        type: 'actor',
        position: pos ? { x: pos.x, y: pos.y } : { x: Math.random() * 400, y: Math.random() * 300 },
        data: { label: `👤 ${camelToTitle(a.name)}`, partName: a.name, description: a.description },
        parentId: a.boundary ? `boundary-${a.boundary}` : undefined,
        extent: a.boundary ? 'parent' as const : undefined,
      });
    });

    // Threats
    model.threats.forEach(t => {
      const pos = positions.find(p => p.partName === t.name);
      nodes.push({
        id: `threat-${t.name}`,
        type: 'threat',
        position: pos ? { x: pos.x, y: pos.y } : { x: Math.random() * 400 + 500, y: Math.random() * 300 },
        data: { label: `⚠️ ${camelToTitle(t.name)}`, partName: t.name, description: t.description },
      });
    });

    // Mitigations
    model.mitigations.forEach(m => {
      const pos = positions.find(p => p.partName === m.name);
      nodes.push({
        id: `mit-${m.name}`,
        type: 'mitigation',
        position: pos ? { x: pos.x, y: pos.y } : { x: Math.random() * 400 + 500, y: Math.random() * 300 + 300 },
        data: { label: `✅ ${camelToTitle(m.name)}`, partName: m.name, description: m.description },
      });
    });

    return nodes;
  }, [model, positions]);

  // ── Build edges from sequences ──
  const initialEdges = useMemo(() => {
    const edges: Edge[] = [];
    const nodeIdMap = new Map<string, string>();
    initialNodes.forEach(n => {
      const partName = (n.data as Record<string, unknown>)?.partName as string | undefined;
      if (partName) nodeIdMap.set(partName, n.id);
    });

    model.sequences.forEach(seq => {
      seq.flows.forEach(f => {
        const sourceId = nodeIdMap.get(f.from);
        const targetId = nodeIdMap.get(f.to);
        if (!sourceId || !targetId) return;

        const hasStride = !!f.stride;
        let label = f.dataType;
        if (f.stride?.category) label += ` [${f.stride.category}]`;

        edges.push({
          id: `flow-${f.name}`,
          source: sourceId,
          target: targetId,
          type: hasStride ? 'strideEdge' : 'default',
          label,
          animated: hasStride,
          markerEnd: { type: MarkerType.ArrowClosed, width: 15, height: 15 },
          style: hasStride ? { stroke: '#ff8a65', strokeWidth: 2.5 } : { stroke: '#888', strokeWidth: 2 },
          data: { flowName: f.name, dataType: f.dataType, sequenceName: seq.name, hasStride },
        });
      });
    });
    return edges;
  }, [model, initialNodes]);

  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

  // Sync when model updates
  React.useEffect(() => { setNodes(initialNodes); }, [initialNodes]);
  React.useEffect(() => { setEdges(initialEdges); }, [initialEdges]);

  // ── Node drag end → save position ──
  const handleNodesChange = useCallback((changes: NodeChange[]) => {
    onNodesChange(changes);
    changes.forEach(change => {
      if (change.type === 'position' && !change.dragging && change.position) {
        const node = nodes.find(n => n.id === change.id);
        const partName = (node?.data as Record<string, unknown>)?.partName as string | undefined;
        if (partName && change.position) {
          onNodeMove(partName, Math.round(change.position.x), Math.round(change.position.y));
        }
      }
    });
  }, [nodes, onNodeMove, onNodesChange]);

  // ── Edge connection (ReactFlow's built-in connect) ──
  const handleConnect = useCallback((params: Connection) => {
    // Resolve node IDs back to part names
    const sourceNode = nodes.find(n => n.id === params.source);
    const targetNode = nodes.find(n => n.id === params.target);
    const fromPart = (sourceNode?.data as Record<string, unknown>)?.partName as string;
    const toPart = (targetNode?.data as Record<string, unknown>)?.partName as string;
    if (fromPart && toPart) {
      onConnect(fromPart, toPart);
    }
  }, [nodes, onConnect]);

  // ── Drag & Drop from toolbox ──
  const onDragOver = useCallback((e: DragEvent) => {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
  }, []);

  const handleDrop = useCallback((e: DragEvent) => {
    e.preventDefault();
    const sysmlType = e.dataTransfer.getData('application/reactflow-type');
    const usage = e.dataTransfer.getData('application/reactflow-usage');
    if (!sysmlType) return;

    const position = screenToFlowPosition({ x: e.clientX, y: e.clientY });
    onDrop(sysmlType, usage, Math.round(position.x), Math.round(position.y));
  }, [screenToFlowPosition, onDrop]);

  // ── Delete key handling ──
  const onKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === 'Delete' || e.key === 'Backspace') {
      const selectedNodes = nodes.filter(n => n.selected);
      const selectedEdges = edges.filter(ed => ed.selected);
      selectedNodes.forEach(n => {
        const partName = (n.data as Record<string, unknown>)?.partName as string;
        if (partName) onDeleteNode(partName);
      });
      selectedEdges.forEach(ed => {
        const flowName = (ed.data as Record<string, unknown>)?.flowName as string;
        if (flowName) onDeleteFlow(flowName);
      });
    }
  }, [nodes, edges, onDeleteNode, onDeleteFlow]);

  // ── Status bar ──
  const flowCount = model.sequences.reduce((acc, s) => acc + s.flows.length, 0);
  const total = model.components.length + model.actors.length + model.threats.length + model.mitigations.length;

  return (
    <div
      className="canvas-panel"
      ref={reactFlowWrapper}
      onKeyDown={onKeyDown}
      tabIndex={0}
    >
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={handleNodesChange}
        onEdgesChange={onEdgesChange}
        onConnect={handleConnect}
        onDrop={handleDrop}
        onDragOver={onDragOver}
        nodeTypes={nodeTypes}
        edgeTypes={edgeTypes}
        fitView
        fitViewOptions={{ padding: 0.2 }}
        deleteKeyCode={null}
        connectionLineStyle={{ stroke: '#3794ff', strokeWidth: 2 }}
        defaultEdgeOptions={{
          markerEnd: { type: MarkerType.ArrowClosed, width: 15, height: 15 },
        }}
      >
        <Background gap={20} size={1} />
        <Controls />
        <MiniMap
          nodeStrokeWidth={3}
          zoomable
          pannable
        />
        <Panel position="bottom-center">
          <div className="status-bar">
            {total} elements · {model.boundaries.length} boundaries · {model.threats.length} threats · {flowCount} flows
          </div>
        </Panel>
      </ReactFlow>
    </div>
  );
}
