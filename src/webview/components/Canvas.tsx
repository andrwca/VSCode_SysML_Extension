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
  onNodeMove: (partName: string, x: number, y: number, width?: number, height?: number) => void;
  onDrop: (sysmlType: string, usageKeyword: string, x: number, y: number, boundary?: string, itemJson?: string) => void;
  onDeleteNode: (partName: string) => void;
  onDeleteFlow: (flowName: string) => void;
  onConnect: (fromPart: string, toPart: string) => void;
  onAutoLayout: () => void;
  onSelectionChange: (nodeId: string | null) => void;
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
  onDeleteFlow, onConnect, onSelectionChange,
}: CanvasProps) {
  const reactFlowWrapper = useRef<HTMLDivElement>(null);
  const { screenToFlowPosition } = useReactFlow();

  // ── Build nodes ──
  // Build a position lookup once
  const posMap = useMemo(() => {
    const m = new Map<string, NodePosition>();
    for (const p of positions) { m.set(p.partName, p); }
    return m;
  }, [positions]);

  const initialNodes = useMemo(() => {
    const nodes: Node[] = [];

    // Boundaries as group nodes
    model.boundaries.forEach((b, idx) => {
      const pos = posMap.get(b.name);
      nodes.push({
        id: `boundary-${b.name}`,
        type: 'boundary',
        position: pos ? { x: pos.x, y: pos.y } : { x: idx * 450, y: 0 },
        data: { label: b.description || camelToTitle(b.name), description: b.description, partName: b.name },
        style: { width: pos?.width ?? 400, height: pos?.height ?? 300 },
      });
    });

    // Helper: convert absolute saved position to relative for child nodes
    const toRelative = (saved: NodePosition, parentName: string): { x: number; y: number } => {
      const parentPos = posMap.get(parentName);
      if (parentPos) {
        return { x: saved.x - parentPos.x, y: saved.y - parentPos.y };
      }
      return { x: saved.x, y: saved.y };
    };

    // Components
    let compIdx = 0;
    model.components.forEach(c => {
      const icon = TYPE_ICONS[c.type] || '📦';
      const pos = posMap.get(c.name);
      let position: { x: number; y: number };
      if (pos) {
        position = c.boundary ? toRelative(pos, c.boundary) : { x: pos.x, y: pos.y };
      } else {
        position = c.boundary
          ? { x: 30 + (compIdx % 3) * 160, y: 40 + Math.floor(compIdx / 3) * 80 }
          : { x: compIdx * 200, y: 100 };
      }
      compIdx++;
      nodes.push({
        id: `comp-${c.name}`,
        type: 'component',
        position,
        data: { label: `${icon} ${c.description || camelToTitle(c.name)}`, partName: c.name, componentType: c.type, description: c.description },
        parentId: c.boundary ? `boundary-${c.boundary}` : undefined,
        extent: c.boundary ? 'parent' as const : undefined,
      });
    });

    // Actors
    let actorIdx = 0;
    model.actors.forEach(a => {
      const pos = posMap.get(a.name);
      let position: { x: number; y: number };
      if (pos) {
        position = a.boundary ? toRelative(pos, a.boundary) : { x: pos.x, y: pos.y };
      } else {
        position = a.boundary
          ? { x: 30 + (actorIdx % 3) * 160, y: 40 + Math.floor(actorIdx / 3) * 80 }
          : { x: actorIdx * 200, y: 350 };
      }
      actorIdx++;
      nodes.push({
        id: `actor-${a.name}`,
        type: 'actor',
        position,
        data: { label: `👤 ${a.description || camelToTitle(a.name)}`, partName: a.name, description: a.description },
        parentId: a.boundary ? `boundary-${a.boundary}` : undefined,
        extent: a.boundary ? 'parent' as const : undefined,
      });
    });

    // Threats
    model.threats.forEach((t, idx) => {
      const pos = posMap.get(t.name);
      nodes.push({
        id: `threat-${t.name}`,
        type: 'threat',
        position: pos ? { x: pos.x, y: pos.y } : { x: 600, y: idx * 120 },
        data: { label: `⚠️ ${t.description || camelToTitle(t.name)}`, partName: t.name, description: t.description },
      });
    });

    // Mitigations
    model.mitigations.forEach((m, idx) => {
      const pos = posMap.get(m.name);
      nodes.push({
        id: `mit-${m.name}`,
        type: 'mitigation',
        position: pos ? { x: pos.x, y: pos.y } : { x: 600, y: 400 + idx * 80 },
        data: { label: `✅ ${m.description || camelToTitle(m.name)}`, partName: m.name, description: m.description },
      });
    });

    return nodes;
  }, [model, posMap]);

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

  // Sync when model updates — merge instead of replace to avoid
  // snapping nodes that the user has interactively moved.
  React.useEffect(() => {
    setNodes(prev => {
      const prevMap = new Map(prev.map(n => [n.id, n]));
      const nextIds = new Set(initialNodes.map(n => n.id));

      return initialNodes.map(incoming => {
        const existing = prevMap.get(incoming.id);
        if (!existing) { return incoming; } // new node
        // Keep the user's current interactive position; update data/style only
        return {
          ...incoming,
          position: existing.position,
          style: { ...incoming.style, ...(existing.style?.width ? { width: existing.style.width } : {}), ...(existing.style?.height ? { height: existing.style.height } : {}) },
        };
      });
      // Nodes removed in the model are automatically dropped because
      // they're not in initialNodes.
    });
  }, [initialNodes]);
  React.useEffect(() => { setEdges(initialEdges); }, [initialEdges]);

  // ── Node drag end / resize → save position ──
  const handleNodesChange = useCallback((changes: NodeChange[]) => {
    onNodesChange(changes);
    changes.forEach(change => {
      if (change.type === 'position' && !change.dragging && change.position) {
        const node = nodes.find(n => n.id === change.id);
        const partName = (node?.data as Record<string, unknown>)?.partName as string | undefined;
        if (partName && change.position) {
          let { x, y } = change.position;
          // For child nodes, convert relative position back to absolute
          if (node?.parentId) {
            const parent = nodes.find(n => n.id === node.parentId);
            if (parent) {
              x += parent.position.x;
              y += parent.position.y;
            }
          }
          onNodeMove(partName, Math.round(x), Math.round(y));
        }
      }
      // Persist dimension changes (boundary resize)
      if (change.type === 'dimensions' && change.dimensions) {
        const node = nodes.find(n => n.id === change.id);
        const partName = (node?.data as Record<string, unknown>)?.partName as string | undefined;
        if (partName && node) {
          let { x, y } = node.position;
          if (node.parentId) {
            const parent = nodes.find(n => n.id === node.parentId);
            if (parent) { x += parent.position.x; y += parent.position.y; }
          }
          onNodeMove(partName, Math.round(x), Math.round(y),
            Math.round(change.dimensions.width ?? 400),
            Math.round(change.dimensions.height ?? 300));
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

  // ── Selection change → notify parent ──
  const handleSelectionChange = useCallback(({ nodes: selNodes }: { nodes: Node[] }) => {
    if (selNodes.length === 1) {
      onSelectionChange(selNodes[0].id);
    } else {
      onSelectionChange(null);
    }
  }, [onSelectionChange]);

  const handleDrop = useCallback((e: DragEvent) => {
    e.preventDefault();
    const sysmlType = e.dataTransfer.getData('application/reactflow-type');
    const usage = e.dataTransfer.getData('application/reactflow-usage');
    const itemJson = e.dataTransfer.getData('application/reactflow-item');
    if (!sysmlType) return;

    const position = screenToFlowPosition({ x: e.clientX, y: e.clientY });
    const x = Math.round(position.x);
    const y = Math.round(position.y);

    // Detect if dropped inside a boundary node
    let boundary: string | undefined;
    for (const node of nodes) {
      if (node.type !== 'boundary') continue;
      const bx = node.position.x;
      const by = node.position.y;
      const bw = (node.style?.width as number) || 400;
      const bh = (node.style?.height as number) || 300;
      if (x >= bx && x <= bx + bw && y >= by && y <= by + bh) {
        const partName = node.id.replace('boundary-', '');
        boundary = partName;
        break;
      }
    }

    onDrop(sysmlType, usage, x, y, boundary, itemJson);
  }, [screenToFlowPosition, onDrop, nodes]);

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
        onSelectionChange={handleSelectionChange}
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
