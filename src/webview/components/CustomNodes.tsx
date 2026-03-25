import { Handle, NodeProps, NodeResizer, Position } from '@xyflow/react';
import { memo } from 'react';

/** Dashed boundary group node with resize handles. */
export const BoundaryNode = memo(({ data }: NodeProps) => (
  <div className="rf-node rf-boundary" style={{ width: '100%', height: '100%' }}>
    <NodeResizer minWidth={200} minHeight={150} lineStyle={{ stroke: 'var(--vscode-panel-border, #444)' }} handleStyle={{ width: 8, height: 8, background: 'var(--vscode-textLink-foreground, #3794ff)' }} />
    <div className="rf-boundary-label">{(data as Record<string, string>).label}</div>
  </div>
));
BoundaryNode.displayName = 'BoundaryNode';

/** Solid component node with connection handles. */
export const ComponentNode = memo(({ data }: NodeProps) => (
  <div className="rf-node rf-component" title={(data as Record<string, string>).description}>
    <Handle type="target" position={Position.Left} />
    <div className="rf-node-label">{(data as Record<string, string>).label}</div>
    <Handle type="source" position={Position.Right} />
  </div>
));
ComponentNode.displayName = 'ComponentNode';

/** Actor node (red border). */
export const ActorNode = memo(({ data }: NodeProps) => (
  <div className="rf-node rf-actor" title={(data as Record<string, string>).description}>
    <Handle type="target" position={Position.Left} />
    <div className="rf-node-label">{(data as Record<string, string>).label}</div>
    <Handle type="source" position={Position.Right} />
  </div>
));
ActorNode.displayName = 'ActorNode';

/** Threat node (diamond shape, orange). */
export const ThreatNode = memo(({ data }: NodeProps) => (
  <div className="rf-node rf-threat" title={(data as Record<string, string>).description}>
    <Handle type="target" position={Position.Left} />
    <div className="rf-node-label">{(data as Record<string, string>).label}</div>
    <Handle type="source" position={Position.Right} />
  </div>
));
ThreatNode.displayName = 'ThreatNode';

/** Mitigation node (green border). */
export const MitigationNode = memo(({ data }: NodeProps) => (
  <div className="rf-node rf-mitigation" title={(data as Record<string, string>).description}>
    <Handle type="target" position={Position.Left} />
    <div className="rf-node-label">{(data as Record<string, string>).label}</div>
    <Handle type="source" position={Position.Right} />
  </div>
));
MitigationNode.displayName = 'MitigationNode';
