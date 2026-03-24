import { useEffect, useRef, useState } from 'react';
import type { ParsedModel } from '../types';

interface NameDialogProps {
  open: boolean;
  sysmlType: string;
  boundaries: ParsedModel['boundaries'];
  onConfirm: (name: string, boundary?: string) => void;
  onCancel: () => void;
}

export function NameDialog({ open, sysmlType, boundaries, onConfirm, onCancel }: NameDialogProps) {
  const [name, setName] = useState('');
  const [boundary, setBoundary] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);

  const showBoundary = [
    'WebApplication', 'IdentityProvider', 'DataStore', 'SecretStore',
    'MonitoringService', 'Gateway', 'ExternalSystem', 'ThreatActor',
  ].includes(sysmlType);

  useEffect(() => {
    if (open) {
      const base = sysmlType.charAt(0).toLowerCase() + sysmlType.slice(1);
      setName(base + '1');
      setBoundary('');
      setTimeout(() => {
        inputRef.current?.focus();
        inputRef.current?.select();
      }, 50);
    }
  }, [open, sysmlType]);

  if (!open) return null;

  const valid = /^[a-zA-Z_][a-zA-Z0-9_]*$/.test(name);

  const submit = () => {
    if (!valid) return;
    onConfirm(name, boundary || undefined);
  };

  return (
    <div className="dialog-backdrop" onClick={onCancel}>
      <div className="dialog" onClick={e => e.stopPropagation()}>
        <h3>Name this {camelToTitle(sysmlType)}</h3>
        <input
          ref={inputRef}
          type="text"
          value={name}
          onChange={e => setName(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter') submit(); if (e.key === 'Escape') onCancel(); }}
          placeholder="e.g. appService"
          className={!valid && name ? 'error' : ''}
        />
        <div className="hint">Use camelCase. This becomes the SysML part name.</div>
        {showBoundary && (
          <div className="field">
            <label>Drop into boundary:</label>
            <select value={boundary} onChange={e => setBoundary(e.target.value)}>
              <option value="">(top-level)</option>
              {boundaries.map(b => (
                <option key={b.name} value={b.name}>{camelToTitle(b.name)}</option>
              ))}
            </select>
          </div>
        )}
        <div className="dialog-buttons">
          <button onClick={onCancel}>Cancel</button>
          <button className="primary" disabled={!valid} onClick={submit}>Add</button>
        </div>
      </div>
    </div>
  );
}

interface FlowDialogProps {
  open: boolean;
  /** Pre-set endpoints from Connect mode (null = show dropdowns). */
  endpoints: { from: string; to: string } | null;
  /** If opened by dragging a flow type, pre-set the data type */
  flowTypeHint?: string;
  model: ParsedModel;
  onConfirm: (data: {
    sequenceName: string; flowName: string; dataType: string;
    fromPart: string; toPart: string; addStride: boolean;
  }) => void;
  onCancel: () => void;
}

export function FlowDialog({ open, endpoints, flowTypeHint, model, onConfirm, onCancel }: FlowDialogProps) {
  const [seqName, setSeqName] = useState('');
  const [flowName, setFlowName] = useState('');
  const [dataType, setDataType] = useState('HttpRequest');
  const [from, setFrom] = useState('');
  const [to, setTo] = useState('');
  const [addStride, setAddStride] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const nodeNames = [
    ...model.components.map(c => c.name),
    ...model.actors.map(a => a.name),
  ];

  useEffect(() => {
    if (!open) return;
    const existingSeqs = model.sequences.map(s => s.name);
    setSeqName(existingSeqs[0] || 'DataFlowSequence');
    setAddStride(false);

    if (endpoints) {
      setFrom(endpoints.from);
      setTo(endpoints.to);
      setFlowName(endpoints.from + 'To' + endpoints.to.charAt(0).toUpperCase() + endpoints.to.slice(1));
    } else {
      setFrom(nodeNames[0] || '');
      setTo(nodeNames[1] || nodeNames[0] || '');
      const f = nodeNames[0] || 'source';
      const t = nodeNames[1] || nodeNames[0] || 'target';
      setFlowName(f + 'To' + t.charAt(0).toUpperCase() + t.slice(1));
    }

    if (flowTypeHint) {
      setDataType(flowTypeHint);
    } else {
      setDataType('HttpRequest');
    }

    setTimeout(() => { inputRef.current?.focus(); inputRef.current?.select(); }, 50);
  }, [open]);

  // Auto-update flow name when from/to change (only when selectors visible)
  useEffect(() => {
    if (!endpoints && from && to) {
      setFlowName(from + 'To' + to.charAt(0).toUpperCase() + to.slice(1));
    }
  }, [from, to]);

  if (!open) return null;

  const validName = /^[a-zA-Z_][a-zA-Z0-9_]*$/.test(flowName);
  const validSeq = /^[a-zA-Z_][a-zA-Z0-9_]*$/.test(seqName);
  const validEndpoints = from && to && from !== to;

  const submit = () => {
    if (!validName || !validSeq || !validEndpoints) return;
    onConfirm({ sequenceName: seqName, flowName, dataType, fromPart: from, toPart: to, addStride });
  };

  return (
    <div className="dialog-backdrop" onClick={onCancel}>
      <div className="dialog dialog-wide" onClick={e => e.stopPropagation()}>
        <h3>Create Data Flow</h3>

        {endpoints ? (
          <div className="flow-endpoints">{camelToTitle(endpoints.from)} → {camelToTitle(endpoints.to)}</div>
        ) : (
          <>
            <div className="field">
              <label>From (source)</label>
              <select value={from} onChange={e => setFrom(e.target.value)}>
                {nodeNames.map(n => <option key={n} value={n}>{camelToTitle(n)}</option>)}
              </select>
            </div>
            <div className="field">
              <label>To (target)</label>
              <select value={to} onChange={e => setTo(e.target.value)}>
                {nodeNames.map(n => <option key={n} value={n}>{camelToTitle(n)}</option>)}
              </select>
            </div>
          </>
        )}

        <div className="field">
          <label>Sequence name</label>
          <input
            ref={inputRef}
            type="text" value={seqName} onChange={e => setSeqName(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter') submit(); if (e.key === 'Escape') onCancel(); }}
            placeholder="e.g. SuccessfulHttpRequest"
            className={!validSeq && seqName ? 'error' : ''}
          />
          <div className="hint">New or existing occurrence def to hold this flow.</div>
        </div>

        <div className="field">
          <label>Flow name</label>
          <input
            type="text" value={flowName} onChange={e => setFlowName(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter') submit(); if (e.key === 'Escape') onCancel(); }}
            placeholder="e.g. userToApp"
            className={!validName && flowName ? 'error' : ''}
          />
          <div className="hint">The succession flow name (camelCase).</div>
        </div>

        <div className="field">
          <label>Data type</label>
          <select value={dataType} onChange={e => setDataType(e.target.value)}>
            <option value="HttpRequest">HttpRequest</option>
            <option value="HttpResponse">HttpResponse</option>
            <option value="AuthToken">AuthToken</option>
            <option value="DatabaseQuery">DatabaseQuery</option>
            <option value="DatabaseResult">DatabaseResult</option>
            <option value="TelemetryPayload">TelemetryPayload</option>
            <option value="Credential">Credential</option>
          </select>
        </div>

        <label className="checkbox-label">
          <input type="checkbox" checked={addStride} onChange={e => setAddStride(e.target.checked)} />
          Add STRIDE annotation
        </label>

        <div className="dialog-buttons">
          <button onClick={onCancel}>Cancel</button>
          <button className="primary" disabled={!validName || !validSeq || !validEndpoints} onClick={submit}>Create Flow</button>
        </div>
      </div>
    </div>
  );
}

function camelToTitle(s: string): string {
  return s.replace(/([A-Z])/g, ' $1').replace(/^./, c => c.toUpperCase()).trim();
}
