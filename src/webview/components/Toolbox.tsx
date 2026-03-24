import { DragEvent, useCallback, useState } from 'react';
import type { ToolboxCategory, ToolboxItem } from '../types';

interface ToolboxProps {
  categories: ToolboxCategory[];
  onNewFile: () => void;
}

export function Toolbox({ categories, onNewFile }: ToolboxProps) {
  const [filter, setFilter] = useState('');

  const onDragStart = useCallback((e: DragEvent, item: ToolboxItem) => {
    e.dataTransfer.setData('application/reactflow-type', item.sysmlType);
    e.dataTransfer.setData('application/reactflow-usage', item.usageKeyword);
    e.dataTransfer.effectAllowed = 'move';
  }, []);

  const q = filter.toLowerCase();

  return (
    <div className="toolbox-panel">
      <div className="toolbox-header">🛡️ Threat Model Toolbox</div>
      <div className="toolbox-actions">
        <button onClick={onNewFile}>New Threat Model</button>
      </div>
      <div className="toolbox-search">
        <input
          type="text"
          placeholder="Filter items…"
          value={filter}
          onChange={e => setFilter(e.target.value)}
        />
      </div>
      <div className="toolbox-items">
        {categories.map(cat => (
          <div className="toolbox-category" key={cat.id}>
            <div className="category-header" title={cat.description}>
              {cat.icon} {cat.label}
            </div>
            {cat.description && <div className="category-desc">{cat.description}</div>}
            {cat.items
              .filter(item => !q || item.name.toLowerCase().includes(q))
              .map(item => (
                <div
                  key={item.id}
                  className="toolbox-item"
                  draggable
                  title={item.description}
                  onDragStart={e => onDragStart(e, item)}
                >
                  <span className="item-icon">{item.icon}</span>
                  <span className="item-name">{item.name}</span>
                </div>
              ))}
          </div>
        ))}
      </div>
    </div>
  );
}
