import { useState, useCallback } from 'react';
import { Ban, X } from 'lucide-react';

export interface AccessControlData {
  allow: string[];
  deny: string[];
}

interface AccessControlConfigProps {
  config: AccessControlData;
  onChange: (config: AccessControlData) => void;
}

export function AccessControlConfig({ config, onChange }: AccessControlConfigProps) {
  const [newCidr, setNewCidr] = useState('');
  const [listType, setListType] = useState<'allow' | 'deny'>('deny');

  const handleAdd = useCallback(() => {
    if (!newCidr) return;
    if (listType === 'allow') {
      onChange({ ...config, allow: [...config.allow, newCidr] });
    } else {
      onChange({ ...config, deny: [...config.deny, newCidr] });
    }
    setNewCidr('');
  }, [newCidr, listType, config, onChange]);

  const handleRemove = useCallback((type: 'allow' | 'deny', cidr: string) => {
    if (type === 'allow') {
      onChange({ ...config, allow: config.allow.filter(c => c !== cidr) });
    } else {
      onChange({ ...config, deny: config.deny.filter(c => c !== cidr) });
    }
  }, [config, onChange]);

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2">
        <Ban className="w-5 h-5 text-ink-muted" />
        <div>
          <h3 className="text-sm font-medium text-ink-primary">Access Control</h3>
          <p className="text-xs text-ink-secondary">IP/CIDR Allow & Deny Lists</p>
        </div>
      </div>

      <div className="space-y-4 border-t border-border-subtle pt-6">
        {/* Add Form */}
        <div className="flex gap-2">
          <select 
            value={listType}
            onChange={(e) => setListType(e.target.value as 'allow' | 'deny')}
            className="bg-surface-base border border-border-subtle rounded px-3 py-2 text-sm focus:border-ac-blue focus:outline-none"
          >
            <option value="deny">Block (Deny)</option>
            <option value="allow">Allow</option>
          </select>
          <input
            type="text"
            placeholder="CIDR (e.g., 10.0.0.0/8)"
            value={newCidr}
            onChange={(e) => setNewCidr(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleAdd()}
            className="flex-1 bg-surface-base border border-border-subtle rounded px-3 py-2 text-sm focus:border-ac-blue focus:outline-none font-mono"
          />
          <button 
            onClick={handleAdd}
            disabled={!newCidr}
            className="px-4 py-2 bg-surface-subtle border border-border-subtle rounded text-sm font-medium hover:bg-surface-card disabled:opacity-50"
          >
            Add
          </button>
        </div>

        {/* Lists */}
        <div className="grid grid-cols-2 gap-4">
          <div className="space-y-2">
            <h4 className="text-xs font-medium text-ac-red uppercase tracking-wider">Deny List</h4>
            {config.deny.length === 0 ? (
              <p className="text-xs text-ink-muted italic">No denied CIDRs</p>
            ) : (
              config.deny.map(cidr => (
                <div key={cidr} className="flex justify-between items-center p-2 bg-ac-red/5 border border-ac-red/20 rounded text-xs">
                  <span className="font-mono text-ink-primary">{cidr}</span>
                  <button onClick={() => handleRemove('deny', cidr)} className="text-ink-muted hover:text-ac-red"><X className="w-3 h-3" /></button>
                </div>
              ))
            )}
          </div>

          <div className="space-y-2">
            <h4 className="text-xs font-medium text-ac-green uppercase tracking-wider">Allow List</h4>
            {config.allow.length === 0 ? (
              <p className="text-xs text-ink-muted italic">No allowed CIDRs</p>
            ) : (
              config.allow.map(cidr => (
                <div key={cidr} className="flex justify-between items-center p-2 bg-ac-green/5 border border-ac-green/20 rounded text-xs">
                  <span className="font-mono text-ink-primary">{cidr}</span>
                  <button onClick={() => handleRemove('allow', cidr)} className="text-ink-muted hover:text-ac-green"><X className="w-3 h-3" /></button>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
