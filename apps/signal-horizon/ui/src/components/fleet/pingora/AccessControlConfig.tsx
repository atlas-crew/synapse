import { useState, useCallback, memo } from 'react';
import { Ban, X } from 'lucide-react';
import { Button, Input, Select, Stack, colors } from '@/ui';

export interface AccessControlData {
  allow: string[];
  deny: string[];
}

interface AccessControlConfigProps {
  config: AccessControlData;
  onChange: (config: AccessControlData) => void;
}

const LIST_TYPE_OPTIONS = [
  { value: 'deny', label: 'Block (Deny)' },
  { value: 'allow', label: 'Allow' },
];

export const AccessControlConfig = memo(function AccessControlConfig({ config, onChange }: AccessControlConfigProps) {
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
      <Stack direction="row" align="center" gap="sm">
        <Ban className="w-5 h-5 text-ink-muted" aria-hidden="true" />
        <div>
          <h3 className="text-sm font-medium text-ink-primary">Access Control</h3>
          <p className="text-xs text-ink-secondary">IP/CIDR Allow & Deny Lists</p>
        </div>
      </Stack>

      <div className="space-y-4 border-t border-border-subtle pt-6">
        {/* Add Form */}
        <div className="flex gap-2 text-[10px] uppercase tracking-[0.18em] text-ink-muted">
          <label htmlFor="access-list-type" className="w-full max-w-[180px]">
            List Type
          </label>
          <label htmlFor="access-cidr-input" className="flex-1">
            CIDR Block
          </label>
        </div>
        <div className="flex gap-2">
          <Select
            id="access-list-type"
            aria-label="Access list type"
            options={LIST_TYPE_OPTIONS}
            value={listType}
            onChange={(e) => setListType(e.target.value as 'allow' | 'deny')}
            size="md"
            containerStyle={{ width: '100%', maxWidth: '180px' }}
          />
          <Input
            id="access-cidr-input"
            aria-label="CIDR block"
            type="text"
            placeholder="CIDR (e.g., 10.0.0.0/8)"
            value={newCidr}
            onChange={(e) => setNewCidr(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleAdd()}
            fill
            size="md"
            className="font-mono"
            containerStyle={{ flex: 1 }}
          />
          <Button
            onClick={handleAdd}
            disabled={!newCidr}
            variant="outlined"
            size="sm"
            style={{ height: '40px', padding: '0 16px' }}
          >
            Add
          </Button>
        </div>

        {/* Lists */}
        <div className="grid grid-cols-2 gap-4">
          <div className="space-y-2">
            <h4 className="text-xs font-medium text-ac-red uppercase tracking-wider">Deny List</h4>
            {config.deny.length === 0 ? (
              <p className="text-xs text-ink-muted italic">No denied CIDRs</p>
            ) : (
              config.deny.map(cidr => (
                <div key={cidr} className="flex justify-between items-center p-2 bg-ac-red/5 border border-ac-red/20 text-xs">
                  <span className="font-mono text-ink-primary">{cidr}</span>
                  <Button
                    onClick={() => handleRemove('deny', cidr)}
                    variant="ghost"
                    size="sm"
                    icon={<X className="w-3 h-3" aria-hidden="true" />}
                    style={{ height: '20px', padding: 0, color: colors.gray.mid }}
                    aria-label={`Remove denied CIDR ${cidr}`}
                  />
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
                <div key={cidr} className="flex justify-between items-center p-2 bg-ac-green/5 border border-ac-green/20 text-xs">
                  <span className="font-mono text-ink-primary">{cidr}</span>
                  <Button
                    onClick={() => handleRemove('allow', cidr)}
                    variant="ghost"
                    size="sm"
                    icon={<X className="w-3 h-3" aria-hidden="true" />}
                    style={{ height: '20px', padding: 0, color: colors.gray.mid }}
                    aria-label={`Remove allowed CIDR ${cidr}`}
                  />
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
});
