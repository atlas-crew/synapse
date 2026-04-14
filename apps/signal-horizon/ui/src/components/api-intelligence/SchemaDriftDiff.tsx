import { clsx } from 'clsx';
import { ArrowRight, AlertTriangle } from 'lucide-react';
import { Panel, Stack } from '@/ui';

interface SchemaChange {
  field: string;
  oldType?: string;
  newType?: string;
  description: string;
  severity: 'low' | 'medium' | 'high';
}

interface SchemaDriftDiffProps {
  endpoint: string;
  method: string;
  detectedAt: string;
  changes: SchemaChange[];
}

export function SchemaDriftDiff({ endpoint, method, detectedAt, changes }: SchemaDriftDiffProps) {
  // Previously used `border-l-4 border-l-ac-orange` (left accent) — a
  // one-off deviation from the design system. Collapsing to
  // `tone="warning"` gives a top-accent orange bar consistent with
  // every other warning panel in the app.
  return (
    <Panel tone="warning" padding="none" spacing="none">
      <div className="p-4 border-b border-border-subtle flex justify-between items-start">
        <div>
          <Stack direction="row" align="center" gap="sm" className="mb-1">
            <span className={clsx(
              "px-2 py-0.5 text-xs font-bold  uppercase",
              method === 'GET' ? 'bg-method-get/10 text-method-get' :
              method === 'POST' ? 'bg-method-post/10 text-method-post' :
              'bg-surface-subtle text-ink-secondary'
            )}>
              {method}
            </span>
            <span className="font-mono text-sm text-ink-primary">{endpoint}</span>
          </Stack>
          <p className="text-xs text-ink-secondary">
            Drift detected at {new Date(detectedAt).toLocaleString()}
          </p>
        </div>
        <Stack direction="row" align="center" gap="xs" className="text-ac-orange text-xs font-medium">
          <AlertTriangle className="w-4 h-4" />
          {changes.length} Changes
        </Stack>
      </div>
      
      <div className="divide-y divide-border-subtle">
        {changes.map((change, idx) => (
          <div key={idx} className="p-3 text-sm hover:bg-surface-subtle transition-colors">
            <div className="flex items-center justify-between mb-1">
              <span className="font-mono text-ink-primary font-medium">{change.field}</span>
              <span className={clsx(
                "text-[10px] uppercase tracking-wider font-semibold",
                change.severity === 'high' ? 'text-ac-red' : 'text-ac-orange'
              )}>
                {change.severity} Impact
              </span>
            </div>
            
            <Stack direction="row" align="center" gap="smPlus" className="text-xs mt-2">
              <div className="flex-1 bg-surface-base p-2 border border-border-subtle text-ink-muted">
                <span className="block text-[10px] uppercase text-ink-muted mb-0.5">Expected</span>
                <span className="font-mono text-green-600">{change.oldType || 'undefined'}</span>
              </div>
              <ArrowRight className="w-4 h-4 text-ink-muted" />
              <div className="flex-1 bg-surface-base p-2 border border-border-subtle text-ink-muted">
                <span className="block text-[10px] uppercase text-ink-muted mb-0.5">Actual</span>
                <span className="font-mono text-red-500">{change.newType || 'undefined'}</span>
              </div>
            </Stack>
            
            <p className="text-ink-secondary text-xs mt-2 italic">
              {change.description}
            </p>
          </div>
        ))}
      </div>
    </Panel>
  );
}
