import { Clock } from 'lucide-react';
import type { ApiSignal } from '../../hooks/useApiIntelligence';
import { Panel, SectionHeader, CARD_HEADER_TITLE_STYLE } from '@/ui';

export interface ViolationsFeedProps {
  signals: ApiSignal[];
}

export function ViolationsFeed({ signals }: ViolationsFeedProps) {
  return (
    <Panel tone="default">
      <Panel.Header>
        <SectionHeader
          title="Recent Violations"
          size="h4"
          mb="xs"
          style={{ marginBottom: 0 }}
          titleStyle={CARD_HEADER_TITLE_STYLE}
        />
      </Panel.Header>
      <Panel.Body className="space-y-4 max-h-[600px] overflow-y-auto">
        {signals.length === 0 ? (
          <div className="text-center text-ink-muted py-8">No recent violations</div>
        ) : (
          signals.map((signal) => <ViolationCard key={signal.id} signal={signal} />)
        )}
      </Panel.Body>
    </Panel>
  );
}

function ViolationCard({ signal }: { signal: ApiSignal }) {
  return (
    <div className="p-3 bg-surface-subtle border border-border-subtle">
      <div className="flex justify-between items-start mb-1">
        <span className="font-mono text-xs font-semibold text-ac-red bg-ac-red/10 px-1.5 py-0.5">
          {signal.metadata.violationType || 'SCHEMA_VIOLATION'}
        </span>
        <span className="text-[10px] text-ink-muted flex items-center gap-1">
          <Clock className="w-3 h-3" />
          {new Date(signal.createdAt).toLocaleTimeString()}
        </span>
      </div>
      <div className="text-sm font-medium text-ink-primary mb-1">
        {signal.metadata.method} {signal.metadata.endpoint}
      </div>
      <div className="text-xs text-ink-secondary">
        {signal.metadata.violationMessage || 'Request did not match schema definition.'}
      </div>
    </div>
  );
}
