import { useState, useMemo, useCallback } from 'react';
import type { SensorSummary } from '../../types/fleet';
import { SensorStatusBadge } from './SensorStatusBadge';
import { Settings } from 'lucide-react';

interface SensorTableProps {
  sensors: SensorSummary[];
  onSensorClick?: (sensor: SensorSummary) => void;
  onConfigureClick?: (sensor: SensorSummary) => void;
}

type SortField = keyof SensorSummary | 'none';
type SortDirection = 'asc' | 'desc';

export function SensorTable({ sensors, onSensorClick, onConfigureClick }: SensorTableProps) {
  const [sortField, setSortField] = useState<SortField>('none');
  const [sortDirection, setSortDirection] = useState<SortDirection>('asc');

  const handleSort = useCallback((field: SortField) => {
    if (sortField === field) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('asc');
    }
  }, [sortField, sortDirection]);

  const sortedSensors = useMemo(() => {
    if (sortField === 'none') return sensors;
    return [...sensors].sort((a, b) => {
      const aVal = a[sortField];
      const bVal = b[sortField];
      let comparison = 0;
      if (typeof aVal === 'string' && typeof bVal === 'string') {
        comparison = aVal.localeCompare(bVal);
      } else if (typeof aVal === 'number' && typeof bVal === 'number') {
        comparison = aVal - bVal;
      }
      return sortDirection === 'asc' ? comparison : -comparison;
    });
  }, [sensors, sortField, sortDirection]);

  const SortIcon = ({ field }: { field: SortField }) => {
    if (sortField !== field) return <span className="text-ink-muted">⇅</span>;
    return <span>{sortDirection === 'asc' ? '↑' : '↓'}</span>;
  };

  const columns = [
    { key: 'name', label: 'Name' },
    { key: 'status', label: 'Status' },
    { key: 'cpu', label: 'CPU' },
    { key: 'memory', label: 'Memory' },
    { key: 'rps', label: 'RPS' },
    { key: 'latencyMs', label: 'Latency' },
    { key: 'version', label: 'Version' },
    { key: 'region', label: 'Region' },
  ] as const;

  return (
    <div className="overflow-x-auto">
      <table className="min-w-full divide-y divide-border-subtle">
        <thead className="bg-surface-subtle">
          <tr>
            {columns.map((col) => (
              <th
                key={col.key}
                className="px-6 py-3 text-left text-xs font-semibold text-ink-muted uppercase tracking-widest cursor-pointer hover:bg-surface-card focus:outline-none focus:ring-2 focus:ring-inset focus:ring-ac-blue/50"
                onClick={() => handleSort(col.key)}
                onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); handleSort(col.key); } }}
                tabIndex={0}
                role="columnheader"
                aria-sort={sortField === col.key ? (sortDirection === 'asc' ? 'ascending' : 'descending') : 'none'}
              >
                <div className="flex items-center gap-2">
                  {col.label} <SortIcon field={col.key} />
                </div>
              </th>
            ))}
            <th className="px-6 py-3 text-right text-xs font-semibold text-ink-muted uppercase tracking-widest">
              Actions
            </th>
          </tr>
        </thead>
        <tbody className="bg-surface-base divide-y divide-border-subtle">
          {sortedSensors.map((sensor) => (
            <tr
              key={sensor.id}
              className="hover:bg-surface-subtle cursor-pointer transition-colors group focus:outline-none focus:ring-2 focus:ring-inset focus:ring-ac-blue/50"
              onClick={() => onSensorClick?.(sensor)}
              onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onSensorClick?.(sensor); } }}
              tabIndex={0}
              role="link"
              aria-label={`View sensor ${sensor.name}`}
            >
              <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-ink-primary">{sensor.name}</td>
              <td className="px-6 py-4 whitespace-nowrap"><SensorStatusBadge status={sensor.status ?? 'DISCONNECTED'} /></td>
              <td className="px-6 py-4 whitespace-nowrap text-sm text-ink-primary">{sensor.cpu != null ? `${sensor.cpu.toFixed(1)}%` : '—'}</td>
              <td className="px-6 py-4 whitespace-nowrap text-sm text-ink-primary">{sensor.memory != null ? `${sensor.memory.toFixed(1)}%` : '—'}</td>
              <td className="px-6 py-4 whitespace-nowrap text-sm text-ink-primary">{sensor.rps != null ? sensor.rps.toLocaleString() : '—'}</td>
              <td className="px-6 py-4 whitespace-nowrap text-sm text-ink-primary">{sensor.latencyMs != null ? `${sensor.latencyMs.toFixed(0)}ms` : '—'}</td>
              <td className="px-6 py-4 whitespace-nowrap text-sm text-ink-secondary">{sensor.version ?? '—'}</td>
              <td className="px-6 py-4 whitespace-nowrap text-sm text-ink-secondary">{sensor.region ?? '—'}</td>
              <td className="px-6 py-4 whitespace-nowrap text-right">
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    onConfigureClick?.(sensor);
                  }}
                  className="p-1 hover:bg-surface-card text-ink-muted hover:text-accent-primary transition-colors opacity-40 group-hover:opacity-100 focus:opacity-100 focus:outline-none focus:ring-2 focus:ring-ac-blue/50"
                  title="Configure Sensor"
                  aria-label={`Configure sensor ${sensor.name}`}
                >
                  <Settings className="w-4 h-4" />
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {sortedSensors.length === 0 && (
        <div className="text-center py-12 text-ink-muted">No sensors found</div>
      )}
    </div>
  );
}
