import { memo } from 'react';
import { MethodBadge, type HttpMethod } from '../../ctrlx/MethodBadge';
import { ProgressBar } from '../../ctrlx/ProgressBar';

interface EndpointStats {
  method: HttpMethod;
  path: string;
  requests: number;
  avgLatency: number;
  errorRate: number;
}

interface TopEndpointsTableProps {
  data: EndpointStats[];
  maxItems?: number;
  className?: string;
}

/**
 * TopEndpointsTable - Table of top endpoints by traffic with method badges and latency.
 */
export const TopEndpointsTable = memo(function TopEndpointsTable({
  data,
  maxItems = 6,
  className = '',
}: TopEndpointsTableProps) {
  const displayData = data.slice(0, maxItems);
  const maxRequests = Math.max(...displayData.map((d) => d.requests));

  return (
    <div className={`overflow-x-auto ${className}`}>
      <table className="ctrlx-table">
        <thead>
          <tr>
            <th className="w-24">Method</th>
            <th>Endpoint</th>
            <th className="w-40">Requests</th>
            <th className="w-24 text-right">Latency</th>
            <th className="w-24 text-right">Error %</th>
          </tr>
        </thead>
        <tbody>
          {displayData.map((endpoint) => (
            <tr key={`${endpoint.method}-${endpoint.path}`}>
              <td>
                <MethodBadge method={endpoint.method} />
              </td>
              <td className="font-mono text-sm">{endpoint.path}</td>
              <td>
                <div className="flex items-center gap-2">
                  <ProgressBar
                    value={endpoint.requests}
                    max={maxRequests}
                    variant="info"
                    size="sm"
                    className="flex-1"
                  />
                  <span className="text-xs text-gray-500 min-w-[4rem] text-right">
                    {(endpoint.requests / 1000).toFixed(0)}K
                  </span>
                </div>
              </td>
              <td className="text-right">
                <span
                  className={`text-sm font-medium ${
                    endpoint.avgLatency > 100
                      ? 'text-ctrlx-warning'
                      : endpoint.avgLatency > 200
                        ? 'text-ctrlx-danger'
                        : 'text-gray-700'
                  }`}
                >
                  {endpoint.avgLatency}ms
                </span>
              </td>
              <td className="text-right">
                <span
                  className={`text-sm font-medium ${
                    endpoint.errorRate > 1
                      ? 'text-ctrlx-danger'
                      : endpoint.errorRate > 0.5
                        ? 'text-ctrlx-warning'
                        : 'text-gray-500'
                  }`}
                >
                  {endpoint.errorRate.toFixed(2)}%
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
});

// Demo data generator
export function generateTopEndpointsData(): EndpointStats[] {
  return [
    { method: 'GET', path: '/api/v2/users', requests: 342000, avgLatency: 32, errorRate: 0.12 },
    { method: 'POST', path: '/api/v2/auth/login', requests: 187000, avgLatency: 89, errorRate: 0.45 },
    { method: 'GET', path: '/api/v2/products', requests: 156000, avgLatency: 45, errorRate: 0.08 },
    { method: 'PUT', path: '/api/v2/cart', requests: 98000, avgLatency: 67, errorRate: 0.23 },
    { method: 'GET', path: '/api/v2/orders', requests: 76000, avgLatency: 112, errorRate: 0.34 },
    { method: 'DELETE', path: '/api/v2/sessions', requests: 54000, avgLatency: 23, errorRate: 0.02 },
    { method: 'POST', path: '/api/v2/payments', requests: 43000, avgLatency: 234, errorRate: 1.23 },
    { method: 'GET', path: '/api/v2/inventory', requests: 38000, avgLatency: 56, errorRate: 0.15 },
  ];
}

export default TopEndpointsTable;
