/**
 * Services Page
 * Endpoints grouped by service with metrics
 */

import { useState, useMemo } from 'react';
import { motion } from 'framer-motion';
import {
  Server,
  ChevronDown,
  ChevronRight,
  Activity,
  Clock,
  AlertTriangle,
  CheckCircle,
} from 'lucide-react';
import { clsx } from 'clsx';
// import { useApexEndpoints } from '../../../stores/apexStore';
import { StatsGridSkeleton, CardSkeleton } from '../../../components/LoadingStates';

// Demo data - services with endpoints
const DEMO_SERVICES = [
  {
    name: 'user-service',
    description: 'User management and authentication',
    endpoints: 8,
    totalRequests: 2500000,
    avgLatencyMs: 65,
    errorRate: 1.2,
    status: 'healthy' as const,
  },
  {
    name: 'product-service',
    description: 'Product catalog and inventory',
    endpoints: 12,
    totalRequests: 8900000,
    avgLatencyMs: 42,
    errorRate: 0.4,
    status: 'healthy' as const,
  },
  {
    name: 'order-service',
    description: 'Order processing and fulfillment',
    endpoints: 6,
    totalRequests: 980000,
    avgLatencyMs: 145,
    errorRate: 2.8,
    status: 'degraded' as const,
  },
  {
    name: 'search-service',
    description: 'Full-text search and filtering',
    endpoints: 3,
    totalRequests: 4200000,
    avgLatencyMs: 220,
    errorRate: 0.6,
    status: 'healthy' as const,
  },
  {
    name: 'auth-service',
    description: 'Authentication and authorization',
    endpoints: 5,
    totalRequests: 1800000,
    avgLatencyMs: 95,
    errorRate: 3.2,
    status: 'degraded' as const,
  },
  {
    name: 'payment-service',
    description: 'Payment processing',
    endpoints: 4,
    totalRequests: 450000,
    avgLatencyMs: 180,
    errorRate: 0.8,
    status: 'healthy' as const,
  },
];

const DEMO_SERVICE_ENDPOINTS: Record<string, Array<{
  method: string;
  path: string;
  requestCount: number;
  avgLatencyMs: number;
  errorRate: number;
}>> = {
  'user-service': [
    { method: 'GET', path: '/api/v1/users', requestCount: 850000, avgLatencyMs: 45, errorRate: 0.5 },
    { method: 'POST', path: '/api/v1/users', requestCount: 120000, avgLatencyMs: 85, errorRate: 1.2 },
    { method: 'GET', path: '/api/v1/users/:id', requestCount: 650000, avgLatencyMs: 38, errorRate: 0.3 },
    { method: 'PUT', path: '/api/v1/users/:id', requestCount: 95000, avgLatencyMs: 72, errorRate: 0.8 },
    { method: 'DELETE', path: '/api/v1/users/:id', requestCount: 25000, avgLatencyMs: 55, errorRate: 0.4 },
  ],
  'product-service': [
    { method: 'GET', path: '/api/v1/products', requestCount: 4200000, avgLatencyMs: 32, errorRate: 0.2 },
    { method: 'GET', path: '/api/v1/products/:id', requestCount: 2800000, avgLatencyMs: 28, errorRate: 0.3 },
    { method: 'POST', path: '/api/v1/products', requestCount: 85000, avgLatencyMs: 95, errorRate: 1.1 },
    { method: 'PUT', path: '/api/v1/products/:id', requestCount: 62000, avgLatencyMs: 88, errorRate: 0.9 },
  ],
  'order-service': [
    { method: 'POST', path: '/api/v1/orders', requestCount: 320000, avgLatencyMs: 180, errorRate: 3.2 },
    { method: 'GET', path: '/api/v1/orders', requestCount: 450000, avgLatencyMs: 95, errorRate: 1.5 },
    { method: 'GET', path: '/api/v1/orders/:id', requestCount: 210000, avgLatencyMs: 65, errorRate: 0.8 },
  ],
  'search-service': [
    { method: 'GET', path: '/api/v1/search', requestCount: 3800000, avgLatencyMs: 220, errorRate: 0.5 },
    { method: 'POST', path: '/api/v1/search/advanced', requestCount: 400000, avgLatencyMs: 320, errorRate: 1.2 },
  ],
  'auth-service': [
    { method: 'POST', path: '/api/v1/auth/login', requestCount: 850000, avgLatencyMs: 95, errorRate: 3.5 },
    { method: 'POST', path: '/api/v1/auth/logout', requestCount: 420000, avgLatencyMs: 25, errorRate: 0.2 },
    { method: 'POST', path: '/api/v1/auth/refresh', requestCount: 380000, avgLatencyMs: 45, errorRate: 2.1 },
    { method: 'POST', path: '/api/v1/auth/verify', requestCount: 150000, avgLatencyMs: 35, errorRate: 4.8 },
  ],
  'payment-service': [
    { method: 'POST', path: '/api/v1/payments', requestCount: 180000, avgLatencyMs: 250, errorRate: 1.2 },
    { method: 'GET', path: '/api/v1/payments/:id', requestCount: 220000, avgLatencyMs: 65, errorRate: 0.3 },
    { method: 'POST', path: '/api/v1/payments/:id/refund', requestCount: 15000, avgLatencyMs: 180, errorRate: 0.5 },
  ],
};

const METHOD_COLORS: Record<string, string> = {
  GET: 'text-green-400 bg-green-500/20',
  POST: 'text-blue-400 bg-blue-500/20',
  PUT: 'text-yellow-400 bg-yellow-500/20',
  PATCH: 'text-orange-400 bg-orange-500/20',
  DELETE: 'text-red-400 bg-red-500/20',
};

// Stat Card
function StatCard({
  label,
  value,
  icon: Icon,
}: {
  label: string;
  value: string;
  icon: React.ElementType;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="bg-gray-800 border border-gray-700 rounded-xl p-5"
    >
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-gray-400">{label}</p>
          <p className="mt-1 text-2xl font-bold text-white">{value}</p>
        </div>
        <div className="p-3 bg-gray-700/50 rounded-lg">
          <Icon className="w-6 h-6 text-horizon-400" />
        </div>
      </div>
    </motion.div>
  );
}

// Service Card Component
function ServiceCard({
  service,
  isExpanded,
  onToggle,
  endpoints,
}: {
  service: typeof DEMO_SERVICES[0];
  isExpanded: boolean;
  onToggle: () => void;
  endpoints: typeof DEMO_SERVICE_ENDPOINTS['user-service'];
}) {
  const statusConfig = {
    healthy: { color: 'text-green-400', icon: CheckCircle, label: 'Healthy' },
    degraded: { color: 'text-yellow-400', icon: AlertTriangle, label: 'Degraded' },
    down: { color: 'text-red-400', icon: AlertTriangle, label: 'Down' },
  };

  const status = statusConfig[service.status];
  const StatusIcon = status.icon;

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="bg-gray-800 border border-gray-700 rounded-xl overflow-hidden"
    >
      {/* Service Header */}
      <button
        onClick={onToggle}
        className="w-full px-5 py-4 flex items-center justify-between hover:bg-gray-750 transition-colors"
      >
        <div className="flex items-center gap-4">
          <div className="p-2 bg-gray-700 rounded-lg">
            <Server className="w-5 h-5 text-horizon-400" />
          </div>
          <div className="text-left">
            <h3 className="text-white font-medium">{service.name}</h3>
            <p className="text-sm text-gray-400">{service.description}</p>
          </div>
        </div>
        <div className="flex items-center gap-6">
          <div className="text-right">
            <p className="text-sm text-gray-400">Endpoints</p>
            <p className="text-white font-medium">{service.endpoints}</p>
          </div>
          <div className="text-right">
            <p className="text-sm text-gray-400">Requests</p>
            <p className="text-white font-medium">
              {(service.totalRequests / 1000000).toFixed(1)}M
            </p>
          </div>
          <div className="text-right">
            <p className="text-sm text-gray-400">Latency</p>
            <p className="text-white font-medium">{service.avgLatencyMs}ms</p>
          </div>
          <div className="text-right">
            <p className="text-sm text-gray-400">Error Rate</p>
            <p
              className={clsx(
                'font-medium',
                service.errorRate < 1
                  ? 'text-green-400'
                  : service.errorRate < 2
                  ? 'text-yellow-400'
                  : 'text-red-400'
              )}
            >
              {service.errorRate.toFixed(1)}%
            </p>
          </div>
          <div className={clsx('flex items-center gap-1', status.color)}>
            <StatusIcon className="w-4 h-4" />
            <span className="text-sm">{status.label}</span>
          </div>
          {isExpanded ? (
            <ChevronDown className="w-5 h-5 text-gray-400" />
          ) : (
            <ChevronRight className="w-5 h-5 text-gray-400" />
          )}
        </div>
      </button>

      {/* Expanded Endpoints List */}
      {isExpanded && endpoints && (
        <div className="border-t border-gray-700">
          <table className="w-full">
            <thead>
              <tr className="text-left text-sm text-gray-400 bg-gray-800/50">
                <th className="px-5 py-2 font-medium">Endpoint</th>
                <th className="px-5 py-2 font-medium text-right">Requests</th>
                <th className="px-5 py-2 font-medium text-right">Latency</th>
                <th className="px-5 py-2 font-medium text-right">Error Rate</th>
              </tr>
            </thead>
            <tbody>
              {endpoints.map((endpoint, idx) => (
                <tr
                  key={idx}
                  className="border-t border-gray-700/50 hover:bg-gray-750 transition-colors"
                >
                  <td className="px-5 py-3">
                    <div className="flex items-center gap-3">
                      <span
                        className={clsx(
                          'px-2 py-0.5 rounded text-xs font-medium',
                          METHOD_COLORS[endpoint.method]
                        )}
                      >
                        {endpoint.method}
                      </span>
                      <code className="text-blue-400 text-sm">{endpoint.path}</code>
                    </div>
                  </td>
                  <td className="px-5 py-3 text-right text-gray-300">
                    {endpoint.requestCount.toLocaleString()}
                  </td>
                  <td className="px-5 py-3 text-right text-white">
                    {endpoint.avgLatencyMs}ms
                  </td>
                  <td className="px-5 py-3 text-right">
                    <span
                      className={clsx(
                        'px-2 py-0.5 rounded text-xs font-medium',
                        endpoint.errorRate < 1
                          ? 'text-green-400 bg-green-500/20'
                          : endpoint.errorRate < 2
                          ? 'text-yellow-400 bg-yellow-500/20'
                          : 'text-red-400 bg-red-500/20'
                      )}
                    >
                      {endpoint.errorRate.toFixed(1)}%
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </motion.div>
  );
}

export default function ServicesPage() {
  const [expandedServices, setExpandedServices] = useState<Set<string>>(new Set());
  // Store integration will be added when backend is ready
  // const storeEndpoints = useApexEndpoints();
  const isLoading = false;

  // Use demo data for now
  const services = DEMO_SERVICES;

  // Calculate stats
  const stats = useMemo(() => {
    const totalServices = services.length;
    const healthyServices = services.filter((s) => s.status === 'healthy').length;
    const totalEndpoints = services.reduce((sum, s) => sum + s.endpoints, 0);
    const totalRequests = services.reduce((sum, s) => sum + s.totalRequests, 0);

    return { totalServices, healthyServices, totalEndpoints, totalRequests };
  }, [services]);

  const toggleService = (serviceName: string) => {
    const newExpanded = new Set(expandedServices);
    if (newExpanded.has(serviceName)) {
      newExpanded.delete(serviceName);
    } else {
      newExpanded.add(serviceName);
    }
    setExpandedServices(newExpanded);
  };

  if (isLoading) {
    return (
      <div className="p-6 space-y-6">
        <div>
          <h1 className="text-2xl font-bold text-white">Services</h1>
          <p className="text-gray-400 mt-1">Loading service data...</p>
        </div>
        <StatsGridSkeleton />
        <CardSkeleton />
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white">Services</h1>
        <p className="text-gray-400 mt-1">Endpoints grouped by service</p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-4 gap-4">
        <StatCard label="Total Services" value={stats.totalServices.toString()} icon={Server} />
        <StatCard
          label="Healthy Services"
          value={`${stats.healthyServices}/${stats.totalServices}`}
          icon={CheckCircle}
        />
        <StatCard label="Total Endpoints" value={stats.totalEndpoints.toString()} icon={Activity} />
        <StatCard
          label="Total Requests"
          value={`${(stats.totalRequests / 1000000).toFixed(1)}M`}
          icon={Clock}
        />
      </div>

      {/* Services List */}
      <div className="space-y-4">
        {services.map((service) => (
          <ServiceCard
            key={service.name}
            service={service}
            isExpanded={expandedServices.has(service.name)}
            onToggle={() => toggleService(service.name)}
            endpoints={DEMO_SERVICE_ENDPOINTS[service.name] || []}
          />
        ))}
      </div>
    </div>
  );
}
