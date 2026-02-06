import { LiveAttackMap } from '../../components/soc/LiveAttackMap';
import { Shield, Globe } from 'lucide-react';
import { useDocumentTitle } from '../../hooks/useDocumentTitle';

export default function LiveMapPage() {
  useDocumentTitle('SOC - Live Map');
  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-light text-ink-primary">Live Threat Map</h1>
          <p className="text-ink-secondary mt-1">
            Real-time visualization of fleet-wide attack vectors
          </p>
        </div>
        <div className="flex items-center gap-2 px-3 py-2 border border-border-subtle bg-surface-card">
          <Globe className="w-4 h-4 text-ac-blue" />
          <span className="text-sm text-ink-secondary">
            Global Fleet Connected
          </span>
          <span className="w-2 h-2 bg-ac-green animate-pulse" />
        </div>
      </div>

      <div className="grid grid-cols-1 gap-6">
        <LiveAttackMap />
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="card p-4">
            <h3 className="text-sm font-medium text-ink-secondary mb-2 flex items-center gap-2">
              <span className="w-2 h-2 bg-ac-red" />
              Critical Threats (Last 5m)
            </h3>
            <span className="text-2xl font-mono text-ink-primary">142</span>
          </div>
          <div className="card p-4">
            <h3 className="text-sm font-medium text-ink-secondary mb-2 flex items-center gap-2">
              <span className="w-2 h-2 bg-ac-orange" />
              High Severity
            </h3>
            <span className="text-2xl font-mono text-ink-primary">853</span>
          </div>
           <div className="card p-4">
            <h3 className="text-sm font-medium text-ink-secondary mb-2 flex items-center gap-2">
              <Shield className="w-4 h-4 text-ac-green" />
              Auto-Blocked
            </h3>
            <span className="text-2xl font-mono text-ink-primary">98.4%</span>
          </div>
        </div>
      </div>
    </div>
  );
}
