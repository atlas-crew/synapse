import { useMemo } from 'react';
import { Users, TrendingDown, MapPin, Plane, AlertTriangle } from 'lucide-react';
import { clsx } from 'clsx';

export interface EntityConfigData {
  enabled: boolean;
  max_entities: number;
  risk_decay_per_minute: number;
  block_threshold: number;
  max_risk: number;
  max_rules_per_entity: number;
}

export interface TravelConfigData {
  max_speed_kmh: number;
  min_distance_km: number;
  history_window_ms: number;
  max_history_per_user: number;
}

interface EntityConfigProps {
  entityConfig: EntityConfigData;
  travelConfig: TravelConfigData;
  onEntityChange: (config: EntityConfigData) => void;
  onTravelChange: (config: TravelConfigData) => void;
}

interface ValidationErrors {
  block_threshold?: string;
  max_risk?: string;
}

function validateEntityConfig(config: EntityConfigData): ValidationErrors {
  const errors: ValidationErrors = {};

  if (config.block_threshold > config.max_risk) {
    errors.block_threshold = 'Block threshold cannot exceed max risk score';
    errors.max_risk = 'Max risk must be >= block threshold';
  }

  return errors;
}

export function EntityConfig({ entityConfig, travelConfig, onEntityChange, onTravelChange }: EntityConfigProps) {
  const validationErrors = useMemo(() => validateEntityConfig(entityConfig), [entityConfig]);
  const hasErrors = Object.keys(validationErrors).length > 0;

  return (
    <div className="space-y-8">
      {/* Entity Store Section */}
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Users className={clsx("w-5 h-5", entityConfig.enabled ? "text-ac-blue" : "text-ink-muted")} />
            <div>
              <h3 className="text-sm font-medium text-ink-primary">Entity Store</h3>
              <p className="text-xs text-ink-secondary">Per-IP risk tracking and automatic blocking</p>
            </div>
          </div>
          <label className="relative inline-flex items-center cursor-pointer">
            <input
              type="checkbox"
              checked={entityConfig.enabled}
              onChange={(e) => onEntityChange({ ...entityConfig, enabled: e.target.checked })}
              className="sr-only peer"
            />
            <div className="w-11 h-6 bg-surface-subtle peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-ac-blue/20 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-ac-blue"></div>
          </label>
        </div>

        {entityConfig.enabled && (
          <div className="space-y-4 border-t border-border-subtle pt-6">
            {hasErrors && (
              <div className="flex items-center gap-2 p-3 bg-status-error/10 border border-status-error/20 rounded-lg">
                <AlertTriangle className="w-4 h-4 text-status-error flex-shrink-0" />
                <span className="text-xs text-status-error">Configuration has validation errors</span>
              </div>
            )}
            <div className="grid grid-cols-3 gap-4">
            <div className="space-y-1">
              <label className="text-xs font-medium text-ink-secondary">Max Entities</label>
              <input
                type="number"
                min="1000"
                max="1000000"
                step="1000"
                value={entityConfig.max_entities}
                onChange={(e) => onEntityChange({ ...entityConfig, max_entities: parseInt(e.target.value) || 100000 })}
                className="w-full px-3 py-2 bg-surface-base border border-border-subtle rounded text-sm focus:border-ac-blue focus:outline-none transition-colors"
              />
            </div>
            <div className="space-y-1">
              <label className="text-xs font-medium text-ink-secondary flex items-center gap-1">
                <TrendingDown className="w-3 h-3" />
                Risk Decay/min
              </label>
              <input
                type="number"
                min="1"
                max="50"
                value={entityConfig.risk_decay_per_minute}
                onChange={(e) => onEntityChange({ ...entityConfig, risk_decay_per_minute: parseFloat(e.target.value) || 10 })}
                className="w-full px-3 py-2 bg-surface-base border border-border-subtle rounded text-sm focus:border-ac-blue focus:outline-none transition-colors"
              />
            </div>
            <div className="space-y-1">
              <label className="text-xs font-medium text-ink-secondary">Block Threshold</label>
              <input
                type="number"
                min="50"
                max="100"
                value={entityConfig.block_threshold}
                onChange={(e) => onEntityChange({ ...entityConfig, block_threshold: parseFloat(e.target.value) || 70 })}
                className={clsx(
                  "w-full px-3 py-2 bg-surface-base border rounded text-sm focus:outline-none transition-colors",
                  validationErrors.block_threshold
                    ? "border-status-error focus:border-status-error"
                    : "border-border-subtle focus:border-ac-blue"
                )}
              />
              {validationErrors.block_threshold && (
                <p className="text-xs text-status-error">{validationErrors.block_threshold}</p>
              )}
            </div>
            <div className="space-y-1">
              <label className="text-xs font-medium text-ink-secondary">Max Risk Score</label>
              <input
                type="number"
                min="100"
                max="1000"
                value={entityConfig.max_risk}
                onChange={(e) => onEntityChange({ ...entityConfig, max_risk: parseFloat(e.target.value) || 100 })}
                className={clsx(
                  "w-full px-3 py-2 bg-surface-base border rounded text-sm focus:outline-none transition-colors",
                  validationErrors.max_risk
                    ? "border-status-error focus:border-status-error"
                    : "border-border-subtle focus:border-ac-blue"
                )}
              />
              {validationErrors.max_risk && (
                <p className="text-xs text-status-error">{validationErrors.max_risk}</p>
              )}
            </div>
            <div className="space-y-1 col-span-2">
              <label className="text-xs font-medium text-ink-secondary">Max Rules Per Entity</label>
              <input
                type="number"
                min="10"
                max="200"
                value={entityConfig.max_rules_per_entity}
                onChange={(e) => onEntityChange({ ...entityConfig, max_rules_per_entity: parseInt(e.target.value) || 50 })}
                className="w-full px-3 py-2 bg-surface-base border border-border-subtle rounded text-sm focus:border-ac-blue focus:outline-none transition-colors"
              />
            </div>
            </div>
          </div>
        )}
      </div>

      {/* Impossible Travel Section */}
      <div className="space-y-6">
        <div className="flex items-center gap-2">
          <Plane className="w-5 h-5 text-ac-sky-blue" />
          <div>
            <h3 className="text-sm font-medium text-ink-primary">Impossible Travel Detection</h3>
            <p className="text-xs text-ink-secondary">Flag logins from geographically impossible locations</p>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-4 border-t border-border-subtle pt-6">
          <div className="space-y-1">
            <label className="text-xs font-medium text-ink-secondary flex items-center gap-1">
              <MapPin className="w-3 h-3" />
              Max Speed (km/h)
            </label>
            <input
              type="number"
              min="100"
              max="2000"
              value={travelConfig.max_speed_kmh}
              onChange={(e) => onTravelChange({ ...travelConfig, max_speed_kmh: parseFloat(e.target.value) || 800 })}
              className="w-full px-3 py-2 bg-surface-base border border-border-subtle rounded text-sm focus:border-ac-blue focus:outline-none transition-colors"
            />
            <p className="text-xs text-ink-muted">800 km/h ≈ commercial flight</p>
          </div>
          <div className="space-y-1">
            <label className="text-xs font-medium text-ink-secondary">Min Distance (km)</label>
            <input
              type="number"
              min="10"
              max="1000"
              value={travelConfig.min_distance_km}
              onChange={(e) => onTravelChange({ ...travelConfig, min_distance_km: parseFloat(e.target.value) || 100 })}
              className="w-full px-3 py-2 bg-surface-base border border-border-subtle rounded text-sm focus:border-ac-blue focus:outline-none transition-colors"
            />
          </div>
          <div className="space-y-1">
            <label className="text-xs font-medium text-ink-secondary">History Window (hours)</label>
            <input
              type="number"
              min="1"
              max="168"
              value={Math.round(travelConfig.history_window_ms / 3600000)}
              onChange={(e) => onTravelChange({ ...travelConfig, history_window_ms: (parseInt(e.target.value) || 24) * 3600000 })}
              className="w-full px-3 py-2 bg-surface-base border border-border-subtle rounded text-sm focus:border-ac-blue focus:outline-none transition-colors"
            />
          </div>
          <div className="space-y-1">
            <label className="text-xs font-medium text-ink-secondary">Max History/User</label>
            <input
              type="number"
              min="10"
              max="500"
              value={travelConfig.max_history_per_user}
              onChange={(e) => onTravelChange({ ...travelConfig, max_history_per_user: parseInt(e.target.value) || 100 })}
              className="w-full px-3 py-2 bg-surface-base border border-border-subtle rounded text-sm focus:border-ac-blue focus:outline-none transition-colors"
            />
          </div>
        </div>
      </div>
    </div>
  );
}
