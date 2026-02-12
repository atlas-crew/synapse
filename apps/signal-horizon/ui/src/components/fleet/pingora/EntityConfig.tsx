import { useMemo, memo } from 'react';
import { Users, TrendingDown, MapPin, Plane } from 'lucide-react';
import { clsx } from 'clsx';
import {
  DEFAULT_ENTITY_BLOCK_THRESHOLD,
  DEFAULT_ENTITY_MAX_RISK,
  DEFAULT_ENTITY_RISK_DECAY_PER_MINUTE,
  DEFAULT_TRAVEL_MAX_SPEED_KMH,
  DEFAULT_TRAVEL_MIN_DISTANCE_KM,
} from './configDefaults';
// Note: Some DEFAULT_* constants removed since parseIntSafe uses current value as fallback
import { parseIntSafe } from '../../../utils/parseNumeric';
import { Alert, Stack } from '@/ui';

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

export const EntityConfig = memo(function EntityConfig({ entityConfig, travelConfig, onEntityChange, onTravelChange }: EntityConfigProps) {
  const validationErrors = useMemo(() => validateEntityConfig(entityConfig), [entityConfig]);
  const hasErrors = Object.keys(validationErrors).length > 0;

  return (
    <div className="space-y-8">
      {/* Entity Store Section */}
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <Stack direction="row" align="center" gap="sm">
            <Users className={clsx("w-5 h-5", entityConfig.enabled ? "text-ac-blue" : "text-ink-muted")} aria-hidden="true" />
            <div>
              <h3 className="text-sm font-medium text-ink-primary">Entity Store</h3>
              <p className="text-xs text-ink-secondary">Per-IP risk tracking and automatic blocking</p>
            </div>
          </Stack>
          <label className="relative inline-flex items-center cursor-pointer">
            <input
              type="checkbox"
              checked={entityConfig.enabled}
              onChange={(e) => onEntityChange({ ...entityConfig, enabled: e.target.checked })}
              className="sr-only peer"
              aria-label="Enable Entity Store"
            />
            <div className="w-11 h-6 bg-surface-subtle peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-ac-blue/20 peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after: after:h-5 after:w-5 after:transition-all peer-checked:bg-ac-blue"></div>
          </label>
        </div>

        {entityConfig.enabled && (
          <div className="space-y-4 border-t border-border-subtle pt-6">
            {hasErrors && (
              <Alert status="error" title="Configuration Error" style={{ padding: '10px 12px' }}>
                Configuration has validation errors
              </Alert>
            )}
            <div className="grid grid-cols-3 gap-4">
            <div className="space-y-1">
              <label htmlFor="entity-max-entities" className="text-xs font-medium text-ink-secondary">Max Entities</label>
              <input
                id="entity-max-entities"
                type="number"
                min="1000"
                max="1000000"
                step="1000"
                value={entityConfig.max_entities}
                onChange={(e) => onEntityChange({
                  ...entityConfig,
                  max_entities: parseIntSafe(e.target.value, entityConfig.max_entities),
                })}
                className="w-full px-3 py-2 bg-surface-base border border-border-subtle text-sm focus:border-ac-blue focus:outline-none transition-colors"
              />
            </div>
            <div className="space-y-1">
              <Stack direction="row" align="center" gap="xs" className="text-xs font-medium text-ink-secondary">
                <TrendingDown className="w-3 h-3" aria-hidden="true" />
                <label htmlFor="entity-risk-decay">Risk Decay/min</label>
              </Stack>
              <input
                id="entity-risk-decay"
                type="number"
                min="1"
                max="50"
                value={entityConfig.risk_decay_per_minute}
                onChange={(e) => onEntityChange({
                  ...entityConfig,
                  risk_decay_per_minute: parseFloat(e.target.value) || DEFAULT_ENTITY_RISK_DECAY_PER_MINUTE,
                })}
                className="w-full px-3 py-2 bg-surface-base border border-border-subtle text-sm focus:border-ac-blue focus:outline-none transition-colors"
              />
            </div>
            <div className="space-y-1">
              <label className="text-xs font-medium text-ink-secondary">Block Threshold</label>
              <input
                type="number"
                min="50"
                max="100"
                value={entityConfig.block_threshold}
                onChange={(e) => onEntityChange({
                  ...entityConfig,
                  block_threshold: parseFloat(e.target.value) || DEFAULT_ENTITY_BLOCK_THRESHOLD,
                })}
                className={clsx(
                  "w-full px-3 py-2 bg-surface-base border  text-sm focus:outline-none transition-colors",
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
                onChange={(e) => onEntityChange({
                  ...entityConfig,
                  max_risk: parseFloat(e.target.value) || DEFAULT_ENTITY_MAX_RISK,
                })}
                className={clsx(
                  "w-full px-3 py-2 bg-surface-base border  text-sm focus:outline-none transition-colors",
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
                onChange={(e) => onEntityChange({
                  ...entityConfig,
                  max_rules_per_entity: parseIntSafe(e.target.value, entityConfig.max_rules_per_entity),
                })}
                className="w-full px-3 py-2 bg-surface-base border border-border-subtle text-sm focus:border-ac-blue focus:outline-none transition-colors"
              />
            </div>
            </div>
          </div>
        )}
      </div>

      {/* Impossible Travel Section */}
      <div className="space-y-6">
        <Stack direction="row" align="center" gap="sm">
          <Plane className="w-5 h-5 text-ac-sky-blue" aria-hidden="true" />
          <div>
            <h3 className="text-sm font-medium text-ink-primary">Impossible Travel Detection</h3>
            <p className="text-xs text-ink-secondary">Flag logins from geographically impossible locations</p>
          </div>
        </Stack>

        <div className="grid grid-cols-2 gap-4 border-t border-border-subtle pt-6">
          <div className="space-y-1">
            <Stack direction="row" align="center" gap="xs" className="text-xs font-medium text-ink-secondary">
              <MapPin className="w-3 h-3" aria-hidden="true" />
              <label htmlFor="travel-max-speed">Max Speed (km/h)</label>
            </Stack>
            <input
              id="travel-max-speed"
              type="number"
              min="100"
              max="2000"
              value={travelConfig.max_speed_kmh}
              onChange={(e) => onTravelChange({
                ...travelConfig,
                max_speed_kmh: parseFloat(e.target.value) || DEFAULT_TRAVEL_MAX_SPEED_KMH,
              })}
              className="w-full px-3 py-2 bg-surface-base border border-border-subtle text-sm focus:border-ac-blue focus:outline-none transition-colors"
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
              onChange={(e) => onTravelChange({
                ...travelConfig,
                min_distance_km: parseFloat(e.target.value) || DEFAULT_TRAVEL_MIN_DISTANCE_KM,
              })}
              className="w-full px-3 py-2 bg-surface-base border border-border-subtle text-sm focus:border-ac-blue focus:outline-none transition-colors"
            />
          </div>
          <div className="space-y-1">
            <label className="text-xs font-medium text-ink-secondary">History Window (hours)</label>
              <input
                type="number"
                min="1"
                max="168"
                value={Math.round(travelConfig.history_window_ms / 3600000)}
                onChange={(e) => onTravelChange({
                  ...travelConfig,
                  history_window_ms: parseIntSafe(e.target.value, Math.round(travelConfig.history_window_ms / 3600000)) * 3600000,
                })}
                className="w-full px-3 py-2 bg-surface-base border border-border-subtle text-sm focus:border-ac-blue focus:outline-none transition-colors"
              />
          </div>
          <div className="space-y-1">
            <label className="text-xs font-medium text-ink-secondary">Max History/User</label>
            <input
              type="number"
              min="10"
              max="500"
              value={travelConfig.max_history_per_user}
              onChange={(e) => onTravelChange({
                ...travelConfig,
                max_history_per_user: parseIntSafe(e.target.value, travelConfig.max_history_per_user),
              })}
              className="w-full px-3 py-2 bg-surface-base border border-border-subtle text-sm focus:border-ac-blue focus:outline-none transition-colors"
            />
          </div>
        </div>
      </div>
    </div>
  );
});
