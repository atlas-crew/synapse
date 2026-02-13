/**
 * RolloutManager Component
 * Multi-step wizard for configuring and executing fleet rollouts,
 * plus progress monitoring for active rollouts
 */

import { memo, useState, useCallback, useMemo, useEffect } from 'react';
import {
  Check,
  ChevronLeft,
  ChevronRight,
  Package,
  Settings,
  Users,
  ClipboardCheck,
  AlertTriangle,
  Download,
  CheckCircle2,
  XCircle,
  Clock,
  Zap,
  GitBranch,
  Layers,
  Search,
  Play,
  Square,
  Info,
} from 'lucide-react';
import { clsx } from 'clsx';
import { parseIntSafe } from '../../utils/parseNumeric';
import type {
  Release,
  Rollout,
  RolloutConfig,
  RolloutStrategy,
  RolloutProgress,
  RolloutProgressStatus,
} from '../../hooks/fleet/useReleases';
import { useSensors } from '../../hooks/fleet/useSensors';
import { Modal, Spinner, Stack, colors } from '@/ui';

// ============================================================================
// Types
// ============================================================================

export interface RolloutManagerProps {
  /** Available releases to deploy */
  releases: Release[];
  /** Active rollout (if any) */
  activeRollout?: Rollout | null;
  /** Whether a rollout is currently being started */
  isStartingRollout?: boolean;
  /** Whether a rollout is currently being cancelled */
  isCancellingRollout?: boolean;
  /** Callback when rollout starts */
  onRolloutStart?: (releaseId: string, config: RolloutConfig) => Promise<Rollout | void>;
  /** Callback when rollout is cancelled */
  onRolloutCancel?: (rolloutId: string) => Promise<void>;
  /** Callback when rollout completes */
  onRolloutComplete?: (rollout: Rollout) => void;
  /** Additional CSS classes */
  className?: string;
}

type WizardStep = 'release' | 'strategy' | 'targets' | 'review';

// ============================================================================
// Constants
// ============================================================================

const WIZARD_STEPS: { key: WizardStep; label: string; icon: React.ReactNode }[] = [
  { key: 'release', label: 'Select Release', icon: <Package className="w-4 h-4" /> },
  { key: 'strategy', label: 'Configure Strategy', icon: <Settings className="w-4 h-4" /> },
  { key: 'targets', label: 'Select Targets', icon: <Users className="w-4 h-4" /> },
  { key: 'review', label: 'Review & Deploy', icon: <ClipboardCheck className="w-4 h-4" /> },
];

const STRATEGY_OPTIONS: { value: RolloutStrategy; label: string; description: string; icon: React.ReactNode }[] = [
  {
    value: 'immediate',
    label: 'Immediate',
    description: 'Deploy to all sensors simultaneously. Fastest but highest risk.',
    icon: <Zap className="w-5 h-5" />,
  },
  {
    value: 'canary',
    label: 'Canary (10%)',
    description: 'Deploy to 10% of sensors first, then continue after validation.',
    icon: <GitBranch className="w-5 h-5" />,
  },
  {
    value: 'rolling',
    label: 'Rolling (Batched)',
    description: 'Deploy in configurable batches with delays between each.',
    icon: <Layers className="w-5 h-5" />,
  },
];

const STATUS_CONFIG: Record<
  RolloutProgressStatus,
  { label: string; icon: React.ReactNode; className: string }
> = {
  pending: {
    label: 'Pending',
    icon: <Clock className="w-3.5 h-3.5" />,
    className: 'text-ink-muted bg-surface-subtle border-border-subtle',
  },
  downloading: {
    label: 'Downloading',
    icon: <Download className="w-3.5 h-3.5 animate-pulse" />,
    className: 'text-ac-blue bg-ac-blue/10 border-ac-blue/30',
  },
  ready: {
    label: 'Ready',
    icon: <CheckCircle2 className="w-3.5 h-3.5" />,
    className: 'text-ac-orange bg-ac-orange/10 border-ac-orange/30',
  },
  activated: {
    label: 'Activated',
    icon: <Check className="w-3.5 h-3.5" />,
    className: 'text-status-success bg-status-success/10 border-status-success/30',
  },
  failed: {
    label: 'Failed',
    icon: <XCircle className="w-3.5 h-3.5" />,
    className: 'text-status-error bg-status-error/10 border-status-error/30',
  },
};

// ============================================================================
// Helper Functions
// ============================================================================

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

function formatDate(dateString: string): string {
  return new Date(dateString).toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  });
}

function formatRelativeTime(dateString: string): string {
  const date = new Date(dateString);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);

  if (diffMins < 1) return 'just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  return `${diffDays}d ago`;
}

function extractSensorTags(sensors: Array<{ id: string; name: string; region: string; version: string }>): string[] {
  const tags = new Set<string>();
  tags.add('all');

  for (const sensor of sensors) {
    // Add region as tag
    tags.add(sensor.region);
    // Add version as tag
    tags.add(`v${sensor.version}`);
    // Add environment detection from name
    if (sensor.name.includes('prod')) tags.add('production');
    if (sensor.name.includes('stag')) tags.add('staging');
    if (sensor.name.includes('dev')) tags.add('development');
  }

  return Array.from(tags).sort();
}

// ============================================================================
// Sub-Components
// ============================================================================

/** Step indicator for wizard */
const StepIndicator = memo(function StepIndicator({
  steps,
  currentStep,
  onStepClick,
}: {
  steps: typeof WIZARD_STEPS;
  currentStep: WizardStep;
  onStepClick?: (step: WizardStep) => void;
}) {
  const currentIndex = steps.findIndex((s) => s.key === currentStep);

  return (
    <div className="flex items-center justify-between px-6 py-4 bg-surface-raised border-b border-border-subtle">
      {steps.map((step, index) => {
        const isActive = step.key === currentStep;
        const isCompleted = index < currentIndex;
        const isClickable = onStepClick && index <= currentIndex;

        return (
          <div key={step.key} className="flex items-center">
            {/* Step circle */}
            <button
              onClick={() => isClickable && onStepClick(step.key)}
              disabled={!isClickable}
              className={clsx(
                'px-3 py-1.5 transition-colors',
                isActive && 'bg-ac-blue text-white',
                isCompleted && 'bg-status-success/10 text-status-success',
                !isActive && !isCompleted && 'bg-surface-subtle text-ink-muted',
                isClickable && 'cursor-pointer hover:opacity-80',
                !isClickable && 'cursor-default'
              )}
            >
              <Stack as="span" direction="row" inline align="center" gap="sm">
                {isCompleted ? <Check className="w-4 h-4" /> : step.icon}
                <span className="text-xs font-medium hidden sm:inline">{step.label}</span>
              </Stack>
            </button>

            {/* Connector line */}
            {index < steps.length - 1 && (
              <div
                className={clsx(
                  'w-8 h-0.5 mx-2',
                  index < currentIndex ? 'bg-status-success' : 'bg-border-subtle'
                )}
              />
            )}
          </div>
        );
      })}
    </div>
  );
});

/** Release card for selection */
const ReleaseCard = memo(function ReleaseCard({
  release,
  isSelected,
  isLatest,
  onClick,
}: {
  release: Release;
  isSelected: boolean;
  isLatest: boolean;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className={clsx(
        'w-full p-4 text-left border transition-all',
        isSelected
          ? 'border-ac-blue bg-ac-blue/5 ring-1 ring-ac-blue/50'
          : 'border-border-subtle hover:border-ink-muted hover:bg-surface-subtle'
      )}
    >
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <Stack direction="row" align="center" gap="sm">
            <span className="text-lg font-semibold text-ink-primary">v{release.version}</span>
            {isLatest && (
              <span className="px-2 py-0.5 text-xs font-medium bg-status-success/10 text-status-success border border-status-success/30">
                Latest
              </span>
            )}
          </Stack>
          <div className="mt-1 text-xs text-ink-muted">
            {formatDate(release.createdAt)} - {formatBytes(release.size)}
          </div>
        </div>
        <div
          className={clsx(
            'w-5 h-5 border-2 flex items-center justify-center',
            isSelected ? 'border-ac-blue bg-ac-blue' : 'border-border-subtle'
          )}
        >
          {isSelected && <Check className="w-3 h-3 text-white" />}
        </div>
      </div>

      {/* Changelog preview */}
      <div className="mt-3 text-xs text-ink-secondary line-clamp-2">
        {release.changelog.split('\n').find((line) => !line.startsWith('#')) || 'No description'}
      </div>
    </button>
  );
});

/** Strategy option card */
const StrategyCard = memo(function StrategyCard({
  option,
  isSelected,
  onClick,
}: {
  option: (typeof STRATEGY_OPTIONS)[0];
  isSelected: boolean;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className={clsx(
        'w-full p-4 text-left border transition-all',
        isSelected
          ? 'border-ac-blue bg-ac-blue/5 ring-1 ring-ac-blue/50'
          : 'border-border-subtle hover:border-ink-muted hover:bg-surface-subtle'
      )}
    >
      <div className="flex items-start gap-3">
        <div
          className={clsx(
            'p-2',
            isSelected ? 'bg-ac-blue/10 text-ac-blue' : 'bg-surface-subtle text-ink-muted'
          )}
        >
          {option.icon}
        </div>
        <div className="flex-1">
          <div className="flex items-center justify-between">
            <span className="font-medium text-ink-primary">{option.label}</span>
            <div
              className={clsx(
                'w-5 h-5 border-2 flex items-center justify-center',
                isSelected ? 'border-ac-blue bg-ac-blue' : 'border-border-subtle'
              )}
            >
              {isSelected && <Check className="w-3 h-3 text-white" />}
            </div>
          </div>
          <p className="mt-1 text-sm text-ink-secondary">{option.description}</p>
        </div>
      </div>
    </button>
  );
});

/** Sensor progress card */
const SensorProgressCard = memo(function SensorProgressCard({ progress }: { progress: RolloutProgress }) {
  const config = STATUS_CONFIG[progress.status];

  return (
    <div className="p-3 bg-surface-card border border-border-subtle">
      <div className="flex items-center justify-between">
        <span className="text-sm font-medium text-ink-primary truncate">{progress.sensorName}</span>
        <Stack
          direction="row"
          inline
          align="center"
          gap="xs"
          className={clsx(
            'px-2 py-0.5 text-xs font-medium border',
            config.className
          )}
        >
          {config.icon}
          <span>{config.label}</span>
        </Stack>
      </div>
      {progress.error && (
        <div className="mt-2 p-2 bg-status-error/10 border border-status-error/20 text-xs text-status-error">
          {progress.error}
        </div>
      )}
      <div className="mt-1 text-xs text-ink-muted">{formatRelativeTime(progress.updatedAt)}</div>
    </div>
  );
});

// ============================================================================
// Main Component
// ============================================================================

export const RolloutManager = memo(function RolloutManager({
  releases,
  activeRollout,
  isStartingRollout = false,
  isCancellingRollout = false,
  onRolloutStart,
  onRolloutCancel,
  onRolloutComplete,
  className = '',
}: RolloutManagerProps) {
  // Wizard state
  const [currentStep, setCurrentStep] = useState<WizardStep>('release');
  const [selectedReleaseId, setSelectedReleaseId] = useState<string | null>(null);
  const [strategy, setStrategy] = useState<RolloutStrategy>('rolling');
  const [batchSize, setBatchSize] = useState(10);
  const [batchDelay, setBatchDelay] = useState(60);
  const [selectedTags, setSelectedTags] = useState<string[]>(['all']);
  const [sensorSearch, setSensorSearch] = useState('');
  const [showConfirmCancel, setShowConfirmCancel] = useState(false);

  // Get sensors for target selection
  const { data: sensors = [] } = useSensors();

  // Extract available tags from sensors
  const availableTags = useMemo(() => extractSensorTags(sensors), [sensors]);

  // Filter sensors based on selected tags and search
  const filteredSensors = useMemo(() => {
    return sensors.filter((sensor) => {
      // Search filter
      if (sensorSearch && !sensor.name.toLowerCase().includes(sensorSearch.toLowerCase())) {
        return false;
      }

      // Tag filter (if not "all")
      if (!selectedTags.includes('all')) {
        const sensorTags = [
          sensor.region,
          `v${sensor.version}`,
          sensor.name.includes('prod') ? 'production' : null,
          sensor.name.includes('stag') ? 'staging' : null,
          sensor.name.includes('dev') ? 'development' : null,
        ].filter(Boolean) as string[];

        return selectedTags.some((tag) => sensorTags.includes(tag));
      }

      return true;
    });
  }, [sensors, selectedTags, sensorSearch]);

  // Selected release
  const selectedRelease = releases.find((r) => r.id === selectedReleaseId);

  // Progress calculations for active rollout
  const rolloutProgress = useMemo(() => {
    if (!activeRollout) return null;

    const total = activeRollout.progress.length;
    const completed = activeRollout.progress.filter((p) => p.status === 'activated').length;
    const failed = activeRollout.progress.filter((p) => p.status === 'failed').length;
    const inProgress = activeRollout.progress.filter(
      (p) => p.status === 'downloading' || p.status === 'ready'
    ).length;
    const pending = activeRollout.progress.filter((p) => p.status === 'pending').length;

    const percentage = total > 0 ? Math.round((completed / total) * 100) : 0;

    return { total, completed, failed, inProgress, pending, percentage };
  }, [activeRollout]);

  // Detect rollout completion
  useEffect(() => {
    if (activeRollout && rolloutProgress && rolloutProgress.pending === 0 && rolloutProgress.inProgress === 0) {
      if (activeRollout.status === 'in_progress') {
        onRolloutComplete?.(activeRollout);
      }
    }
  }, [activeRollout, rolloutProgress, onRolloutComplete]);

  // Navigation handlers
  const handleNext = useCallback(() => {
    const stepIndex = WIZARD_STEPS.findIndex((s) => s.key === currentStep);
    if (stepIndex < WIZARD_STEPS.length - 1) {
      setCurrentStep(WIZARD_STEPS[stepIndex + 1].key);
    }
  }, [currentStep]);

  const handleBack = useCallback(() => {
    const stepIndex = WIZARD_STEPS.findIndex((s) => s.key === currentStep);
    if (stepIndex > 0) {
      setCurrentStep(WIZARD_STEPS[stepIndex - 1].key);
    }
  }, [currentStep]);

  const handleStepClick = useCallback((step: WizardStep) => {
    setCurrentStep(step);
  }, []);

  // Tag toggle handler
  const handleTagToggle = useCallback((tag: string) => {
    setSelectedTags((prev) => {
      if (tag === 'all') {
        return ['all'];
      }

      const newTags = prev.filter((t) => t !== 'all');

      if (prev.includes(tag)) {
        const filtered = newTags.filter((t) => t !== tag);
        return filtered.length === 0 ? ['all'] : filtered;
      }

      return [...newTags, tag];
    });
  }, []);

  // Start rollout handler
  const handleStartRollout = useCallback(async () => {
    if (!selectedReleaseId || !onRolloutStart) return;

    const config: RolloutConfig = {
      strategy,
      targetTags: selectedTags,
      batchSize: strategy === 'rolling' ? batchSize : filteredSensors.length,
      batchDelay: strategy === 'rolling' ? batchDelay : 0,
    };

    await onRolloutStart(selectedReleaseId, config);

    // Reset wizard
    setCurrentStep('release');
    setSelectedReleaseId(null);
    setStrategy('rolling');
    setBatchSize(10);
    setBatchDelay(60);
    setSelectedTags(['all']);
  }, [selectedReleaseId, strategy, selectedTags, batchSize, batchDelay, filteredSensors.length, onRolloutStart]);

  // Cancel rollout handler
  const handleCancelRollout = useCallback(async () => {
    if (!activeRollout || !onRolloutCancel) return;
    await onRolloutCancel(activeRollout.id);
    setShowConfirmCancel(false);
  }, [activeRollout, onRolloutCancel]);

  // Check if can proceed to next step
  const canProceed = useMemo(() => {
    switch (currentStep) {
      case 'release':
        return !!selectedReleaseId;
      case 'strategy':
        return true;
      case 'targets':
        return filteredSensors.length > 0;
      case 'review':
        return true;
      default:
        return false;
    }
  }, [currentStep, selectedReleaseId, filteredSensors.length]);

  // If there's an active rollout, show progress view
  if (activeRollout && (activeRollout.status === 'in_progress' || activeRollout.status === 'pending')) {
    return (
      <div className={clsx('bg-surface-card border border-border-subtle overflow-hidden', className)}>
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 bg-surface-raised border-b border-border-subtle">
          <Stack direction="row" align="center" gap="smPlus">
            <div className="p-2 bg-ac-blue/10">
              <Layers className="w-5 h-5 text-ac-blue" />
            </div>
            <div>
              <h3 className="text-lg font-semibold text-ink-primary">Active Rollout</h3>
              <p className="text-sm text-ink-secondary">
                v{activeRollout.release.version} - {activeRollout.strategy} strategy
              </p>
            </div>
          </Stack>
          <button
            onClick={() => setShowConfirmCancel(true)}
            disabled={isCancellingRollout}
            className="px-4 py-2 text-sm font-medium text-status-error bg-status-error/10 border border-status-error/30 hover:bg-status-error/20 transition-colors disabled:opacity-50"
          >
            <Stack as="span" direction="row" inline align="center" gap="sm">
              {isCancellingRollout ? (
                <Spinner size={16} color={colors.red} />
              ) : (
                <Square className="w-4 h-4" />
              )}
              Cancel Rollout
            </Stack>
          </button>
        </div>

        {/* Progress overview */}
        {rolloutProgress && (
          <div className="p-6 border-b border-border-subtle">
            <div className="flex items-center justify-between mb-3">
              <span className="text-sm font-medium text-ink-primary">Overall Progress</span>
              <span className="text-sm font-semibold text-ac-blue">{rolloutProgress.percentage}%</span>
            </div>
            <div className="w-full h-3 bg-surface-subtle overflow-hidden">
              <div
                className="h-full bg-ac-blue transition-all duration-500"
                style={{ width: `${rolloutProgress.percentage}%` }}
              />
            </div>
            <div className="mt-3 grid grid-cols-4 gap-4 text-center">
              <div>
                <div className="text-lg font-semibold text-status-success">{rolloutProgress.completed}</div>
                <div className="text-xs text-ink-muted">Activated</div>
              </div>
              <div>
                <div className="text-lg font-semibold text-ac-blue">{rolloutProgress.inProgress}</div>
                <div className="text-xs text-ink-muted">In Progress</div>
              </div>
              <div>
                <div className="text-lg font-semibold text-ink-muted">{rolloutProgress.pending}</div>
                <div className="text-xs text-ink-muted">Pending</div>
              </div>
              <div>
                <div className="text-lg font-semibold text-status-error">{rolloutProgress.failed}</div>
                <div className="text-xs text-ink-muted">Failed</div>
              </div>
            </div>
          </div>
        )}

        {/* Sensor progress grid */}
        <div className="p-6">
          <div className="flex items-center justify-between mb-4">
            <h4 className="text-sm font-medium text-ink-primary">Sensor Status</h4>
            <span className="text-xs text-ink-muted">{activeRollout.progress.length} sensors</span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 max-h-96 overflow-y-auto">
            {activeRollout.progress.map((progress) => (
              <SensorProgressCard key={progress.sensorId} progress={progress} />
            ))}
          </div>
        </div>

        {/* Cancel confirmation dialog */}
        {showConfirmCancel && (
          <Modal open onClose={() => setShowConfirmCancel(false)} size="520px" title="Cancel Rollout?">
            <p className="text-sm text-ink-secondary mb-6">
              This will stop the rollout immediately. Sensors that have already been updated will
              remain on the new version. This action cannot be undone.
            </p>
            <div className="flex justify-end gap-3">
              <button
                onClick={() => setShowConfirmCancel(false)}
                className="px-4 py-2 text-sm font-medium text-ink-secondary hover:text-ink-primary hover:bg-surface-subtle transition-colors"
              >
                Keep Running
              </button>
              <button
                onClick={handleCancelRollout}
                disabled={isCancellingRollout}
                className="px-4 py-2 text-sm font-medium text-white bg-status-error hover:bg-status-error/90 transition-colors disabled:opacity-50"
              >
                <Stack as="span" direction="row" inline align="center" gap="sm">
                  {isCancellingRollout && <Spinner size={16} color={colors.white} />}
                  Cancel Rollout
                </Stack>
              </button>
            </div>
          </Modal>
        )}
      </div>
    );
  }

  // Render wizard
  return (
    <div className={clsx('bg-surface-card border border-border-subtle overflow-hidden', className)}>
      {/* Step indicator */}
      <StepIndicator steps={WIZARD_STEPS} currentStep={currentStep} onStepClick={handleStepClick} />

      {/* Step content */}
      <div className="p-6">
        {/* Step 1: Select Release */}
        {currentStep === 'release' && (
          <div className="space-y-4">
            <div>
              <h3 className="text-lg font-semibold text-ink-primary">Select Release</h3>
              <p className="mt-1 text-sm text-ink-secondary">
                Choose which version to deploy to your fleet sensors.
              </p>
            </div>

            {releases.length === 0 ? (
              <div className="py-12 text-center">
                <Package className="w-12 h-12 mx-auto text-ink-muted" />
                <p className="mt-4 text-sm text-ink-muted">No releases available. Upload a release first.</p>
              </div>
            ) : (
              <div className="space-y-3 max-h-80 overflow-y-auto">
                {releases.map((release, index) => (
                  <ReleaseCard
                    key={release.id}
                    release={release}
                    isSelected={release.id === selectedReleaseId}
                    isLatest={index === 0}
                    onClick={() => setSelectedReleaseId(release.id)}
                  />
                ))}
              </div>
            )}
          </div>
        )}

        {/* Step 2: Configure Strategy */}
        {currentStep === 'strategy' && (
          <div className="space-y-6">
            <div>
              <h3 className="text-lg font-semibold text-ink-primary">Configure Strategy</h3>
              <p className="mt-1 text-sm text-ink-secondary">
                Choose how to deploy the release across your fleet.
              </p>
            </div>

            <div className="space-y-3">
              {STRATEGY_OPTIONS.map((option) => (
                <StrategyCard
                  key={option.value}
                  option={option}
                  isSelected={strategy === option.value}
                  onClick={() => setStrategy(option.value)}
                />
              ))}
            </div>

            {/* Rolling strategy options */}
            {strategy === 'rolling' && (
              <div className="p-4 bg-surface-subtle space-y-4">
                <Stack direction="row" align="center" gap="sm">
                  <Info className="w-4 h-4 text-ink-muted" />
                  <span className="text-sm font-medium text-ink-primary">Rolling Options</span>
                </Stack>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-ink-secondary mb-1">Batch Size</label>
                    <Stack direction="row" align="center" gap="sm">
                      <input
                        type="range"
                        min="1"
                        max="50"
                        value={batchSize}
                        onChange={(e) => setBatchSize(parseInt(e.target.value))}
                        className="flex-1"
                      />
                      <span className="w-12 text-right text-sm font-mono text-ink-primary">{batchSize}</span>
                    </Stack>
                    <p className="mt-1 text-xs text-ink-muted">Sensors per batch</p>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-ink-secondary mb-1">Batch Delay</label>
                    <Stack direction="row" align="center" gap="sm">
                      <input
                        type="number"
                        min="0"
                        max="600"
                        value={batchDelay}
                        onChange={(e) => setBatchDelay(parseIntSafe(e.target.value, batchDelay))}
                        className="w-20 px-2 py-1 text-sm bg-surface-inset border border-border-subtle text-ink-primary"
                      />
                      <span className="text-sm text-ink-muted">seconds</span>
                    </Stack>
                    <p className="mt-1 text-xs text-ink-muted">Wait between batches</p>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Step 3: Select Targets */}
        {currentStep === 'targets' && (
          <div className="space-y-4">
            <div>
              <h3 className="text-lg font-semibold text-ink-primary">Select Targets</h3>
              <p className="mt-1 text-sm text-ink-secondary">
                Choose which sensors to include in this rollout.
              </p>
            </div>

            {/* Tag filter */}
            <div className="flex flex-wrap gap-2">
              {availableTags.map((tag) => (
                <button
                  key={tag}
                  onClick={() => handleTagToggle(tag)}
                  className={clsx(
                    'px-3 py-1.5 text-xs font-medium border transition-colors',
                    selectedTags.includes(tag)
                      ? 'bg-ac-blue text-white border-ac-blue'
                      : 'bg-surface-subtle text-ink-secondary border-border-subtle hover:border-ink-muted'
                  )}
                >
                  {tag}
                </button>
              ))}
            </div>

            {/* Search */}
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-ink-muted" />
              <input
                type="text"
                value={sensorSearch}
                onChange={(e) => setSensorSearch(e.target.value)}
                placeholder="Search sensors..."
                aria-label="Search sensors for rollout"
                className="w-full pl-9 pr-4 py-2 text-sm bg-surface-inset border border-border-subtle text-ink-primary placeholder:text-ink-muted focus:outline-none focus:border-ac-blue"
              />
            </div>

            {/* Selected count */}
            <div className="flex items-center justify-between px-3 py-2 bg-surface-subtle">
              <span className="text-sm text-ink-secondary">
                {filteredSensors.length} sensor{filteredSensors.length !== 1 ? 's' : ''} selected
              </span>
              {selectedTags.includes('all') && (
                <span className="text-xs text-ink-muted">All sensors in fleet</span>
              )}
            </div>

            {/* Sensor list preview */}
            <div className="max-h-48 overflow-y-auto border border-border-subtle divide-y divide-border-subtle">
              {filteredSensors.slice(0, 10).map((sensor) => (
                <div key={sensor.id} className="px-3 py-2 flex items-center justify-between">
                  <span className="text-sm text-ink-primary">{sensor.name}</span>
                  <span className="text-xs text-ink-muted">{sensor.region}</span>
                </div>
              ))}
              {filteredSensors.length > 10 && (
                <div className="px-3 py-2 text-center text-xs text-ink-muted">
                  +{filteredSensors.length - 10} more sensors
                </div>
              )}
            </div>
          </div>
        )}

        {/* Step 4: Review */}
        {currentStep === 'review' && selectedRelease && (
          <div className="space-y-6">
            <div>
              <h3 className="text-lg font-semibold text-ink-primary">Review & Deploy</h3>
              <p className="mt-1 text-sm text-ink-secondary">
                Confirm the rollout configuration before proceeding.
              </p>
            </div>

            {/* Summary cards */}
            <div className="grid grid-cols-2 gap-4">
              <div className="p-4 bg-surface-subtle">
                <div className="text-xs text-ink-muted uppercase tracking-wide mb-1">Release</div>
                <div className="text-lg font-semibold text-ink-primary">v{selectedRelease.version}</div>
                <div className="text-xs text-ink-muted mt-1">{formatDate(selectedRelease.createdAt)}</div>
              </div>

              <div className="p-4 bg-surface-subtle">
                <div className="text-xs text-ink-muted uppercase tracking-wide mb-1">Strategy</div>
                <div className="text-lg font-semibold text-ink-primary capitalize">{strategy}</div>
                {strategy === 'rolling' && (
                  <div className="text-xs text-ink-muted mt-1">
                    Batch: {batchSize}, Delay: {batchDelay}s
                  </div>
                )}
              </div>

              <div className="p-4 bg-surface-subtle">
                <div className="text-xs text-ink-muted uppercase tracking-wide mb-1">Target Tags</div>
                <div className="flex flex-wrap gap-1 mt-1">
                  {selectedTags.map((tag) => (
                    <span
                      key={tag}
                      className="px-2 py-0.5 text-xs font-medium bg-ac-blue/10 text-ac-blue"
                    >
                      {tag}
                    </span>
                  ))}
                </div>
              </div>

              <div className="p-4 bg-surface-subtle">
                <div className="text-xs text-ink-muted uppercase tracking-wide mb-1">Sensors</div>
                <div className="text-lg font-semibold text-ink-primary">{filteredSensors.length}</div>
                <div className="text-xs text-ink-muted mt-1">sensors will be updated</div>
              </div>
            </div>

            {/* Warning */}
            <div className="flex items-start gap-3 p-4 bg-status-warning/10 border border-status-warning/20">
              <AlertTriangle className="w-5 h-5 text-status-warning shrink-0 mt-0.5" />
              <div>
                <div className="text-sm font-medium text-status-warning">Impact Warning</div>
                <p className="text-sm text-ink-secondary mt-1">
                  This rollout will update {filteredSensors.length} sensor{filteredSensors.length !== 1 ? 's' : ''} to v
                  {selectedRelease.version}. Ensure you have tested this version before deploying to production.
                </p>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Navigation footer */}
      <div className="flex items-center justify-between px-6 py-4 bg-surface-raised border-t border-border-subtle">
        <button
          onClick={handleBack}
          disabled={currentStep === 'release'}
          className={clsx(
            'px-4 py-2 text-sm font-medium transition-colors',
            currentStep === 'release'
              ? 'text-ink-muted cursor-not-allowed'
              : 'text-ink-secondary hover:text-ink-primary hover:bg-surface-subtle'
          )}
        >
          <Stack as="span" direction="row" inline align="center" gap="sm">
            <ChevronLeft className="w-4 h-4" />
            Back
          </Stack>
        </button>

        {currentStep === 'review' ? (
          <button
            onClick={handleStartRollout}
            disabled={!canProceed || isStartingRollout}
            className="px-6 py-2 text-sm font-medium text-white bg-ac-blue hover:bg-ac-blue-dark transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isStartingRollout ? (
              <Stack as="span" direction="row" inline align="center" gap="sm">
                <Spinner size={16} color={colors.white} />
                Starting...
              </Stack>
            ) : (
              <Stack as="span" direction="row" inline align="center" gap="sm">
                <Play className="w-4 h-4" />
                Start Rollout
              </Stack>
            )}
          </button>
        ) : (
          <button
            onClick={handleNext}
            disabled={!canProceed}
            className={clsx(
              'px-4 py-2 text-sm font-medium transition-colors',
              canProceed
                ? 'text-white bg-ac-blue hover:bg-ac-blue-dark'
                : 'text-ink-muted bg-surface-subtle cursor-not-allowed'
            )}
          >
            <Stack as="span" direction="row" inline align="center" gap="sm">
              Next
              <ChevronRight className="w-4 h-4" />
            </Stack>
          </button>
        )}
      </div>
    </div>
  );
});

export default RolloutManager;
