/**
 * ReleasesPage
 * Main page for release management including upload, listing, and rollout control
 */

import { useState, useCallback, useMemo, useRef } from 'react';
import {
  Package,
  Upload,
  Trash2,
  Rocket,
  Download,
  Hash,
  AlertTriangle,
  X,
  Loader2,
  Check,
  RefreshCw,
  ChevronDown,
  ChevronRight,
  MoreVertical,
  History,
  Shield,
} from 'lucide-react';
import { clsx } from 'clsx';
import { useReleases, type Release } from '../../hooks/fleet/useReleases';
import { RolloutManager } from '../../components/fleet/RolloutManager';
import { MetricCard } from '../../components/fleet';

// ============================================================================
// Types
// ============================================================================

interface UploadReleaseModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (data: {
    version: string;
    changelog: string;
    binaryUrl?: string;
    binaryFile?: File;
    sha256?: string;
  }) => Promise<void>;
  isSubmitting: boolean;
}

interface ConfirmDeleteModalProps {
  isOpen: boolean;
  release: Release | null;
  onClose: () => void;
  onConfirm: () => Promise<void>;
  isDeleting: boolean;
}

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

function formatDateTime(dateString: string): string {
  return new Date(dateString).toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function validateSemver(version: string): boolean {
  const semverRegex =
    /^\d+\.\d+\.\d+(-[a-zA-Z0-9]+(\.[a-zA-Z0-9]+)*)?(\+[a-zA-Z0-9]+(\.[a-zA-Z0-9]+)*)?$/;
  return semverRegex.test(version);
}

async function calculateSha256(file: File): Promise<string> {
  const arrayBuffer = await file.arrayBuffer();
  const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

// ============================================================================
// Sub-Components
// ============================================================================

/** Upload Release Modal */
function UploadReleaseModal({ isOpen, onClose, onSubmit, isSubmitting }: UploadReleaseModalProps) {
  const [version, setVersion] = useState('');
  const [changelog, setChangelog] = useState('');
  const [uploadMode, setUploadMode] = useState<'file' | 'url'>('url');
  const [binaryUrl, setBinaryUrl] = useState('');
  const [binaryFile, setBinaryFile] = useState<File | null>(null);
  const [sha256, setSha256] = useState('');
  const [isCalculatingSha, setIsCalculatingSha] = useState(false);
  const [validationErrors, setValidationErrors] = useState<Record<string, string>>({});

  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileChange = useCallback(async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setBinaryFile(file);

    // Auto-calculate SHA-256
    setIsCalculatingSha(true);
    try {
      const hash = await calculateSha256(file);
      setSha256(hash);
    } catch (error) {
      console.error('Failed to calculate SHA-256:', error);
    } finally {
      setIsCalculatingSha(false);
    }
  }, []);

  const validate = useCallback(() => {
    const errors: Record<string, string> = {};

    if (!version.trim()) {
      errors.version = 'Version is required';
    } else if (!validateSemver(version.trim())) {
      errors.version = 'Invalid semantic version format (e.g., 2.4.1)';
    }

    if (!changelog.trim()) {
      errors.changelog = 'Changelog is required';
    }

    if (uploadMode === 'url') {
      if (!binaryUrl.trim()) {
        errors.binaryUrl = 'Binary URL is required';
      } else {
        try {
          new URL(binaryUrl);
        } catch {
          errors.binaryUrl = 'Invalid URL format';
        }
      }
    } else {
      if (!binaryFile) {
        errors.binaryFile = 'Binary file is required';
      }
    }

    setValidationErrors(errors);
    return Object.keys(errors).length === 0;
  }, [version, changelog, uploadMode, binaryUrl, binaryFile]);

  const handleSubmit = useCallback(async () => {
    if (!validate()) return;

    await onSubmit({
      version: version.trim(),
      changelog: changelog.trim(),
      binaryUrl: uploadMode === 'url' ? binaryUrl.trim() : undefined,
      binaryFile: uploadMode === 'file' ? binaryFile || undefined : undefined,
      sha256: sha256.trim() || undefined,
    });

    // Reset form
    setVersion('');
    setChangelog('');
    setBinaryUrl('');
    setBinaryFile(null);
    setSha256('');
    setValidationErrors({});
  }, [version, changelog, uploadMode, binaryUrl, binaryFile, sha256, validate, onSubmit]);

  const handleClose = useCallback(() => {
    setVersion('');
    setChangelog('');
    setBinaryUrl('');
    setBinaryFile(null);
    setSha256('');
    setValidationErrors({});
    onClose();
  }, [onClose]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={handleClose} />

      <div className="relative bg-surface-card border border-border-subtle shadow-xl max-w-lg w-full max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-border-subtle sticky top-0 bg-surface-card">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-ac-blue/10">
              <Upload className="w-5 h-5 text-ac-blue" />
            </div>
            <h2 className="text-lg font-semibold text-ink-primary">Upload Release</h2>
          </div>
          <button
            onClick={handleClose}
            className="p-2 text-ink-muted hover:text-ink-primary hover:bg-surface-subtle transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Form */}
        <div className="p-6 space-y-5">
          {/* Version */}
          <div>
            <label className="block text-sm font-medium text-ink-secondary mb-1.5">
              Version <span className="text-status-error">*</span>
            </label>
            <input
              type="text"
              value={version}
              onChange={(e) => setVersion(e.target.value)}
              placeholder="2.4.2"
              className={clsx(
                'w-full px-3 py-2 text-sm bg-surface-inset border text-ink-primary placeholder:text-ink-muted focus:outline-none focus:ring-2 focus:ring-ac-blue/50',
                validationErrors.version ? 'border-status-error' : 'border-border-subtle',
              )}
            />
            {validationErrors.version && (
              <p className="mt-1 text-xs text-status-error">{validationErrors.version}</p>
            )}
            <p className="mt-1 text-xs text-ink-muted">
              Semantic version (e.g., 2.4.2, 2.5.0-beta.1)
            </p>
          </div>

          {/* Changelog */}
          <div>
            <label className="block text-sm font-medium text-ink-secondary mb-1.5">
              Changelog <span className="text-status-error">*</span>
            </label>
            <textarea
              value={changelog}
              onChange={(e) => setChangelog(e.target.value)}
              placeholder="### Changes&#10;- Feature 1&#10;- Bug fix 2"
              rows={6}
              className={clsx(
                'w-full px-3 py-2 text-sm bg-surface-inset border text-ink-primary placeholder:text-ink-muted focus:outline-none focus:ring-2 focus:ring-ac-blue/50 font-mono',
                validationErrors.changelog ? 'border-status-error' : 'border-border-subtle',
              )}
            />
            {validationErrors.changelog && (
              <p className="mt-1 text-xs text-status-error">{validationErrors.changelog}</p>
            )}
            <p className="mt-1 text-xs text-ink-muted">Markdown supported</p>
          </div>

          {/* Upload mode toggle */}
          <div>
            <label className="block text-sm font-medium text-ink-secondary mb-1.5">
              Binary Source
            </label>
            <div className="flex gap-2">
              <button
                onClick={() => setUploadMode('url')}
                className={clsx(
                  'flex-1 px-4 py-2 text-sm font-medium border transition-colors',
                  uploadMode === 'url'
                    ? 'bg-ac-blue text-white border-ac-blue'
                    : 'bg-surface-subtle text-ink-secondary border-border-subtle hover:border-ink-muted',
                )}
              >
                URL
              </button>
              <button
                onClick={() => setUploadMode('file')}
                className={clsx(
                  'flex-1 px-4 py-2 text-sm font-medium border transition-colors',
                  uploadMode === 'file'
                    ? 'bg-ac-blue text-white border-ac-blue'
                    : 'bg-surface-subtle text-ink-secondary border-border-subtle hover:border-ink-muted',
                )}
              >
                Upload File
              </button>
            </div>
          </div>

          {/* URL input */}
          {uploadMode === 'url' && (
            <div>
              <label className="block text-sm font-medium text-ink-secondary mb-1.5">
                Binary URL <span className="text-status-error">*</span>
              </label>
              <input
                type="url"
                value={binaryUrl}
                onChange={(e) => setBinaryUrl(e.target.value)}
                placeholder="https://releases.example.com/sensor-2.4.2.tar.gz"
                className={clsx(
                  'w-full px-3 py-2 text-sm bg-surface-inset border text-ink-primary placeholder:text-ink-muted focus:outline-none focus:ring-2 focus:ring-ac-blue/50',
                  validationErrors.binaryUrl ? 'border-status-error' : 'border-border-subtle',
                )}
              />
              {validationErrors.binaryUrl && (
                <p className="mt-1 text-xs text-status-error">{validationErrors.binaryUrl}</p>
              )}
            </div>
          )}

          {/* File upload */}
          {uploadMode === 'file' && (
            <div>
              <label className="block text-sm font-medium text-ink-secondary mb-1.5">
                Binary File <span className="text-status-error">*</span>
              </label>
              <input
                ref={fileInputRef}
                type="file"
                onChange={handleFileChange}
                accept=".tar.gz,.tgz,.zip,.deb,.rpm"
                className="hidden"
              />
              <button
                onClick={() => fileInputRef.current?.click()}
                className={clsx(
                  'w-full px-4 py-6 border-2 border-dashed text-center transition-colors',
                  binaryFile
                    ? 'border-status-success bg-status-success/5'
                    : validationErrors.binaryFile
                      ? 'border-status-error'
                      : 'border-border-subtle hover:border-ink-muted',
                )}
              >
                {binaryFile ? (
                  <div className="flex items-center justify-center gap-2">
                    <Check className="w-5 h-5 text-status-success" />
                    <span className="text-sm text-ink-primary">{binaryFile.name}</span>
                    <span className="text-xs text-ink-muted">({formatBytes(binaryFile.size)})</span>
                  </div>
                ) : (
                  <div>
                    <Upload className="w-8 h-8 mx-auto text-ink-muted" />
                    <p className="mt-2 text-sm text-ink-secondary">Click to select file</p>
                    <p className="text-xs text-ink-muted">.tar.gz, .tgz, .zip, .deb, .rpm</p>
                  </div>
                )}
              </button>
              {validationErrors.binaryFile && (
                <p className="mt-1 text-xs text-status-error">{validationErrors.binaryFile}</p>
              )}
            </div>
          )}

          {/* SHA-256 */}
          <div>
            <label className="block text-sm font-medium text-ink-secondary mb-1.5">
              SHA-256 Checksum
            </label>
            <div className="relative">
              <input
                type="text"
                value={sha256}
                onChange={(e) => setSha256(e.target.value)}
                placeholder="64-character hex string"
                disabled={isCalculatingSha}
                className="w-full px-3 py-2 text-sm bg-surface-inset border border-border-subtle text-ink-primary placeholder:text-ink-muted focus:outline-none focus:ring-2 focus:ring-ac-blue/50 font-mono disabled:opacity-50"
              />
              {isCalculatingSha && (
                <div className="absolute right-3 top-1/2 -translate-y-1/2">
                  <Loader2 className="w-4 h-4 animate-spin text-ink-muted" />
                </div>
              )}
            </div>
            <p className="mt-1 text-xs text-ink-muted">
              {uploadMode === 'file'
                ? 'Auto-calculated from uploaded file'
                : 'Optional verification checksum'}
            </p>
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-border-subtle bg-surface-raised sticky bottom-0">
          <button
            onClick={handleClose}
            className="px-4 py-2 text-sm font-medium text-ink-secondary hover:text-ink-primary hover:bg-surface-subtle transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={handleSubmit}
            disabled={isSubmitting}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-ac-blue hover:bg-ac-blue-dark transition-colors disabled:opacity-50"
          >
            {isSubmitting ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Uploading...
              </>
            ) : (
              <>
                <Upload className="w-4 h-4" />
                Upload Release
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
}

/** Confirm Delete Modal */
function ConfirmDeleteModal({
  isOpen,
  release,
  onClose,
  onConfirm,
  isDeleting,
}: ConfirmDeleteModalProps) {
  if (!isOpen || !release) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />

      <div className="relative bg-surface-card border border-border-subtle shadow-xl max-w-md w-full p-6">
        <div className="flex items-center gap-3 mb-4">
          <div className="p-2 bg-status-error/10">
            <AlertTriangle className="w-6 h-6 text-status-error" />
          </div>
          <h3 className="text-lg font-semibold text-ink-primary">Delete Release?</h3>
        </div>

        <p className="text-sm text-ink-secondary mb-2">
          Are you sure you want to delete release{' '}
          <span className="font-semibold">v{release.version}</span>?
        </p>
        <p className="text-sm text-ink-muted mb-6">
          This action cannot be undone. Sensors currently using this version will not be affected.
        </p>

        <div className="flex justify-end gap-3">
          <button
            onClick={onClose}
            className="px-4 py-2 text-sm font-medium text-ink-secondary hover:text-ink-primary hover:bg-surface-subtle transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            disabled={isDeleting}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-status-error hover:bg-status-error/90 transition-colors disabled:opacity-50"
          >
            {isDeleting ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Deleting...
              </>
            ) : (
              <>
                <Trash2 className="w-4 h-4" />
                Delete Release
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
}

/** Release row in the table */
function ReleaseRow({
  release,
  isLatest,
  onDeploy,
  onDelete,
}: {
  release: Release;
  isLatest: boolean;
  onDeploy: (release: Release) => void;
  onDelete: (release: Release) => void;
}) {
  const [showChangelog, setShowChangelog] = useState(false);
  const [showMenu, setShowMenu] = useState(false);

  return (
    <>
      <tr className="border-b border-border-subtle hover:bg-surface-subtle">
        <td className="px-6 py-4">
          <div className="flex items-center gap-2">
            <button
              onClick={() => setShowChangelog(!showChangelog)}
              className="p-1 hover:bg-surface-subtle transition-colors"
            >
              {showChangelog ? (
                <ChevronDown className="w-4 h-4 text-ink-muted" />
              ) : (
                <ChevronRight className="w-4 h-4 text-ink-muted" />
              )}
            </button>
            <span className="font-semibold text-ink-primary">v{release.version}</span>
            {isLatest && (
              <span className="px-2 py-0.5 text-xs font-medium bg-status-success/10 text-status-success border border-status-success/30">
                Latest
              </span>
            )}
          </div>
        </td>
        <td className="px-6 py-4 text-sm text-ink-secondary">{formatDate(release.createdAt)}</td>
        <td className="px-6 py-4 text-sm text-ink-secondary">{formatBytes(release.size)}</td>
        <td className="px-6 py-4 text-sm text-ink-muted truncate max-w-[200px]">
          {release.createdBy}
        </td>
        <td className="px-6 py-4">
          <div className="flex items-center justify-end gap-2">
            <button
              onClick={() => onDeploy(release)}
              className="flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium text-ac-blue bg-ac-blue/10 border border-ac-blue/30 hover:bg-ac-blue/20 transition-colors"
            >
              <Rocket className="w-3.5 h-3.5" />
              Deploy
            </button>
            <div className="relative">
              <button
                onClick={() => setShowMenu(!showMenu)}
                className="p-1.5 text-ink-muted hover:text-ink-primary hover:bg-surface-subtle transition-colors"
              >
                <MoreVertical className="w-4 h-4" />
              </button>
              {showMenu && (
                <>
                  <div className="fixed inset-0 z-10" onClick={() => setShowMenu(false)} />
                  <div className="absolute right-0 top-full mt-1 z-20 bg-surface-card border border-border-subtle shadow-lg py-1 min-w-[140px]">
                    <button
                      onClick={() => {
                        window.open(release.binaryUrl, '_blank');
                        setShowMenu(false);
                      }}
                      className="w-full flex items-center gap-2 px-3 py-2 text-sm text-ink-secondary hover:bg-surface-subtle"
                    >
                      <Download className="w-4 h-4" />
                      Download
                    </button>
                    <button
                      onClick={() => {
                        navigator.clipboard.writeText(release.sha256);
                        setShowMenu(false);
                      }}
                      className="w-full flex items-center gap-2 px-3 py-2 text-sm text-ink-secondary hover:bg-surface-subtle"
                    >
                      <Hash className="w-4 h-4" />
                      Copy SHA-256
                    </button>
                    <hr className="my-1 border-border-subtle" />
                    <button
                      onClick={() => {
                        onDelete(release);
                        setShowMenu(false);
                      }}
                      className="w-full flex items-center gap-2 px-3 py-2 text-sm text-status-error hover:bg-status-error/10"
                    >
                      <Trash2 className="w-4 h-4" />
                      Delete
                    </button>
                  </div>
                </>
              )}
            </div>
          </div>
        </td>
      </tr>
      {showChangelog && (
        <tr className="bg-surface-subtle">
          <td colSpan={5} className="px-6 py-4">
            <div className="prose prose-sm max-w-none text-ink-secondary">
              <pre className="whitespace-pre-wrap text-xs font-mono bg-surface-inset p-4 border border-border-subtle">
                {release.changelog}
              </pre>
            </div>
            <div className="mt-3 flex items-center gap-4 text-xs text-ink-muted">
              <span className="flex items-center gap-1">
                <Hash className="w-3.5 h-3.5" />
                <span className="font-mono truncate max-w-[200px]">{release.sha256}</span>
              </span>
              <span className="flex items-center gap-1">
                <Shield className="w-3.5 h-3.5" />
                Verified
              </span>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

// ============================================================================
// Main Component
// ============================================================================

export function ReleasesPage() {
  // State
  const [showUploadModal, setShowUploadModal] = useState(false);
  const [releaseToDelete, setReleaseToDelete] = useState<Release | null>(null);
  const [showRolloutManager, setShowRolloutManager] = useState(false);
  const [deployingRelease, setDeployingRelease] = useState<Release | null>(null);

  // Hooks
  const {
    releases,
    isLoadingReleases,
    createRelease,
    deleteRelease,
    isCreatingRelease,
    isDeletingRelease,
    rollouts,
    activeRollout,
    startRollout,
    cancelRollout,
    isStartingRollout,
    isCancellingRollout,
    refreshReleases,
    refreshRollouts,
  } = useReleases();

  // Defensive defaults: some error paths can yield partial/undefined data; UI should not crash.
  const safeReleases = Array.isArray(releases) ? releases : [];
  const safeRollouts = Array.isArray(rollouts) ? rollouts : [];

  // Stats
  const stats = useMemo(() => {
    const completedRollouts = safeRollouts.filter((r) => r.status === 'completed').length;
    const totalSensorsUpdated = safeRollouts
      .filter((r) => r.status === 'completed')
      .reduce((sum, r) => {
        const progress = Array.isArray(r.progress) ? r.progress : [];
        return sum + progress.filter((p) => p.status === 'activated').length;
      }, 0);

    return {
      totalReleases: safeReleases.length,
      latestVersion: safeReleases[0]?.version || 'N/A',
      completedRollouts,
      totalSensorsUpdated,
    };
  }, [safeReleases, safeRollouts]);

  // Recent rollouts (completed)
  const recentRollouts = useMemo(() => {
    return safeRollouts.filter((r) => r.status === 'completed').slice(0, 5);
  }, [safeRollouts]);

  // Handlers
  const handleUploadRelease = useCallback(
    async (data: Parameters<typeof createRelease>[0]) => {
      await createRelease(data);
      setShowUploadModal(false);
    },
    [createRelease],
  );

  const handleDeleteRelease = useCallback(async () => {
    if (!releaseToDelete) return;
    await deleteRelease(releaseToDelete.id);
    setReleaseToDelete(null);
  }, [releaseToDelete, deleteRelease]);

  const handleDeployClick = useCallback((release: Release) => {
    setDeployingRelease(release);
    setShowRolloutManager(true);
  }, []);

  const handleRolloutStart = useCallback(
    async (releaseId: string, config: Parameters<typeof startRollout>[1]) => {
      const rollout = await startRollout(releaseId, config);
      setShowRolloutManager(false);
      setDeployingRelease(null);
      return rollout;
    },
    [startRollout],
  );

  const handleRolloutCancel = useCallback(
    async (rolloutId: string) => {
      await cancelRollout(rolloutId);
    },
    [cancelRollout],
  );

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-light text-ink-primary">Release Management</h1>
          <p className="mt-1 text-sm text-ink-secondary">
            Manage and deploy sensor releases across your fleet
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => {
              refreshReleases();
              refreshRollouts();
            }}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-ink-secondary border border-border-subtle hover:bg-surface-subtle transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
            Refresh
          </button>
          <button
            onClick={() => setShowUploadModal(true)}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-ac-blue hover:bg-ac-blue-dark transition-colors"
          >
            <Upload className="w-4 h-4" />
            Upload Release
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 gap-6 md:grid-cols-4">
        <MetricCard label="Total Releases" value={stats.totalReleases} />
        <MetricCard label="Latest Version" value={stats.latestVersion} />
        <MetricCard label="Completed Rollouts" value={stats.completedRollouts} />
        <MetricCard label="Sensors Updated" value={stats.totalSensorsUpdated} />
      </div>

      {/* Active Rollout Panel */}
      {(activeRollout || showRolloutManager) && (
        <div className="card">
          <div className="px-6 py-4 border-b border-border-subtle flex items-center justify-between">
            <h2 className="text-lg font-medium text-ink-primary">
              {activeRollout ? 'Active Rollout' : 'New Rollout'}
            </h2>
            {!activeRollout && (
              <button
                onClick={() => {
                  setShowRolloutManager(false);
                  setDeployingRelease(null);
                }}
                className="p-1.5 text-ink-muted hover:text-ink-primary hover:bg-surface-subtle transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            )}
          </div>
          <div className="p-6">
            <RolloutManager
              releases={
                deployingRelease
                  ? [deployingRelease, ...safeReleases.filter((r) => r.id !== deployingRelease.id)]
                  : safeReleases
              }
              activeRollout={activeRollout}
              isStartingRollout={isStartingRollout}
              isCancellingRollout={isCancellingRollout}
              onRolloutStart={handleRolloutStart}
              onRolloutCancel={handleRolloutCancel}
            />
          </div>
        </div>
      )}

      {/* Releases Table */}
      <div className="card">
        <div className="px-6 py-4 border-b border-border-subtle flex items-center justify-between">
          <h2 className="text-lg font-medium text-ink-primary">Available Releases</h2>
          <span className="text-sm text-ink-muted">{safeReleases.length} releases</span>
        </div>

        {isLoadingReleases ? (
          <div className="p-12 text-center">
            <Loader2 className="w-8 h-8 mx-auto animate-spin text-ink-muted" />
            <p className="mt-4 text-sm text-ink-muted">Loading releases...</p>
          </div>
        ) : safeReleases.length === 0 ? (
          <div className="p-12 text-center">
            <Package className="w-12 h-12 mx-auto text-ink-muted" />
            <p className="mt-4 text-sm text-ink-muted">No releases found.</p>
            <p className="text-sm text-ink-muted">Upload your first release to get started.</p>
            <button
              onClick={() => setShowUploadModal(true)}
              className="mt-4 inline-flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-ac-blue hover:bg-ac-blue-dark transition-colors"
            >
              <Upload className="w-4 h-4" />
              Upload Release
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="bg-surface-raised text-left">
                  <th className="px-6 py-3 text-xs font-semibold text-ink-muted uppercase tracking-wide">
                    Version
                  </th>
                  <th className="px-6 py-3 text-xs font-semibold text-ink-muted uppercase tracking-wide">
                    Created
                  </th>
                  <th className="px-6 py-3 text-xs font-semibold text-ink-muted uppercase tracking-wide">
                    Size
                  </th>
                  <th className="px-6 py-3 text-xs font-semibold text-ink-muted uppercase tracking-wide">
                    Created By
                  </th>
                  <th className="px-6 py-3 text-xs font-semibold text-ink-muted uppercase tracking-wide text-right">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody>
                {safeReleases.map((release, index) => (
                  <ReleaseRow
                    key={release.id}
                    release={release}
                    isLatest={index === 0}
                    onDeploy={handleDeployClick}
                    onDelete={setReleaseToDelete}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Recent Rollout History */}
      {recentRollouts.length > 0 && (
        <div className="card">
          <div className="px-6 py-4 border-b border-border-subtle flex items-center justify-between">
            <div className="flex items-center gap-2">
              <History className="w-5 h-5 text-ink-muted" />
              <h2 className="text-lg font-medium text-ink-primary">Recent Rollouts</h2>
            </div>
          </div>
          <div className="divide-y divide-border-subtle">
            {recentRollouts.map((rollout) => (
              <div key={rollout.id} className="px-6 py-4 flex items-center justify-between">
                <div className="flex items-center gap-4">
                  <div className="p-2 bg-status-success/10">
                    <Check className="w-4 h-4 text-status-success" />
                  </div>
                  <div>
                    <div className="font-medium text-ink-primary">v{rollout.release.version}</div>
                    <div className="text-sm text-ink-muted">
                      {
                        (Array.isArray(rollout.progress) ? rollout.progress : []).filter(
                          (p) => p.status === 'activated',
                        ).length
                      }{' '}
                      sensors updated
                    </div>
                  </div>
                </div>
                <div className="text-right">
                  <div className="text-sm text-ink-secondary capitalize">{rollout.strategy}</div>
                  <div className="text-xs text-ink-muted">
                    {rollout.completedAt ? formatDateTime(rollout.completedAt) : 'In progress'}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Modals */}
      <UploadReleaseModal
        isOpen={showUploadModal}
        onClose={() => setShowUploadModal(false)}
        onSubmit={handleUploadRelease}
        isSubmitting={isCreatingRelease}
      />

      <ConfirmDeleteModal
        isOpen={!!releaseToDelete}
        release={releaseToDelete}
        onClose={() => setReleaseToDelete(null)}
        onConfirm={handleDeleteRelease}
        isDeleting={isDeletingRelease}
      />
    </div>
  );
}

export default ReleasesPage;
