/**
 * FileBrowser Component
 *
 * File system browser for remote sensors with directory navigation,
 * file downloads with progress tracking, and file operations.
 */

import { memo, useState, useCallback, useRef, useEffect, type KeyboardEvent } from 'react';
import { clsx } from 'clsx';
import {
  Folder,
  File,
  FileText,
  FileCode,
  FileJson,
  FolderOpen,
  Download,
  RefreshCw,
  ChevronRight,
  Home,
  ArrowUp,
  Copy,
  Check,
  X,
  AlertCircle,
  Hash,
  ChevronDown,
  ChevronUp,
  Clock,
  HardDrive,
  Trash2,
} from 'lucide-react';
import {
  useFileTransfer,
  type FileInfo,
  type DownloadProgress,
} from '../../hooks/fleet/useFileTransfer';
import { Modal, Spinner, Stack } from '@/ui';

// =============================================================================
// Type Definitions
// =============================================================================

export interface FileBrowserProps {
  /** Target sensor ID */
  sensorId: string;
  /** Display name for the sensor */
  sensorName: string;
  /** Initial path to display */
  initialPath?: string;
  /** Additional CSS classes */
  className?: string;
  /** Height of the component (number in pixels or CSS string) */
  height?: number | string;
  /** Callback when download completes */
  onDownloadComplete?: (path: string, blob: Blob) => void;
  /** Callback when close button is clicked */
  onClose?: () => void;
}

type SortColumn = 'name' | 'size' | 'modified';
type SortDirection = 'asc' | 'desc';

// =============================================================================
// Helper Functions
// =============================================================================

/**
 * Format file size for display
 */
function formatSize(bytes: number): string {
  if (bytes === 0) return '-';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  const size = bytes / Math.pow(1024, i);
  return `${size.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

/**
 * Format speed for display
 */
function formatSpeed(bytesPerSec: number): string {
  if (bytesPerSec === 0) return '0 B/s';
  const units = ['B/s', 'KB/s', 'MB/s', 'GB/s'];
  const i = Math.floor(Math.log(bytesPerSec) / Math.log(1024));
  const speed = bytesPerSec / Math.pow(1024, i);
  return `${speed.toFixed(1)} ${units[i]}`;
}

/**
 * Format ETA for display
 */
function formatEta(seconds: number): string {
  if (seconds <= 0 || !isFinite(seconds)) return '--';
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) {
    const mins = Math.floor(seconds / 60);
    const secs = Math.round(seconds % 60);
    return `${mins}m ${secs}s`;
  }
  const hours = Math.floor(seconds / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  return `${hours}h ${mins}m`;
}

/**
 * Format date for display
 */
function formatDate(isoString: string): string {
  const date = new Date(isoString);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

  if (diffDays === 0) {
    return date.toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit',
    });
  } else if (diffDays === 1) {
    return 'Yesterday';
  } else if (diffDays < 7) {
    return `${diffDays} days ago`;
  } else {
    return date.toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: date.getFullYear() !== now.getFullYear() ? 'numeric' : undefined,
    });
  }
}

/**
 * Get file icon based on extension
 */
function getFileIcon(filename: string, isDir: boolean) {
  if (isDir) return Folder;

  const ext = filename.split('.').pop()?.toLowerCase() || '';

  // Log files
  if (ext === 'log' || filename.includes('log')) return FileText;

  // Code files
  if (['ts', 'tsx', 'js', 'jsx', 'py', 'rs', 'go', 'java', 'c', 'cpp', 'h'].includes(ext)) {
    return FileCode;
  }

  // JSON/Config files
  if (['json', 'yaml', 'yml', 'toml', 'xml', 'ini', 'conf', 'cfg'].includes(ext)) {
    return FileJson;
  }

  // Text files
  if (['txt', 'md', 'rst', 'csv'].includes(ext)) return FileText;

  return File;
}

/**
 * Trigger file download in browser
 */
function triggerBrowserDownload(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

// =============================================================================
// Sub-Components
// =============================================================================

/**
 * Breadcrumb navigation component
 */
interface BreadcrumbsProps {
  path: string;
  onNavigate: (path: string) => void;
}

const Breadcrumbs = memo(function Breadcrumbs({ path, onNavigate }: BreadcrumbsProps) {
  const parts = path.split('/').filter(Boolean);

  return (
    <nav className="flex items-center gap-1 text-sm overflow-x-auto">
      <button
        onClick={() => onNavigate('/')}
        className="flex items-center gap-1 px-2 py-1 hover:bg-surface-subtle text-ink-secondary hover:text-ink-primary transition-colors shrink-0"
        title="Go to root"
      >
        <Home className="w-4 h-4" />
      </button>

      {parts.map((part, index) => {
        const partPath = '/' + parts.slice(0, index + 1).join('/');
        const isLast = index === parts.length - 1;

        return (
          <div key={partPath} className="flex items-center gap-1 shrink-0">
            <ChevronRight className="w-4 h-4 text-ink-muted" />
            {isLast ? (
              <span className="px-2 py-1 font-medium text-ink-primary truncate max-w-[200px]">
                {part}
              </span>
            ) : (
              <button
                onClick={() => onNavigate(partPath)}
                className="px-2 py-1 hover:bg-surface-subtle text-ink-secondary hover:text-ink-primary transition-colors truncate max-w-[150px]"
              >
                {part}
              </button>
            )}
          </div>
        );
      })}
    </nav>
  );
});

/**
 * File row component
 */
interface FileRowProps {
  file: FileInfo;
  isSelected: boolean;
  onSelect: () => void;
  onOpen: () => void;
  onDownload: () => void;
  onCopyPath: () => void;
  onViewChecksum: () => void;
  isDownloading?: boolean;
}

const FileRow = memo(function FileRow({
  file,
  isSelected,
  onSelect,
  onOpen,
  onDownload,
  onCopyPath,
  onViewChecksum,
  isDownloading = false,
}: FileRowProps) {
  const IconComponent = getFileIcon(file.name, file.isDir);

  return (
    <tr
      className={clsx(
        'group cursor-pointer transition-colors',
        isSelected ? 'bg-accent-primary/10' : 'hover:bg-surface-subtle'
      )}
      onClick={onSelect}
      onDoubleClick={file.isDir ? onOpen : undefined}
      onKeyDown={(e: KeyboardEvent<HTMLTableRowElement>) => {
        if (e.key === 'Enter') {
          if (file.isDir) {
            onOpen();
          } else {
            onDownload();
          }
        }
      }}
      tabIndex={0}
      role="row"
      aria-selected={isSelected}
    >
      {/* Name */}
      <td className="px-4 py-2">
        <div className="flex items-center gap-2">
          {file.isDir ? (
            <FolderOpen className="w-4 h-4 text-yellow-500 shrink-0" />
          ) : (
            <IconComponent className="w-4 h-4 text-ink-muted shrink-0" />
          )}
          <span
            className={clsx(
              'truncate',
              file.isDir ? 'font-medium text-ink-primary' : 'text-ink-secondary'
            )}
            title={file.name}
          >
            {file.name}
          </span>
        </div>
      </td>

      {/* Size */}
      <td className="px-4 py-2 text-right text-sm text-ink-secondary tabular-nums">
        {formatSize(file.size)}
      </td>

      {/* Modified */}
      <td className="px-4 py-2 text-sm text-ink-muted" title={file.modified}>
        {formatDate(file.modified)}
      </td>

      {/* Actions */}
      <td className="px-4 py-2">
        <div className="flex items-center justify-end gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
          {file.isDir ? (
            <button
              onClick={(e) => {
                e.stopPropagation();
                onOpen();
              }}
              className="p-1.5 hover:bg-surface-card text-ink-muted hover:text-ink-primary transition-colors"
              title="Open folder"
            >
              <FolderOpen className="w-4 h-4" />
            </button>
          ) : (
            <button
              onClick={(e) => {
                e.stopPropagation();
                onDownload();
              }}
              disabled={isDownloading}
              className="p-1.5 hover:bg-surface-card text-ink-muted hover:text-accent-primary transition-colors disabled:opacity-50"
              title="Download file"
            >
              {isDownloading ? (
                <Spinner size={16} color="#0057B7" />
              ) : (
                <Download className="w-4 h-4" />
              )}
            </button>
          )}

          <button
            onClick={(e) => {
              e.stopPropagation();
              onCopyPath();
            }}
            className="p-1.5 hover:bg-surface-card text-ink-muted hover:text-ink-primary transition-colors"
            title="Copy path"
          >
            <Copy className="w-4 h-4" />
          </button>

          {!file.isDir && (
            <button
              onClick={(e) => {
                e.stopPropagation();
                onViewChecksum();
              }}
              className="p-1.5 hover:bg-surface-card text-ink-muted hover:text-ink-primary transition-colors"
              title="View checksum"
            >
              <Hash className="w-4 h-4" />
            </button>
          )}
        </div>
      </td>
    </tr>
  );
});

/**
 * Download progress item component
 */
interface DownloadItemProps {
  download: DownloadProgress;
  onCancel: () => void;
  onSave: () => void;
}

const DownloadItem = memo(function DownloadItem({ download, onCancel, onSave }: DownloadItemProps) {
  const filename = download.path.split('/').pop() || 'file';

  return (
    <Stack direction="column" gap="xs" className="p-2 bg-surface-subtle">
      <div className="flex items-center justify-between gap-2">
        <span className="text-xs font-medium text-ink-primary truncate" title={download.path}>
          {filename}
        </span>

        <div className="flex items-center gap-1 shrink-0">
          {download.status === 'complete' && (
            <button
              onClick={onSave}
              className="p-1 hover:bg-surface-card text-status-success"
              title="Save file"
            >
              <Download className="w-3.5 h-3.5" />
            </button>
          )}

          {['pending', 'downloading', 'verifying'].includes(download.status) && (
            <button
              onClick={onCancel}
              className="p-1 hover:bg-surface-card text-ink-muted hover:text-status-error"
              title="Cancel download"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>

      {/* Progress bar */}
      <div className="h-1.5 bg-surface-card overflow-hidden">
        <div
          className={clsx(
            'h-full transition-all duration-300',
            download.status === 'error' || download.status === 'cancelled'
              ? 'bg-status-error'
              : download.status === 'complete'
              ? 'bg-status-success'
              : 'bg-accent-primary'
          )}
          style={{ width: `${download.progress}%` }}
        />
      </div>

      {/* Status line */}
      <div className="flex items-center justify-between text-[10px] text-ink-muted">
        <span>
          {download.status === 'pending' && 'Starting...'}
          {download.status === 'downloading' && (
            <>
              {formatSize(download.downloadedSize)} / {formatSize(download.totalSize)}
              {download.speed > 0 && <span className="ml-2">{formatSpeed(download.speed)}</span>}
            </>
          )}
          {download.status === 'verifying' && 'Verifying checksum...'}
          {download.status === 'complete' && (
            <span className="text-status-success flex items-center gap-1">
              <Check className="w-3 h-3" /> Complete
            </span>
          )}
          {download.status === 'error' && (
            <span className="text-status-error">{download.error || 'Download failed'}</span>
          )}
          {download.status === 'cancelled' && <span className="text-status-warning">Cancelled</span>}
        </span>

        {download.status === 'downloading' && download.eta > 0 && (
          <span>{formatEta(download.eta)} remaining</span>
        )}
      </div>
    </Stack>
  );
});

/**
 * Checksum modal component
 */
interface ChecksumModalProps {
  file: FileInfo | null;
  checksum: string | null;
  isLoading: boolean;
  error: string | null;
  onClose: () => void;
}

const ChecksumModal = memo(function ChecksumModal({
  file,
  checksum,
  isLoading,
  error,
  onClose,
}: ChecksumModalProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = useCallback(() => {
    if (checksum) {
      navigator.clipboard.writeText(checksum);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  }, [checksum]);

  if (!file) return null;

  return (
    <Modal open onClose={onClose} size="520px" title="File Checksum">
      <div className="space-y-4">
        <div>
          <div className="text-xs text-ink-muted mb-1">File</div>
          <div className="text-sm text-ink-primary font-mono truncate" title={file.path}>
            {file.name}
          </div>
        </div>

        {isLoading && (
          <div className="flex items-center justify-center py-4">
            <Spinner size={24} color="#7F7F7F" />
          </div>
        )}

        {error && (
          <div className="flex items-start gap-2 p-3 bg-status-error/10 border border-status-error/20">
            <AlertCircle className="w-4 h-4 text-status-error shrink-0 mt-0.5" />
            <p className="text-xs text-status-error">{error}</p>
          </div>
        )}

        {checksum && !isLoading && (
          <div>
            <div className="text-xs text-ink-muted mb-1">SHA-256</div>
            <div className="flex items-center gap-2">
              <code className="flex-1 p-2 text-xs bg-surface-inset font-mono text-ink-secondary break-all">
                {checksum}
              </code>
              <button
                onClick={handleCopy}
                className="p-2 hover:bg-surface-subtle text-ink-muted hover:text-ink-primary transition-colors shrink-0"
                title="Copy checksum"
              >
                {copied ? <Check className="w-4 h-4 text-status-success" /> : <Copy className="w-4 h-4" />}
              </button>
            </div>
          </div>
        )}
      </div>
    </Modal>
  );
});

// =============================================================================
// Main Component
// =============================================================================

export const FileBrowser = memo(function FileBrowser({
  sensorId,
  sensorName,
  initialPath = '/',
  className = '',
  height = 600,
  onDownloadComplete,
  onClose,
}: FileBrowserProps) {
  // File transfer hook
  const {
    currentPath,
    files,
    isLoadingFiles,
    filesError,
    navigateTo,
    navigateUp,
    refresh,
    downloads,
    downloadFile,
    cancelDownload,
    clearCompletedDownloads,
    getFileInfo,
  } = useFileTransfer({
    sensorId,
    initialPath,
    onDownloadComplete: (path, blob) => {
      onDownloadComplete?.(path, blob);
    },
  });

  // State
  const [selectedFile, setSelectedFile] = useState<FileInfo | null>(null);
  const [sortColumn, setSortColumn] = useState<SortColumn>('name');
  const [sortDirection, setSortDirection] = useState<SortDirection>('asc');
  const [pathInput, setPathInput] = useState(currentPath);
  const [isEditingPath, setIsEditingPath] = useState(false);
  const [showDownloads, setShowDownloads] = useState(true);
  const [copiedPath, setCopiedPath] = useState<string | null>(null);

  // Checksum modal state
  const [checksumFile, setChecksumFile] = useState<FileInfo | null>(null);
  const [checksumValue, setChecksumValue] = useState<string | null>(null);
  const [checksumLoading, setChecksumLoading] = useState(false);
  const [checksumError, setChecksumError] = useState<string | null>(null);

  const pathInputRef = useRef<HTMLInputElement>(null);
  const tableRef = useRef<HTMLTableSectionElement>(null);

  // Sync path input with current path
  useEffect(() => {
    if (!isEditingPath) {
      setPathInput(currentPath);
    }
  }, [currentPath, isEditingPath]);

  // Sort files
  const sortedFiles = [...files].sort((a, b) => {
    // Directories always come first
    if (a.isDir && !b.isDir) return -1;
    if (!a.isDir && b.isDir) return 1;

    let comparison = 0;
    switch (sortColumn) {
      case 'name':
        comparison = a.name.localeCompare(b.name);
        break;
      case 'size':
        comparison = a.size - b.size;
        break;
      case 'modified':
        comparison = new Date(a.modified).getTime() - new Date(b.modified).getTime();
        break;
    }

    return sortDirection === 'asc' ? comparison : -comparison;
  });

  // Active downloads
  const activeDownloads = Array.from(downloads.entries()).filter(([, d]) =>
    ['pending', 'downloading', 'verifying'].includes(d.status)
  );

  const completedDownloads = Array.from(downloads.entries()).filter(([, d]) =>
    ['complete', 'error', 'cancelled'].includes(d.status)
  );

  // Handlers
  const handleSort = useCallback((column: SortColumn) => {
    setSortColumn((prev) => {
      if (prev === column) {
        setSortDirection((dir) => (dir === 'asc' ? 'desc' : 'asc'));
      } else {
        setSortDirection('asc');
      }
      return column;
    });
  }, []);

  const handlePathSubmit = useCallback(() => {
    navigateTo(pathInput);
    setIsEditingPath(false);
  }, [pathInput, navigateTo]);

  const handlePathKeyDown = useCallback(
    (e: KeyboardEvent<HTMLInputElement>) => {
      if (e.key === 'Enter') {
        handlePathSubmit();
      } else if (e.key === 'Escape') {
        setPathInput(currentPath);
        setIsEditingPath(false);
      }
    },
    [handlePathSubmit, currentPath]
  );

  const handleCopyPath = useCallback((path: string) => {
    navigator.clipboard.writeText(path);
    setCopiedPath(path);
    setTimeout(() => setCopiedPath(null), 2000);
  }, []);

  const handleViewChecksum = useCallback(
    async (file: FileInfo) => {
      setChecksumFile(file);
      setChecksumValue(null);
      setChecksumError(null);
      setChecksumLoading(true);

      try {
        const info = await getFileInfo(file.path);
        setChecksumValue(info.checksum || null);
        if (!info.checksum) {
          setChecksumError('Checksum not available for this file');
        }
      } catch (err) {
        setChecksumError(err instanceof Error ? err.message : 'Failed to get checksum');
      } finally {
        setChecksumLoading(false);
      }
    },
    [getFileInfo]
  );

  const handleSaveDownload = useCallback((download: DownloadProgress) => {
    if (download.blob) {
      const filename = download.path.split('/').pop() || 'file';
      triggerBrowserDownload(download.blob, filename);
    }
  }, []);

  // Keyboard navigation
  useEffect(() => {
    const handleKeyDown = (e: globalThis.KeyboardEvent) => {
      // Don't handle if in input
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) {
        return;
      }

      switch (e.key) {
        case 'Backspace':
          navigateUp();
          break;
        case 'F5':
        case 'r':
          if (e.ctrlKey || e.metaKey) {
            e.preventDefault();
            refresh();
          }
          break;
        case 'ArrowUp':
        case 'ArrowDown': {
          e.preventDefault();
          const currentIndex = selectedFile ? sortedFiles.findIndex((f) => f.path === selectedFile.path) : -1;
          let newIndex: number;

          if (e.key === 'ArrowUp') {
            newIndex = currentIndex <= 0 ? sortedFiles.length - 1 : currentIndex - 1;
          } else {
            newIndex = currentIndex >= sortedFiles.length - 1 ? 0 : currentIndex + 1;
          }

          if (sortedFiles[newIndex]) {
            setSelectedFile(sortedFiles[newIndex]);
          }
          break;
        }
        case 'Enter':
          if (selectedFile) {
            if (selectedFile.isDir) {
              navigateTo(selectedFile.path);
            } else {
              downloadFile(selectedFile.path);
            }
          }
          break;
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [selectedFile, sortedFiles, navigateUp, refresh, navigateTo, downloadFile]);

  // Render sort indicator
  const SortIndicator = useCallback(
    ({ column }: { column: SortColumn }) => {
      if (sortColumn !== column) return null;
      return sortDirection === 'asc' ? (
        <ChevronUp className="w-3.5 h-3.5" />
      ) : (
        <ChevronDown className="w-3.5 h-3.5" />
      );
    },
    [sortColumn, sortDirection]
  );

  return (
    <>
      <div
        className={clsx(
          'flex flex-col bg-surface-base border border-border-subtle overflow-hidden',
          className
        )}
        style={{ height: typeof height === 'string' ? height : `${height}px` }}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-2 border-b border-border-subtle bg-surface-raised">
          <div className="flex items-center gap-3">
            <HardDrive className="w-4 h-4 text-ink-muted" />
            <h3 className="text-sm font-semibold text-ink-primary">{sensorName}</h3>
            <span className="text-xs text-ink-secondary">File Browser</span>
          </div>

          <div className="flex items-center gap-2">
            {/* Refresh */}
            <button
              onClick={refresh}
              disabled={isLoadingFiles}
              className="p-1.5 hover:bg-surface-subtle text-ink-muted hover:text-ink-primary transition-colors disabled:opacity-50"
              title="Refresh (Ctrl+R)"
            >
              {isLoadingFiles ? <Spinner size={16} color="#7F7F7F" /> : <RefreshCw className="w-4 h-4" />}
            </button>

            {/* Close */}
            {onClose && (
              <button
                onClick={onClose}
                className="p-1.5 hover:bg-surface-subtle text-ink-muted hover:text-ink-primary transition-colors"
                title="Close"
              >
                <X className="w-4 h-4" />
              </button>
            )}
          </div>
        </div>

        {/* Navigation bar */}
        <div className="flex items-center gap-2 px-4 py-2 border-b border-border-subtle bg-surface-subtle">
          {/* Up button */}
          <button
            onClick={navigateUp}
            disabled={currentPath === '/'}
            className="p-1.5 hover:bg-surface-card text-ink-muted hover:text-ink-primary transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            title="Go up (Backspace)"
          >
            <ArrowUp className="w-4 h-4" />
          </button>

          {/* Breadcrumbs or path input */}
          {isEditingPath ? (
            <input
              ref={pathInputRef}
              type="text"
              value={pathInput}
              onChange={(e) => setPathInput(e.target.value)}
              onKeyDown={handlePathKeyDown}
              onBlur={() => {
                setPathInput(currentPath);
                setIsEditingPath(false);
              }}
              className="flex-1 px-3 py-1 text-sm bg-surface-base border border-border-subtle font-mono focus:outline-none focus:ring-2 focus:ring-accent-primary/20 focus:border-accent-primary"
              autoFocus
            />
          ) : (
            <div
              className="flex-1 cursor-text"
              onClick={() => {
                setIsEditingPath(true);
                setTimeout(() => pathInputRef.current?.select(), 0);
              }}
            >
              <Breadcrumbs path={currentPath} onNavigate={navigateTo} />
            </div>
          )}
        </div>

        {/* File table */}
        <div className="flex-1 overflow-auto">
          {isLoadingFiles ? (
            <div className="flex flex-col items-center justify-center h-full text-ink-muted">
              <Spinner size={32} color="#7F7F7F" style={{ marginBottom: '12px' }} />
              <p className="text-sm">Loading directory...</p>
            </div>
          ) : filesError ? (
            <div className="flex flex-col items-center justify-center h-full text-ink-muted p-4">
              <AlertCircle className="w-10 h-10 text-status-error mb-3" />
              <p className="text-sm text-status-error font-medium mb-2">Failed to load directory</p>
              <p className="text-xs text-ink-muted text-center mb-4">{filesError.message}</p>
              <button
                onClick={refresh}
                className="px-4 py-2 text-sm font-medium text-ink-primary bg-surface-subtle hover:bg-surface-card transition-colors"
              >
                Retry
              </button>
            </div>
          ) : sortedFiles.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full text-ink-muted">
              <Folder className="w-10 h-10 mb-3 opacity-50" />
              <p className="text-sm font-medium">Directory is empty</p>
            </div>
          ) : (
            <table className="w-full text-sm">
              <thead className="sticky top-0 bg-surface-raised border-b border-border-subtle">
                <tr>
                  <th
                    className="px-4 py-2 text-left font-medium text-ink-secondary cursor-pointer select-none hover:text-ink-primary"
                    onClick={() => handleSort('name')}
                  >
                    <div className="flex items-center gap-1">
                      Name
                      <SortIndicator column="name" />
                    </div>
                  </th>
                  <th
                    className="px-4 py-2 text-right font-medium text-ink-secondary cursor-pointer select-none hover:text-ink-primary w-24"
                    onClick={() => handleSort('size')}
                  >
                    <div className="flex items-center justify-end gap-1">
                      Size
                      <SortIndicator column="size" />
                    </div>
                  </th>
                  <th
                    className="px-4 py-2 text-left font-medium text-ink-secondary cursor-pointer select-none hover:text-ink-primary w-32"
                    onClick={() => handleSort('modified')}
                  >
                    <div className="flex items-center gap-1">
                      Modified
                      <SortIndicator column="modified" />
                    </div>
                  </th>
                  <th className="px-4 py-2 w-28" />
                </tr>
              </thead>
              <tbody ref={tableRef}>
                {sortedFiles.map((file) => {
                  const downloadProgress = downloads.get(file.path);
                  const isDownloading =
                    downloadProgress &&
                    ['pending', 'downloading', 'verifying'].includes(downloadProgress.status);

                  return (
                    <FileRow
                      key={file.path}
                      file={file}
                      isSelected={selectedFile?.path === file.path}
                      onSelect={() => setSelectedFile(file)}
                      onOpen={() => file.isDir && navigateTo(file.path)}
                      onDownload={() => downloadFile(file.path)}
                      onCopyPath={() => handleCopyPath(file.path)}
                      onViewChecksum={() => handleViewChecksum(file)}
                      isDownloading={isDownloading}
                    />
                  );
                })}
              </tbody>
            </table>
          )}
        </div>

        {/* Download manager section */}
        {downloads.size > 0 && (
          <div className="border-t border-border-subtle">
            {/* Header */}
            <button
              onClick={() => setShowDownloads(!showDownloads)}
              className="w-full flex items-center justify-between px-4 py-2 bg-surface-raised hover:bg-surface-subtle transition-colors"
            >
              <div className="flex items-center gap-2">
                <Download className="w-4 h-4 text-ink-muted" />
                <span className="text-xs font-medium text-ink-primary">
                  Downloads
                  {activeDownloads.length > 0 && (
                    <span className="ml-1 text-ink-muted">({activeDownloads.length} active)</span>
                  )}
                </span>
              </div>

              <div className="flex items-center gap-2">
                {completedDownloads.length > 0 && (
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      clearCompletedDownloads();
                    }}
                    className="p-1 hover:bg-surface-card text-ink-muted hover:text-ink-primary"
                    title="Clear completed"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                )}
                {showDownloads ? (
                  <ChevronDown className="w-4 h-4 text-ink-muted" />
                ) : (
                  <ChevronUp className="w-4 h-4 text-ink-muted" />
                )}
              </div>
            </button>

            {/* Download list */}
            {showDownloads && (
              <div className="px-4 py-2 space-y-2 max-h-40 overflow-y-auto bg-surface-base">
                {Array.from(downloads.entries()).map(([path, download]) => (
                  <DownloadItem
                    key={path}
                    download={download}
                    onCancel={() => cancelDownload(path)}
                    onSave={() => handleSaveDownload(download)}
                  />
                ))}
              </div>
            )}
          </div>
        )}

        {/* Status bar */}
        <div className="px-4 py-1.5 border-t border-border-subtle bg-surface-raised">
          <div className="flex items-center justify-between text-xs text-ink-muted">
            <span>
              {sortedFiles.length} item{sortedFiles.length !== 1 ? 's' : ''}
              {selectedFile && (
                <>
                  <span className="mx-2">|</span>
                  <span className="font-mono">{selectedFile.name}</span>
                  {!selectedFile.isDir && <span className="ml-2">{formatSize(selectedFile.size)}</span>}
                </>
              )}
            </span>

            <div className="flex items-center gap-2">
              <Clock className="w-3 h-3" />
              <span>Backspace: Up | Enter: Open/Download | Ctrl+R: Refresh</span>
            </div>
          </div>
        </div>

        {/* Copy feedback */}
        {copiedPath && (
          <div className="absolute bottom-16 right-4 flex items-center gap-2 px-3 py-2 bg-surface-card border border-border-subtle shadow-lg text-xs text-status-success">
            <Check className="w-3.5 h-3.5" />
            Path copied!
          </div>
        )}
      </div>

      {/* Checksum modal */}
      <ChecksumModal
        file={checksumFile}
        checksum={checksumValue}
        isLoading={checksumLoading}
        error={checksumError}
        onClose={() => setChecksumFile(null)}
      />
    </>
  );
});

export default FileBrowser;
