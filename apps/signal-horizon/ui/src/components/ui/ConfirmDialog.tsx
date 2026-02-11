import { AlertTriangle } from 'lucide-react';
import { Button, Modal } from '@/ui';

interface ConfirmDialogProps {
  open: boolean;
  title: string;
  description: string;
  confirmLabel?: string;
  cancelLabel?: string;
  variant?: 'danger' | 'warning';
  onConfirm: () => void;
  onCancel: () => void;
}

export function ConfirmDialog({
  open,
  title,
  description,
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  variant = 'danger',
  onConfirm,
  onCancel,
}: ConfirmDialogProps) {
  if (!open) return null;

  const confirmStyle =
    variant === 'danger'
      ? { background: '#EF3340', color: '#FFFFFF' }
      : { background: '#F59E0B', color: '#111827' };

  return (
    <Modal open={open} onClose={onCancel} size="480px">
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="confirm-dialog-title"
        aria-describedby="confirm-dialog-desc"
      >
        <div className="flex items-start gap-4 mb-6">
          <div className="flex-shrink-0 w-10 h-10 flex items-center justify-center bg-status-error/10 border border-status-error/20">
            <AlertTriangle className="w-5 h-5 text-status-error" />
          </div>
          <div className="flex-1 min-w-0">
            <h2
              id="confirm-dialog-title"
              className="text-lg font-semibold text-ink-primary"
            >
              {title}
            </h2>
            <p
              id="confirm-dialog-desc"
              className="mt-2 text-sm text-ink-secondary"
            >
              {description}
            </p>
          </div>
        </div>

        <div className="flex justify-end gap-3 pt-4 border-t border-border-subtle">
          <Button
            type="button"
            onClick={onCancel}
            variant="outlined"
            size="sm"
          >
            {cancelLabel}
          </Button>
          <Button
            type="button"
            onClick={onConfirm}
            autoFocus
            size="sm"
            style={confirmStyle}
          >
            {confirmLabel}
          </Button>
        </div>
      </div>
    </Modal>
  );
}
