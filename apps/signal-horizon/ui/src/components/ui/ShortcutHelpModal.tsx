import { AnimatePresence, motion } from 'framer-motion';
import { X, Keyboard } from 'lucide-react';
import { SectionHeader } from '@/ui';

interface ShortcutHelpModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export function ShortcutHelpModal({ isOpen, onClose }: ShortcutHelpModalProps) {
  const shortcuts = [
    { keys: ['Ctrl', 'K'], label: 'Open Command Palette' },
    { keys: ['Ctrl', 'B'], label: 'Toggle Sidebar' },
    { keys: ['/'], label: 'Focus Command Palette' },
    { keys: ['?'], label: 'Show this help modal' },
    { keys: ['ESC'], label: 'Close modals / palettes' },
  ];

  return (
    <AnimatePresence>
      {isOpen && (
        <div className="fixed inset-0 z-[110] flex items-center justify-center p-4">
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/60 backdrop-blur-sm"
            onClick={onClose}
          />
          <motion.div
            initial={{ opacity: 0, scale: 0.95, y: 20 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.95, y: 20 }}
            className="w-full max-w-md bg-surface-card border border-border-strong shadow-2xl relative z-10 overflow-hidden scanlines"
          >
            <div className="flex items-center justify-between p-4 border-b border-border-subtle bg-surface-subtle/50">
              <SectionHeader
                title="Keyboard Shortcuts"
                icon={<Keyboard className="w-5 h-5 text-ac-blue" />}
                size="h4"
                mb="xs"
                style={{ marginBottom: 0 }}
                titleStyle={{
                  fontSize: '18px',
                  lineHeight: '24px',
                  textTransform: 'uppercase',
                  letterSpacing: '0.02em',
                }}
              />
              <button
                onClick={onClose}
                className="p-1 text-ink-muted hover:text-ink-primary transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="p-4 space-y-4">
              {shortcuts.map((shortcut, i) => (
                <div key={i} className="flex items-center justify-between">
                  <span className="text-sm text-ink-secondary">{shortcut.label}</span>
                  <div className="flex items-center gap-1">
                    {shortcut.keys.map((key, j) => (
                      <kbd
                        key={j}
                        className="px-2 py-1 min-w-[24px] text-center text-[10px] font-bold text-ink-primary bg-surface-base border border-border-subtle shadow-sm uppercase"
                      >
                        {key === 'Ctrl' && (navigator.platform?.includes('Mac') ? '⌘' : 'Ctrl')}
                        {key !== 'Ctrl' && key}
                      </kbd>
                    ))}
                  </div>
                </div>
              ))}
            </div>
            <div className="p-4 bg-surface-subtle/30 text-[10px] text-center text-ink-muted uppercase tracking-[0.2em]">
              Tactical Keyboard Interface · v0.1
            </div>
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  );
}
