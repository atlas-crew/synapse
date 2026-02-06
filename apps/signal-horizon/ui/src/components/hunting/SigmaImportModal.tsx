import { useState, useRef, useCallback } from 'react';
import { X, ArrowRight, FileText } from 'lucide-react';
import { CodeEditor } from '../ctrlx/CodeEditor';
import { convertSigmaToSql } from '../../utils/sigmaToSql';
import { useFocusTrap } from '../../hooks/useFocusTrap';

interface SigmaImportModalProps {
  onImport: (sql: string) => void;
  onClose: () => void;
}

const EXAMPLE_RULE = `title: Suspicious cURL User Agent
description: Detects suspicious cURL user agents often used by bots
logsource:
  category: web_server
detection:
  selection:
    UserAgent|contains: 'curl/'
  condition: selection`;

export function SigmaImportModal({ onImport, onClose }: SigmaImportModalProps) {
  const [sigmaYaml, setSigmaYaml] = useState(EXAMPLE_RULE);
  const [previewSql, setPreviewSql] = useState(convertSigmaToSql(EXAMPLE_RULE));
  const modalRef = useRef<HTMLDivElement>(null);
  const stableOnClose = useCallback(() => onClose(), [onClose]);
  useFocusTrap(modalRef, true, stableOnClose);

  const handleYamlChange = (value: string) => {
    setSigmaYaml(value);
    setPreviewSql(convertSigmaToSql(value));
  };

  const handleImport = () => {
    onImport(previewSql);
    onClose();
  };

  return (
    <div className="fixed inset-0 bg-ac-black/50 flex items-center justify-center z-50">
      <div ref={modalRef} role="dialog" aria-modal="true" aria-labelledby="sigma-import-title" className="bg-surface-base border border-border-subtle w-full max-w-5xl h-[80vh] flex flex-col shadow-2xl">
        {/* Header */}
        <div className="px-6 py-4 border-b border-border-subtle flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-ac-blue/10 rounded-sm">
              <FileText className="w-5 h-5 text-ac-blue" />
            </div>
            <div>
              <h2 id="sigma-import-title" className="text-lg font-medium text-ink-primary">Import Sigma Rule</h2>
              <p className="text-xs text-ink-secondary">
                Convert standard Sigma threat detection rules to ClickHouse SQL
              </p>
            </div>
          </div>
          <button onClick={onClose} className="p-2 text-ink-muted hover:text-ink-primary">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 grid grid-cols-2 divide-x divide-border-subtle overflow-hidden">
          {/* Left: YAML Input */}
          <div className="flex flex-col h-full">
            <div className="px-4 py-2 bg-surface-subtle border-b border-border-subtle text-xs font-semibold text-ink-secondary uppercase tracking-wider">
              Sigma Rule (YAML)
            </div>
            <div className="flex-1 relative">
              <CodeEditor
                value={sigmaYaml}
                onChange={handleYamlChange}
                language="json" // YAML highlighting often works ok with generic or we'd need another extension
                height="100%"
                className="h-full border-0 rounded-none"
              />
            </div>
          </div>

          {/* Right: SQL Preview */}
          <div className="flex flex-col h-full bg-surface-inset">
            <div className="px-4 py-2 bg-surface-subtle border-b border-border-subtle text-xs font-semibold text-ink-secondary uppercase tracking-wider flex justify-between items-center">
              <span>SQL Preview</span>
              <span className="px-2 py-0.5 bg-ac-green/10 text-ac-green text-[10px] border border-ac-green/20 rounded-sm">
                ClickHouse Optimized
              </span>
            </div>
            <div className="flex-1 relative">
               <CodeEditor
                value={previewSql}
                onChange={setPreviewSql}
                language="sql"
                height="100%"
                readOnly={true}
                className="h-full border-0 rounded-none opacity-80"
              />
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-border-subtle flex justify-between items-center bg-surface-base">
          <div className="text-xs text-ink-muted">
            <p>Maps standard fields (UserAgent, c-ip) to <code className="bg-surface-subtle px-1 py-0.5 rounded border border-border-subtle">signal_events</code> schema.</p>
          </div>
          <div className="flex gap-3">
            <button
              onClick={onClose}
              className="btn-outline px-4 py-2 text-sm"
            >
              Cancel
            </button>
            <button
              onClick={handleImport}
              className="btn-primary px-4 py-2 text-sm flex items-center gap-2"
            >
              Import Query
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
