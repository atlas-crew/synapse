import { useState, useRef, useCallback } from 'react';
import { X, ArrowRight, FileText } from 'lucide-react';
import { CodeEditor } from '../ctrlx/CodeEditor';
import { convertSigmaToSql } from '../../utils/sigmaToSql';
import { useFocusTrap } from '../../hooks/useFocusTrap';
import { SectionHeader } from '@/ui';

interface SigmaImportModalProps {
  onImport: (sql: string) => void;
  onSaveBackgroundHunt?: (input: { name: string; description?: string; sqlTemplate: string }) => Promise<void>;
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

export function SigmaImportModal({ onImport, onSaveBackgroundHunt, onClose }: SigmaImportModalProps) {
  const [sigmaYaml, setSigmaYaml] = useState(EXAMPLE_RULE);
  const [previewSql, setPreviewSql] = useState(convertSigmaToSql(EXAMPLE_RULE));
  const [ruleName, setRuleName] = useState('Suspicious cURL User Agent');
  const [ruleDescription, setRuleDescription] = useState('Detects suspicious cURL user agents often used by bots');
  const [saveStatus, setSaveStatus] = useState<'idle' | 'saving' | 'saved' | 'error'>('idle');
  const [saveError, setSaveError] = useState<string | null>(null);
  const modalRef = useRef<HTMLDivElement>(null);
  const stableOnClose = useCallback(() => onClose(), [onClose]);
  useFocusTrap(modalRef, true, stableOnClose);

  const handleYamlChange = (value: string) => {
    setSigmaYaml(value);
    setPreviewSql(convertSigmaToSql(value));
    setSaveStatus('idle');
    setSaveError(null);

    // Light-touch extraction of title/description for form defaults.
    const titleMatch = value.match(/^\s*title:\s*(.+)\s*$/m);
    if (titleMatch?.[1]) setRuleName(titleMatch[1].replace(/^['"]|['"]$/g, '').trim());
    const descMatch = value.match(/^\s*description:\s*(.+)\s*$/m);
    if (descMatch?.[1]) setRuleDescription(descMatch[1].replace(/^['"]|['"]$/g, '').trim());
  };

  const handleImport = () => {
    onImport(previewSql);
    onClose();
  };

  const handleSaveBackgroundHunt = async () => {
    if (!onSaveBackgroundHunt) return;
    setSaveStatus('saving');
    setSaveError(null);
    try {
      await onSaveBackgroundHunt({ name: ruleName, description: ruleDescription, sqlTemplate: previewSql });
      setSaveStatus('saved');
    } catch (err) {
      setSaveStatus('error');
      setSaveError(err instanceof Error ? err.message : 'Failed to save background hunt');
    }
  };

  return (
    <div className="fixed inset-0 bg-ac-black/50 flex items-center justify-center z-50">
      <div ref={modalRef} role="dialog" aria-modal="true" aria-labelledby="sigma-import-title" className="bg-surface-base border border-border-subtle w-full max-w-5xl h-[80vh] flex flex-col shadow-2xl">
        {/* Header */}
        <div className="px-6 py-4 border-b border-border-subtle flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-ac-blue/10">
              <FileText className="w-5 h-5 text-ac-blue" />
            </div>
            <div>
              <SectionHeader
                titleId="sigma-import-title"
                title="Import Sigma Rule"
                size="h4"
                mb="xs"
                style={{ marginBottom: 0 }}
                titleStyle={{ fontSize: '18px', lineHeight: '24px', fontWeight: 500 }}
              />
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
                className="h-full border-0"
              />
            </div>
          </div>

          {/* Right: SQL Preview */}
          <div className="flex flex-col h-full bg-surface-inset">
            <div className="px-4 py-2 bg-surface-subtle border-b border-border-subtle text-xs font-semibold text-ink-secondary uppercase tracking-wider flex justify-between items-center">
              <span>SQL Preview</span>
              <span className="px-2 py-0.5 bg-ac-green/10 text-ac-green text-[10px] border border-ac-green/20">
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
                className="h-full border-0 opacity-80"
              />
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-border-subtle flex justify-between items-center bg-surface-base">
          <div className="min-w-0 flex-1 pr-4">
            <div className="grid grid-cols-2 gap-3">
              <label className="text-xs text-ink-secondary">
                Rule Name
                <input
                  className="mt-1 w-full px-2 py-1 border border-border-subtle bg-surface-inset text-ink-primary font-mono"
                  value={ruleName}
                  onChange={(e) => setRuleName(e.target.value)}
                  maxLength={120}
                />
              </label>
              <label className="text-xs text-ink-secondary">
                Description
                <input
                  className="mt-1 w-full px-2 py-1 border border-border-subtle bg-surface-inset text-ink-primary font-mono"
                  value={ruleDescription}
                  onChange={(e) => setRuleDescription(e.target.value)}
                  maxLength={2000}
                />
              </label>
            </div>
            <div className="mt-2 text-[11px] text-ink-muted">
              Maps standard fields (UserAgent, c-ip) to <code className="bg-surface-subtle px-1 py-0.5 border border-border-subtle">signal_events</code>.
              {saveStatus === 'saved' && <span className="ml-2 text-ac-green">Saved background hunt.</span>}
              {saveStatus === 'error' && <span className="ml-2 text-ac-red">{saveError ?? 'Save failed.'}</span>}
            </div>
          </div>
          <div className="flex gap-3">
            <button
              onClick={onClose}
              className="btn-outline px-4 py-2 text-sm"
            >
              Cancel
            </button>
            <button
              onClick={handleSaveBackgroundHunt}
              disabled={!onSaveBackgroundHunt || saveStatus === 'saving'}
              className="btn-ghost px-4 py-2 text-sm disabled:opacity-50 disabled:cursor-not-allowed"
              title="Persist rule and enable scheduled background hunting"
            >
              {saveStatus === 'saving' ? 'Saving...' : 'Save Background Hunt'}
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
