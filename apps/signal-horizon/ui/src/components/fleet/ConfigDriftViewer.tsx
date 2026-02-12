import { useState } from 'react';
import { AlertTriangle, CheckCircle, ArrowRight, GitCommit } from 'lucide-react';
import { clsx } from 'clsx';
import { CodeEditor } from '../ctrlx/CodeEditor';
import { Button, Stack } from '@/ui';

interface ConfigDriftViewerProps {
  expectedConfig: string;
  actualConfig: string;
  lastSync?: string;
  driftDetected?: boolean;
}

export function ConfigDriftViewer({ 
  expectedConfig, 
  actualConfig, 
  lastSync,
  driftDetected = true 
}: ConfigDriftViewerProps) {
  const [viewMode, setViewMode] = useState<'split' | 'unified'>('split');

  return (
    <div className="space-y-4">
      {/* Drift Status Banner */}
      <div className={clsx(
        "p-4 border  flex items-center justify-between",
        driftDetected 
          ? "bg-ac-orange/10 border-ac-orange/30 text-ac-orange" 
          : "bg-ac-green/10 border-ac-green/30 text-ac-green"
      )}>
        <Stack direction="row" align="center" gap="md">
          {driftDetected ? <AlertTriangle className="w-5 h-5" /> : <CheckCircle className="w-5 h-5" />}
          <div>
            <h3 className="font-medium text-sm">
              {driftDetected ? "Configuration Drift Detected" : "Configuration Synced"}
            </h3>
            {lastSync && (
              <p className="text-xs opacity-80 mt-0.5">Last check: {lastSync}</p>
            )}
          </div>
        </Stack>
        
        {driftDetected && (
          <Button
            variant="outlined"
            size="sm"
            style={{ height: '32px', borderColor: 'rgba(227,82,5,0.3)' }}
          >
            Force Sync
          </Button>
        )}
      </div>

      {/* Editor Controls */}
      <div className="flex justify-end">
        <div className="flex bg-surface-subtle p-1 border border-border-subtle">
          <Button
            onClick={() => setViewMode('split')}
            variant={viewMode === 'split' ? 'secondary' : 'ghost'}
            size="sm"
            style={{ height: '28px', padding: '0 12px', fontSize: '12px' }}
          >
            Split View
          </Button>
          <Button
            onClick={() => setViewMode('unified')}
            variant={viewMode === 'unified' ? 'secondary' : 'ghost'}
            size="sm"
            style={{ height: '28px', padding: '0 12px', fontSize: '12px' }}
          >
            Unified
          </Button>
        </div>
      </div>

      {/* Diff View */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 h-[500px]">
        {/* Expected Config */}
        <div className="flex flex-col h-full">
          <div className="flex items-center justify-between mb-2 px-1">
            <Stack direction="row" align="center" gap="sm" className="text-xs font-semibold text-ink-secondary uppercase tracking-wider">
              <GitCommit className="w-3 h-3" />
              <span>Expected (Template)</span>
            </Stack>
          </div>
          <div className="flex-1 border border-border-subtle overflow-hidden">
            <CodeEditor
              value={expectedConfig}
              onChange={() => {}}
              language="json"
              readOnly={true}
              height="100%"
              className="h-full border-0"
            />
          </div>
        </div>

        {/* Actual Config */}
        {viewMode === 'split' && (
          <div className="flex flex-col h-full">
            <div className="flex items-center justify-between mb-2 px-1">
              <Stack direction="row" align="center" gap="sm" className="text-xs font-semibold text-ink-secondary uppercase tracking-wider">
                <ArrowRight className="w-3 h-3 text-ac-orange" />
                <span>Actual (Sensor)</span>
              </Stack>
            </div>
            <div className={clsx(
              "flex-1 border  overflow-hidden",
              driftDetected ? "border-ac-orange/50" : "border-border-subtle"
            )}>
              <CodeEditor
                value={actualConfig}
                onChange={() => {}}
                language="json"
                readOnly={true}
                height="100%"
                className="h-full border-0"
              />
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
