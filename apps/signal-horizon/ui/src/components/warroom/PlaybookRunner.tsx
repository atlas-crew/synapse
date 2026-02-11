import { useEffect, useReducer, useRef } from 'react';
import { CheckCircle, Circle, X, Play, AlertCircle } from 'lucide-react';
import { clsx } from 'clsx';
import type { Playbook } from './PlaybookSelector';
import { Spinner, Stack } from '@/ui';

interface PlaybookRunnerProps {
  playbook: Playbook;
  onClose: () => void;
  onComplete: () => void;
}

type State = {
  status: 'idle' | 'executing' | 'waiting_approval' | 'completed';
  currentStep: number;
};

type Action =
  | { type: 'START' }
  | { type: 'ADVANCE' }
  | { type: 'PAUSE_FOR_APPROVAL' }
  | { type: 'APPROVE' }
  | { type: 'RESET' };

function playbookReducer(state: State, action: Action): State {
  switch (action.type) {
    case 'START':
      return { status: 'executing', currentStep: 0 };
    case 'ADVANCE':
      return { ...state, currentStep: state.currentStep + 1 };
    case 'PAUSE_FOR_APPROVAL':
      return { ...state, status: 'waiting_approval' };
    case 'APPROVE':
      return { status: 'executing', currentStep: state.currentStep + 1 };
    case 'RESET':
      return { status: 'idle', currentStep: 0 };
    default:
      return state;
  }
}

export function PlaybookRunner({ playbook, onClose, onComplete }: PlaybookRunnerProps) {
  const [state, dispatch] = useReducer(playbookReducer, { status: 'idle', currentStep: 0 });
  const approvalButtonRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (state.status === 'executing') {
      if (state.currentStep >= playbook.steps.length) {
        onComplete();
        return;
      }

      const step = playbook.steps[state.currentStep];
      
      if (step.type === 'approval') {
        dispatch({ type: 'PAUSE_FOR_APPROVAL' });
        return;
      }

      const timer = setTimeout(() => {
        dispatch({ type: 'ADVANCE' });
      }, 2000);

      return () => clearTimeout(timer);
    }
  }, [state.status, state.currentStep, playbook, onComplete]);

  // Focus management for approval button
  useEffect(() => {
    if (state.status === 'waiting_approval') {
      approvalButtonRef.current?.focus();
    }
  }, [state.status]);

  const handleStart = () => dispatch({ type: 'START' });
  const handleApprove = () => dispatch({ type: 'APPROVE' });

  return (
    <div className="border border-ac-blue/30 bg-ac-blue/5 p-4" role="region" aria-label="Playbook Execution Runner">
      <div className="flex items-center justify-between mb-4 border-b border-ac-blue/20 pb-3">
        <h3 className="font-medium text-ac-blue flex items-center gap-2">
          <Play className="w-4 h-4" aria-hidden="true" />
          <span>Running: {playbook.name}</span>
        </h3>
        <button
          onClick={onClose}
          aria-label="Close playbook runner"
          className="text-ink-muted hover:text-ink-primary p-1 rounded hover:bg-black/5 transition-colors"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      <div className="mb-4 flex items-center justify-between text-[10px] uppercase tracking-wider font-bold text-ink-muted">
        <span>Execution Progress</span>
        <span>
          Step {Math.min(state.currentStep + 1, playbook.steps.length)} of {playbook.steps.length}
        </span>
      </div>

      <div className="space-y-4">
        {playbook.steps.map((step, index) => {
          const isCompleted = index < state.currentStep;
          const isCurrent = index === state.currentStep && state.status !== 'idle';
          const isWaiting = isCurrent && state.status === 'waiting_approval';
          const isApprovalType = step.type === 'approval';

          return (
            <Stack key={index} direction="column" gap="sm">
              <div className="flex items-center gap-3">
                <div className="flex-shrink-0">
                  {isCompleted ? (
                    <CheckCircle className="w-5 h-5 text-ac-green" aria-label="Completed" />
                  ) : isCurrent ? (
                    isWaiting ? (
                      <AlertCircle className="w-5 h-5 text-ac-orange animate-pulse" aria-label="Waiting for approval" />
                    ) : (
                      <Spinner size={20} color="#0057B7" />
                    )
                  ) : (
                    <Circle className="w-5 h-5 text-ink-muted" aria-label="Pending" />
                  )}
                </div>
                
                <div className="flex-1 flex items-center justify-between gap-4">
                  <span className={clsx(
                    "text-sm transition-colors",
                    isCompleted ? "text-ink-primary" :
                    isCurrent ? "text-ac-blue font-medium" :
                    "text-ink-muted"
                  )}>
                    {step.name}
                  </span>
                  
                  <span className={clsx(
                    "text-[10px] px-1.5 py-0.5 rounded border uppercase font-bold",
                    isCompleted ? "bg-surface-subtle text-ink-muted border-border-subtle" :
                    isCurrent ? (
                      isApprovalType ? "bg-ac-orange/20 text-ac-orange border-ac-orange/40" :
                      "bg-ac-blue/20 text-ac-blue border-ac-blue/40"
                    ) : "bg-surface-base text-ink-muted border-border-subtle opacity-50"
                  )}>
                    {step.type}
                  </span>
                </div>
              </div>

              {isWaiting && (
                <div 
                  className="ml-8 mt-1 p-3 bg-white border border-ac-orange/30 rounded-sm shadow-sm space-y-3"
                  role="status"
                >
                  <p className="text-xs text-ink-secondary leading-relaxed">
                    <strong className="text-ac-orange">Manual Approval Required:</strong> {step.name}. 
                    Review the security implications before authorizing this action.
                  </p>
                  <button
                    ref={approvalButtonRef}
                    onClick={handleApprove}
                    aria-label={`Approve ${step.name} and continue`}
                    className="w-full bg-ac-orange text-white text-xs font-bold py-2.5 rounded hover:bg-ac-orange/90 transition-colors uppercase tracking-widest shadow-sm"
                  >
                    Approve and Continue
                  </button>
                </div>
              )}
            </Stack>
          );
        })}
      </div>

      {state.status === 'idle' && (
        <button
          onClick={handleStart}
          className="mt-6 w-full btn-primary h-10 text-sm font-bold uppercase tracking-widest"
        >
          Execute Playbook
        </button>
      )}
      
      {state.currentStep >= playbook.steps.length && state.status !== 'idle' && (
        <div className="mt-6 p-3 bg-ac-green/10 text-ac-green text-center text-sm font-bold border border-ac-green/20 rounded shadow-inner">
          ✓ Playbook Completed Successfully
        </div>
      )}
    </div>
  );
}
