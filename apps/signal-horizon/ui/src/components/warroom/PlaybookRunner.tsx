import { useState, useEffect } from 'react';
import { CheckCircle, Circle, X, Play } from 'lucide-react';
import { clsx } from 'clsx';
import type { Playbook } from './PlaybookSelector';
import { Spinner } from '@/ui';

interface PlaybookRunnerProps {
  playbook: Playbook;
  onClose: () => void;
  onComplete: () => void;
}

export function PlaybookRunner({ playbook, onClose, onComplete }: PlaybookRunnerProps) {
  const [currentStep, setCurrentStep] = useState(0);
  const [isExecuting, setIsExecuting] = useState(false);
  const [isWaitingForApproval, setIsWaitingForApproval] = useState(false);

  useEffect(() => {
    if (isExecuting && currentStep < playbook.steps.length) {
      const step = playbook.steps[currentStep];

      // If this is an approval step and we haven't paused yet
      if (step.type === 'approval' && !isWaitingForApproval) {
        setIsWaitingForApproval(true);
        return;
      }

      // Simulate step execution (only if not waiting for approval)
      if (!isWaitingForApproval) {
        const timer = setTimeout(() => {
          setCurrentStep((prev) => prev + 1);
        }, 2000); // 2 seconds per step
        return () => clearTimeout(timer);
      }
    } else if (isExecuting && currentStep === playbook.steps.length) {
      setIsExecuting(false);
      onComplete();
    }
  }, [isExecuting, currentStep, isWaitingForApproval, playbook.steps, onComplete]);

  const handleStart = () => {
    setIsExecuting(true);
    setIsWaitingForApproval(false);
  };

  const handleApprove = () => {
    setIsWaitingForApproval(false);
    setCurrentStep((prev) => prev + 1);
  };

  return (
    <div className="border border-ac-blue/30 bg-ac-blue/5 p-4">
      <div className="flex items-center justify-between mb-4 border-b border-ac-blue/20 pb-3">
        <h3 className="font-medium text-ac-blue flex items-center gap-2">
          <Play className="w-4 h-4" />
          Running: {playbook.name}
        </h3>
        <button
          onClick={onClose}
          aria-label="Close playbook runner"
          className="text-ink-muted hover:text-ink-primary"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      <div className="space-y-4">
        {playbook.steps.map((step, index) => {
          const isCompleted = index < currentStep;
          const isCurrent = index === currentStep && isExecuting;
          const isApproval = step.type === 'approval';

          return (
            <div key={index} className="flex flex-col gap-2">
              <div className="flex items-center gap-3">
                {isCompleted ? (
                  <CheckCircle className="w-5 h-5 text-ac-green" />
                ) : isCurrent ? (
                  isWaitingForApproval ? (
                    <Circle className="w-5 h-5 text-ac-orange fill-ac-orange/20 animate-pulse" />
                  ) : (
                    <Spinner size={20} color="#0057B7" />
                  )
                ) : (
                  <Circle className="w-5 h-5 text-ink-muted" />
                )}
                
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
                    "text-[10px] px-1.5 py-0.5 rounded border uppercase font-semibold",
                    isCompleted ? "bg-surface-subtle text-ink-muted border-border-subtle" :
                    isCurrent ? (
                      isApproval ? "bg-ac-orange/10 text-ac-orange border-ac-orange/30" :
                      "bg-ac-blue/10 text-ac-blue border-ac-blue/30"
                    ) : "bg-surface-base text-ink-muted border-border-subtle opacity-50"
                  )}>
                    {step.type}
                  </span>
                </div>
              </div>

              {isCurrent && isWaitingForApproval && (
                <div className="ml-8 mt-1 p-3 bg-surface-subtle border border-border-subtle rounded space-y-3">
                  <p className="text-xs text-ink-secondary">
                    This step requires manual authorization to proceed. 
                    Please review the security implications before approving.
                  </p>
                  <button
                    onClick={handleApprove}
                    className="w-full bg-ac-orange text-white text-xs font-bold py-2 rounded hover:bg-ac-orange/90 transition-colors uppercase tracking-wider"
                  >
                    Approve and Continue
                  </button>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {!isExecuting && currentStep === 0 && (
        <button
          onClick={handleStart}
          className="mt-4 w-full btn-primary h-9 text-sm"
        >
          Execute Playbook
        </button>
      )}
      
      {!isExecuting && currentStep === playbook.steps.length && (
        <div className="mt-4 p-2 bg-ac-green/10 text-ac-green text-center text-sm font-medium border border-ac-green/20">
          Playbook Completed Successfully
        </div>
      )}
    </div>
  );
}
