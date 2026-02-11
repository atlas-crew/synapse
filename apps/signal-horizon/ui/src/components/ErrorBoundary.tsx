/**
 * Error Boundary Component
 * Catches React errors and displays fallback UI
 * Uses key-based remounting for true recovery of children
 */

import { Component, type ReactNode, type ErrorInfo } from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';
import { SectionHeader } from '@/ui';

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
  /** Optional callback when error is caught */
  onError?: (error: Error, errorInfo: ErrorInfo) => void;
  /** Optional callback when retry is clicked */
  onRetry?: () => void;
}

interface State {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
  /** Key for forcing remount of children on retry */
  retryKey: number;
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null, errorInfo: null, retryKey: 0 };
  }

  static getDerivedStateFromError(error: Error): Partial<State> {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo): void {
    this.setState({ errorInfo });
    // Log to error reporting service
    console.error('ErrorBoundary caught an error:', error, errorInfo);
    // Call optional error callback
    this.props.onError?.(error, errorInfo);
  }

  handleRetry = (): void => {
    // Increment retryKey to force remount of children
    this.setState((prevState) => ({
      hasError: false,
      error: null,
      errorInfo: null,
      retryKey: prevState.retryKey + 1,
    }));
    // Call optional retry callback
    this.props.onRetry?.();
  };

  render(): ReactNode {
    if (this.state.hasError) {
      if (this.props.fallback) {
        return this.props.fallback;
      }

      return (
        <div
          role="status"
          aria-live="assertive"
          className="flex flex-col items-center justify-center min-h-[400px] p-6 bg-surface-base text-ink-primary"
        >
          <div className="p-4 border border-ac-red/40 bg-ac-red/10 mb-4">
            <AlertTriangle className="w-8 h-8 text-ac-red" aria-hidden="true" />
          </div>
          <SectionHeader
            title="Something went wrong"
            size="h4"
            mb="xs"
            style={{ marginBottom: '8px', display: 'inline-block' }}
            titleStyle={{ fontSize: '24px', lineHeight: '30px', textAlign: 'center' }}
          />
          <p className="text-ink-secondary text-center max-w-md mb-4">
            An error occurred while rendering this component. Try refreshing or contact support if the problem persists.
          </p>
          {import.meta.env.DEV && this.state.error && (
            <pre className="text-xs text-ac-red bg-surface-subtle p-4 border border-ac-red/30 max-w-lg overflow-auto mb-4">
              {this.state.error.message}
              {this.state.errorInfo?.componentStack}
            </pre>
          )}
          <button
            onClick={this.handleRetry}
            className="btn-primary"
            aria-label="Retry loading this component"
          >
            <RefreshCw className="w-4 h-4" aria-hidden="true" />
            Try Again
          </button>
        </div>
      );
    }

    // Use key to force remount of children on retry
    // This ensures fresh state and re-runs effects
    return (
      <div key={this.state.retryKey}>
        {this.props.children}
      </div>
    );
  }
}

export default ErrorBoundary;
