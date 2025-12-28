import React, { ReactNode } from 'react';
import { AlertTriangle } from 'lucide-react';

interface ApexErrorBoundaryProps {
  children: ReactNode;
  title?: string;
  description?: string;
  level?: 'page' | 'component';
}

interface ApexErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
}

export class ApexErrorBoundary extends React.Component<
  ApexErrorBoundaryProps,
  ApexErrorBoundaryState
> {
  constructor(props: ApexErrorBoundaryProps) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
    };
  }

  static getDerivedStateFromError(error: Error): ApexErrorBoundaryState {
    return {
      hasError: true,
      error,
    };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    const { level = 'component' } = this.props;
    console.error(
      `[ApexErrorBoundary - ${level}] Error caught:`,
      error,
      errorInfo
    );
  }

  handleReset = () => {
    this.setState({
      hasError: false,
      error: null,
    });
  };

  render() {
    const {
      children,
      title = 'Apex Component Error',
      description = 'An error occurred while loading this component.',
      level = 'component',
    } = this.props;

    const { hasError } = this.state;

    if (hasError) {
      return (
        <div
          className={`flex flex-col items-center justify-center ${
            level === 'page' ? 'min-h-screen' : 'min-h-[200px]'
          } bg-gray-900 border border-red-900 p-6`}
        >
          <AlertTriangle className="w-12 h-12 text-red-500 mb-4" />
          <h3 className="text-lg font-semibold text-white mb-2">{title}</h3>
          <p className="text-sm text-gray-400 mb-4 text-center max-w-md">
            {description}
          </p>
          <div className="flex gap-3">
            <button
              onClick={this.handleReset}
              className="px-4 py-2 bg-gray-700 text-white hover:bg-gray-600 rounded"
            >
              Try Again
            </button>
            <button
              onClick={() => window.location.reload()}
              className="px-4 py-2 bg-horizon-600 text-white hover:bg-horizon-700 rounded"
            >
              Reload Page
            </button>
          </div>
        </div>
      );
    }

    return children;
  }
}
