import { useState, useEffect, useCallback, useMemo } from 'react';

export interface UseConfigFormOptions<T> {
  /** Initial/remote config value */
  remoteConfig: T | undefined;
  /** Optional transform to apply when syncing from remote */
  transformFromRemote?: (remote: T) => T;
  /** Optional validator function */
  validate?: (config: T) => Record<string, string>;
  /** Callback when config changes (for parent sync) */
  onDirtyChange?: (isDirty: boolean) => void;
}

export interface UseConfigFormReturn<T> {
  /** Current local config state */
  config: T;
  /** Whether local config differs from remote */
  isDirty: boolean;
  /** Validation errors (empty if valid) */
  errors: Record<string, string>;
  /** Whether config is valid */
  isValid: boolean;
  /** Update config with new values */
  setConfig: (config: T) => void;
  /** Update a single field */
  updateField: <K extends keyof T>(field: K, value: T[K]) => void;
  /** Reset to remote config */
  reset: () => void;
  /** Mark config as saved (clears dirty state) */
  markSaved: () => void;
}

/**
 * Hook for managing form state with remote sync, dirty tracking, and validation.
 *
 * @example
 * const { config, isDirty, errors, setConfig, reset } = useConfigForm({
 *   remoteConfig: data?.config,
 *   validate: validateDlpConfig,
 * });
 */
export function useConfigForm<T extends Record<string, unknown>>({
  remoteConfig,
  transformFromRemote,
  validate,
  onDirtyChange,
}: UseConfigFormOptions<T>): UseConfigFormReturn<T> {
  const [localConfig, setLocalConfig] = useState<T>(() => {
    if (remoteConfig) {
      return transformFromRemote ? transformFromRemote(remoteConfig) : remoteConfig;
    }
    return {} as T;
  });
  const [isDirty, setIsDirty] = useState(false);

  // Sync from remote when it changes
  useEffect(() => {
    if (remoteConfig) {
      const transformed = transformFromRemote ? transformFromRemote(remoteConfig) : remoteConfig;
      setLocalConfig(transformed);
      setIsDirty(false);
    }
  }, [remoteConfig, transformFromRemote]);

  // Notify parent of dirty state changes
  useEffect(() => {
    onDirtyChange?.(isDirty);
  }, [isDirty, onDirtyChange]);

  // Compute validation errors
  const errors = useMemo(() => {
    if (!validate) return {};
    return validate(localConfig);
  }, [localConfig, validate]);

  const isValid = useMemo(() => Object.keys(errors).length === 0, [errors]);

  const setConfig = useCallback((newConfig: T) => {
    setLocalConfig(newConfig);
    setIsDirty(true);
  }, []);

  const updateField = useCallback(<K extends keyof T>(field: K, value: T[K]) => {
    setLocalConfig(prev => ({ ...prev, [field]: value }));
    setIsDirty(true);
  }, []);

  const reset = useCallback(() => {
    if (remoteConfig) {
      const transformed = transformFromRemote ? transformFromRemote(remoteConfig) : remoteConfig;
      setLocalConfig(transformed);
      setIsDirty(false);
    }
  }, [remoteConfig, transformFromRemote]);

  const markSaved = useCallback(() => {
    setIsDirty(false);
  }, []);

  return {
    config: localConfig,
    isDirty,
    errors,
    isValid,
    setConfig,
    updateField,
    reset,
    markSaved,
  };
}
