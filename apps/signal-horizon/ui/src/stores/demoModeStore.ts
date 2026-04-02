import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import { useShallow } from 'zustand/shallow';

// Demo scenario types
export type DemoScenario = 'high-threat' | 'normal' | 'quiet';

interface DemoModeState {
  // State
  isEnabled: boolean;
  scenario: DemoScenario;

  // Actions
  toggleDemo: () => void;
  enableDemo: () => void;
  disableDemo: () => void;
  setScenario: (scenario: DemoScenario) => void;
}

export const useDemoModeStore = create<DemoModeState>()(
  persist(
    (set) => ({
      // Initial state — VITE_DEMO_MODE=true activates demo mode by default
      isEnabled: import.meta.env.VITE_DEMO_MODE === 'true',
      scenario: 'normal',

      // Actions
      toggleDemo: () =>
        set((state) => ({ isEnabled: !state.isEnabled })),

      enableDemo: () =>
        set({ isEnabled: true }),

      disableDemo: () =>
        set({ isEnabled: false }),

      setScenario: (scenario) =>
        set({ scenario }),
    }),
    {
      name: 'beam-demo-mode',
      partialize: (state) => ({
        isEnabled: state.isEnabled,
        scenario: state.scenario,
      }),
    }
  )
);

// Memoized selectors
export const useDemoMode = () =>
  useDemoModeStore(
    useShallow((state) => ({
      isEnabled: state.isEnabled,
      scenario: state.scenario,
    }))
  );

export const useDemoActions = () =>
  useDemoModeStore(
    useShallow((state) => ({
      toggleDemo: state.toggleDemo,
      enableDemo: state.enableDemo,
      disableDemo: state.disableDemo,
      setScenario: state.setScenario,
    }))
  );

// Convenience hook for checking if demo mode is active
export const useIsDemo = () => useDemoModeStore((state) => state.isEnabled);

// Get current scenario
export const useDemoScenario = () => useDemoModeStore((state) => state.scenario);
