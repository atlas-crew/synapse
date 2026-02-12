import { useState, useRef, useEffect } from 'react';
import { Play, Square, ChevronDown, AlertTriangle, Shield, Moon } from 'lucide-react';
import { clsx } from 'clsx';
import { useDemoMode, useDemoActions, type DemoScenario } from '../../stores/demoModeStore';
import { SCENARIO_PROFILES } from '../../lib/demoData/scenarios';
import { invalidateDemoCache } from '../../lib/demoData';
import { Stack } from '@/ui';

const SCENARIO_ICONS: Record<DemoScenario, typeof AlertTriangle> = {
  'high-threat': AlertTriangle,
  normal: Shield,
  quiet: Moon,
};

const SCENARIO_COLORS: Record<DemoScenario, string> = {
  'high-threat': 'text-ac-red',
  normal: 'text-ac-green',
  quiet: 'text-ac-cyan',
};

export function DemoModeControls() {
  const { isEnabled, scenario } = useDemoMode();
  const { toggleDemo, setScenario } = useDemoActions();
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  // Close dropdown on outside click
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setDropdownOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleScenarioChange = (newScenario: DemoScenario) => {
    if (newScenario !== scenario) {
      invalidateDemoCache(); // Clear cache when scenario changes
      setScenario(newScenario);
    }
    setDropdownOpen(false);
  };

  const currentProfile = SCENARIO_PROFILES[scenario];
  const ScenarioIcon = SCENARIO_ICONS[scenario];

  return (
    <div ref={dropdownRef}>
      <Stack direction="row" align="center" gap="sm">
      {/* Demo Mode Toggle Button */}
      <button
        type="button"
        onClick={toggleDemo}
        className={clsx(
          'h-8 px-3 text-xs font-medium transition-colors border',
          isEnabled
            ? 'bg-ac-magenta/10 border-ac-magenta text-ac-magenta hover:bg-ac-magenta/20'
            : 'border-border-subtle text-ink-secondary hover:text-ink-primary hover:bg-surface-card'
        )}
      >
        {isEnabled ? (
          <Stack direction="row" align="center" gap="sm">
            <Square className="w-3 h-3" />
            <span>Exit Demo</span>
          </Stack>
        ) : (
          <Stack direction="row" align="center" gap="sm">
            <Play className="w-3 h-3" />
            <span>Demo Mode</span>
          </Stack>
        )}
      </button>

      {/* Scenario Selector (only visible when demo mode enabled) */}
      {isEnabled && (
        <div className="relative">
          <button
            type="button"
            onClick={() => setDropdownOpen(!dropdownOpen)}
            className={clsx(
              'h-8 px-3 text-xs border transition-colors',
              'border-border-subtle bg-surface-card hover:bg-surface-subtle',
              SCENARIO_COLORS[scenario]
            )}
          >
            <Stack direction="row" align="center" gap="sm">
              <ScenarioIcon className="w-3 h-3" />
              <span className="text-ink-primary">{currentProfile.label}</span>
              <ChevronDown className={clsx('w-3 h-3 transition-transform', dropdownOpen && 'rotate-180')} />
            </Stack>
          </button>

          {/* Dropdown Menu */}
          {dropdownOpen && (
            <div className="absolute top-full right-0 mt-1 w-64 bg-surface-card border border-border-subtle shadow-lg z-50">
              {(Object.keys(SCENARIO_PROFILES) as DemoScenario[]).map((key) => {
                const profile = SCENARIO_PROFILES[key];
                const Icon = SCENARIO_ICONS[key];
                const isSelected = key === scenario;

                return (
                  <button
                    key={key}
                    type="button"
                    onClick={() => handleScenarioChange(key)}
                    className={clsx(
                      'w-full flex items-start gap-3 px-3 py-2 text-left transition-colors',
                      isSelected ? 'bg-surface-subtle' : 'hover:bg-surface-subtle'
                    )}
                    >
                      <Icon className={clsx('w-4 h-4 mt-0.5 flex-shrink-0', SCENARIO_COLORS[key])} />
                      <div className="flex-1 min-w-0">
                        <Stack direction="row" align="center" gap="sm">
                          <span className="text-sm font-medium text-ink-primary">{profile.label}</span>
                          {isSelected && (
                            <span className="text-[10px] tracking-wider uppercase text-ac-magenta">Active</span>
                          )}
                        </Stack>
                      <p className="text-xs text-ink-muted mt-0.5">{profile.description}</p>
                    </div>
                  </button>
                );
              })}
            </div>
          )}
        </div>
      )}
      </Stack>
    </div>
  );
}

export default DemoModeControls;
