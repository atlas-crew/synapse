import React from 'react';
import { colors, fontFamily, fontWeight, spacing, transitions } from '../tokens/tokens';

/**
 * Tabs — Horizontal tab navigation with underline indicator.
 *
 * Usage:
 *   <Tabs
 *     tabs={[
 *       { key: 'traffic', label: 'Traffic' },
 *       { key: 'threats', label: 'Threats', badge: 12 },
 *       { key: 'config', label: 'Configuration' },
 *     ]}
 *     active={activeTab}
 *     onChange={setActiveTab}
 *   />
 */

type TabVariant = 'underline' | 'pills';
type TabSize = 'sm' | 'md' | 'lg';

interface Tab {
  key: string;
  label: string;
  badge?: number | string;
  icon?: React.ReactNode;
  disabled?: boolean;
}

interface TabsProps {
  tabs: Tab[];
  active: string;
  onChange: (key: string) => void;
  variant?: TabVariant;
  size?: TabSize;
  fill?: boolean;
  ariaLabel?: string;
  idPrefix?: string;
  panelIdPrefix?: string;
  style?: React.CSSProperties;
}

const sizeMap: Record<TabSize, { fontSize: string; padding: string; gap: string }> = {
  sm: { fontSize: '12px', padding: '8px 12px', gap: '4px' },
  md: { fontSize: '14px', padding: '10px 16px', gap: '8px' },
  lg: { fontSize: '16px', padding: '12px 20px', gap: '8px' },
};

export const Tabs: React.FC<TabsProps> = ({
  tabs,
  active,
  onChange,
  variant = 'underline',
  size = 'md',
  fill,
  ariaLabel,
  idPrefix,
  panelIdPrefix,
  style,
}) => {
  const s = sizeMap[size];
  const enabledTabs = tabs.filter((tab) => !tab.disabled);

  const handleArrowNavigation = (currentKey: string, key: string) => {
    if (key !== 'ArrowRight' && key !== 'ArrowLeft') return;
    if (enabledTabs.length === 0) return;
    const currentIndex = enabledTabs.findIndex((tab) => tab.key === currentKey);
    if (currentIndex === -1) return;

    const delta = key === 'ArrowRight' ? 1 : -1;
    const nextIndex = (currentIndex + delta + enabledTabs.length) % enabledTabs.length;
    onChange(enabledTabs[nextIndex].key);
  };

  return (
    <div
      role="tablist"
      aria-label={ariaLabel}
      style={{
        display: 'flex',
        gap: variant === 'pills' ? spacing.xs : '0',
        borderBottom: variant === 'underline' ? '1px solid rgba(255,255,255,0.08)' : undefined,
        width: fill ? '100%' : undefined,
        ...style,
      }}
    >
      {tabs.map((tab) => {
        const isActive = tab.key === active;

        if (variant === 'pills') {
          return (
            <button
              key={tab.key}
              onClick={() => !tab.disabled && onChange(tab.key)}
              onKeyDown={(e) => handleArrowNavigation(tab.key, e.key)}
              disabled={tab.disabled}
              role="tab"
              id={idPrefix ? `${idPrefix}${tab.key}` : undefined}
              aria-selected={isActive}
              aria-controls={panelIdPrefix ? `${panelIdPrefix}${tab.key}` : undefined}
              tabIndex={isActive ? 0 : -1}
              style={{
                fontFamily,
                fontWeight: isActive ? fontWeight.medium : fontWeight.regular,
                fontSize: s.fontSize,
                padding: s.padding,
                background: isActive ? colors.blue : 'transparent',
                color: isActive ? '#FFFFFF' : tab.disabled ? colors.gray.mid : 'rgba(255,255,255,0.6)',
                border: 'none',
                borderRadius: 0,
                cursor: tab.disabled ? 'not-allowed' : 'pointer',
                transition: `all ${transitions.fast}`,
                display: 'flex',
                alignItems: 'center',
                gap: s.gap,
                flex: fill ? 1 : undefined,
                justifyContent: fill ? 'center' : undefined,
                opacity: tab.disabled ? 0.5 : 1,
              }}
            >
              {tab.icon}
              {tab.label}
              {tab.badge !== undefined && (
                <span
                  style={{
                    background: isActive ? 'rgba(255,255,255,0.2)' : colors.magenta,
                    color: '#FFFFFF',
                    fontSize: '10px',
                    fontWeight: fontWeight.medium,
                    padding: '1px 6px',
                    borderRadius: 0,
                    minWidth: '18px',
                    textAlign: 'center',
                  }}
                >
                  {tab.badge}
                </span>
              )}
            </button>
          );
        }

        // Underline variant
        return (
          <button
            key={tab.key}
            onClick={() => !tab.disabled && onChange(tab.key)}
            onKeyDown={(e) => handleArrowNavigation(tab.key, e.key)}
            disabled={tab.disabled}
            role="tab"
            id={idPrefix ? `${idPrefix}${tab.key}` : undefined}
            aria-selected={isActive}
            aria-controls={panelIdPrefix ? `${panelIdPrefix}${tab.key}` : undefined}
            tabIndex={isActive ? 0 : -1}
            style={{
              fontFamily,
              fontWeight: isActive ? fontWeight.medium : fontWeight.regular,
              fontSize: s.fontSize,
              padding: s.padding,
              paddingBottom: `calc(${s.padding.split(' ')[0]} + 2px)`,
              background: 'transparent',
              color: isActive ? '#F0F4F8' : tab.disabled ? colors.gray.mid : 'rgba(255,255,255,0.5)',
              border: 'none',
              borderBottom: isActive ? `2px solid ${colors.blue}` : '2px solid transparent',
              marginBottom: '-1px',
              borderRadius: 0,
              cursor: tab.disabled ? 'not-allowed' : 'pointer',
              transition: `all ${transitions.fast}`,
              display: 'flex',
              alignItems: 'center',
              gap: s.gap,
              flex: fill ? 1 : undefined,
              justifyContent: fill ? 'center' : undefined,
              opacity: tab.disabled ? 0.5 : 1,
            }}
          >
            {tab.icon}
            {tab.label}
            {tab.badge !== undefined && (
              <span
                style={{
                  background: colors.magenta,
                  color: '#FFFFFF',
                  fontSize: '10px',
                  fontWeight: fontWeight.medium,
                  padding: '1px 6px',
                  borderRadius: 0,
                  minWidth: '18px',
                  textAlign: 'center',
                }}
              >
                {tab.badge}
              </span>
            )}
          </button>
        );
      })}
    </div>
  );
};

Tabs.displayName = 'Tabs';

