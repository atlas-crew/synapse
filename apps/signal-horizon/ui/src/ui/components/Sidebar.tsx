import React, { useState } from 'react';
import { colors, fontFamily, fontWeight, spacing, transitions } from '../tokens/tokens';

/**
 * Sidebar — Main navigation shell for Signal Horizon.
 * AppShell — Layout wrapper that pairs Sidebar with main content.
 */

interface NavItem {
  key: string;
  label: string;
  icon?: React.ReactNode;
  badge?: string | number;
  disabled?: boolean;
  children?: Omit<NavItem, 'children'>[];
}

interface NavSection {
  label?: string;
  items: NavItem[];
}

interface SidebarProps {
  sections: NavSection[];
  active: string;
  onNavigate: (key: string) => void;
  logo?: React.ReactNode;
  footer?: React.ReactNode;
  collapsed?: boolean;
  onToggleCollapse?: () => void;
  width?: string;
  collapsedWidth?: string;
  style?: React.CSSProperties;
}

export const Sidebar: React.FC<SidebarProps> = ({
  sections,
  active,
  onNavigate,
  logo,
  footer,
  collapsed = false,
  onToggleCollapse,
  width = '240px',
  collapsedWidth = '56px',
  style,
}) => {
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set());

  const toggleGroup = (key: string) => {
    setExpandedGroups((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const currentWidth = collapsed ? collapsedWidth : width;

  return (
    <nav
      style={{
        width: currentWidth,
        minWidth: currentWidth,
        height: '100vh',
        background: colors.navy,
        borderRight: '1px solid rgba(255,255,255,0.06)',
        display: 'flex',
        flexDirection: 'column',
        transition: `width ${transitions.normal}, min-width ${transitions.normal}`,
        overflow: 'hidden',
        position: 'sticky',
        top: 0,
        flexShrink: 0,
        ...style,
      }}
    >
      {logo && (
        <div
          style={{
            padding: collapsed ? `${spacing.md} ${spacing.sm}` : `${spacing.lg} ${spacing.md}`,
            borderBottom: '1px solid rgba(255,255,255,0.06)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: collapsed ? 'center' : 'flex-start',
            gap: spacing.sm,
            flexShrink: 0,
          }}
        >
          {logo}
        </div>
      )}

      {onToggleCollapse && (
        <button
          onClick={onToggleCollapse}
          style={{
            background: 'none',
            border: 'none',
            borderBottom: '1px solid rgba(255,255,255,0.06)',
            color: colors.gray.mid,
            cursor: 'pointer',
            padding: `${spacing.sm} ${spacing.md}`,
            fontFamily,
            fontSize: '11px',
            textAlign: collapsed ? 'center' : 'right',
            transition: `color ${transitions.fast}`,
          }}
          onMouseEnter={(e) => ((e.target as HTMLElement).style.color = '#F0F4F8')}
          onMouseLeave={(e) => ((e.target as HTMLElement).style.color = colors.gray.mid)}
        >
          {collapsed ? '→' : '← Collapse'}
        </button>
      )}

      <div style={{ flex: 1, overflow: 'auto', padding: `${spacing.sm} 0` }}>
        {sections.map((section, si) => (
          <div key={si} style={{ marginBottom: spacing.sm }}>
            {section.label && !collapsed && (
              <div
                style={{
                  fontFamily,
                  fontWeight: fontWeight.bold,
                  fontSize: '10px',
                  color: colors.gray.mid,
                  textTransform: 'uppercase',
                  letterSpacing: '0.1em',
                  padding: `${spacing.sm} ${spacing.md}`,
                }}
              >
                {section.label}
              </div>
            )}

            {section.items.map((item) => {
              const isActive = item.key === active;
              const hasChildren = item.children && item.children.length > 0;
              const isExpanded = expandedGroups.has(item.key);

              return (
                <React.Fragment key={item.key}>
                  <button
                    onClick={() => {
                      if (hasChildren) toggleGroup(item.key);
                      else if (!item.disabled) onNavigate(item.key);
                    }}
                    disabled={item.disabled}
                    style={{
                      width: '100%',
                      background: isActive ? 'rgba(30, 144, 255, 0.2)' : 'transparent',
                      border: 'none',
                      borderLeft: isActive ? `3px solid ${colors.blue}` : '3px solid transparent',
                      borderRadius: 0,
                      padding: collapsed ? `${spacing.sm} 0` : `${spacing.sm} ${spacing.md}`,
                      paddingLeft: collapsed ? '0' : `calc(${spacing.md} - 3px)`,
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: collapsed ? 'center' : 'flex-start',
                      gap: spacing.sm,
                      cursor: item.disabled ? 'not-allowed' : 'pointer',
                      color: isActive ? '#F0F4F8' : item.disabled ? colors.gray.mid : 'rgba(255,255,255,0.6)',
                      fontFamily,
                      fontWeight: isActive ? fontWeight.medium : fontWeight.regular,
                      fontSize: '13px',
                      transition: `all ${transitions.fast}`,
                      opacity: item.disabled ? 0.5 : 1,
                      textAlign: collapsed ? 'center' : 'left',
                    }}
                    onMouseEnter={(e) => {
                      if (!isActive) (e.currentTarget as HTMLElement).style.background = 'rgba(255,255,255,0.04)';
                    }}
                    onMouseLeave={(e) => {
                      if (!isActive) (e.currentTarget as HTMLElement).style.background = 'transparent';
                    }}
                  >
                    {item.icon && (
                      <span style={{ flexShrink: 0, width: '20px', textAlign: 'center', fontSize: '16px' }}>
                        {item.icon}
                      </span>
                    )}
                    {!collapsed && (
                      <>
                        <span style={{ flex: 1, textAlign: 'left' }}>{item.label}</span>
                        {item.badge !== undefined && (
                          <span
                            style={{
                              background: typeof item.badge === 'string' ? colors.magenta : colors.blue,
                              color: '#FFFFFF',
                              fontSize: '10px',
                              fontWeight: fontWeight.medium,
                              padding: '1px 6px',
                              borderRadius: 0,
                              minWidth: '18px',
                              textAlign: 'center',
                            }}
                          >
                            {item.badge}
                          </span>
                        )}
                        {hasChildren && (
                          <span
                            style={{
                              fontSize: '10px',
                              color: colors.gray.mid,
                              transition: `transform ${transitions.fast}`,
                              transform: isExpanded ? 'rotate(90deg)' : 'rotate(0deg)',
                            }}
                          >
                            ▸
                          </span>
                        )}
                      </>
                    )}
                  </button>

                  {hasChildren && isExpanded && !collapsed && (
                    <div>
                      {item.children!.map((child) => {
                        const childActive = child.key === active;
                        return (
                          <button
                            key={child.key}
                            onClick={() => !child.disabled && onNavigate(child.key)}
                            style={{
                              width: '100%',
                              background: childActive ? 'rgba(30, 144, 255, 0.15)' : 'transparent',
                              border: 'none',
                              borderRadius: 0,
                              padding: `6px ${spacing.md} 6px 44px`,
                              display: 'flex',
                              alignItems: 'center',
                              gap: spacing.sm,
                              cursor: child.disabled ? 'not-allowed' : 'pointer',
                              color: childActive ? '#F0F4F8' : 'rgba(255,255,255,0.5)',
                              fontFamily,
                              fontWeight: childActive ? fontWeight.medium : fontWeight.regular,
                              fontSize: '12px',
                              transition: `all ${transitions.fast}`,
                            }}
                            onMouseEnter={(e) => {
                              if (!childActive)
                                (e.currentTarget as HTMLElement).style.background = 'rgba(255,255,255,0.04)';
                            }}
                            onMouseLeave={(e) => {
                              if (!childActive)
                                (e.currentTarget as HTMLElement).style.background = 'transparent';
                            }}
                          >
                            {child.icon && <span style={{ width: '16px', fontSize: '14px' }}>{child.icon}</span>}
                            <span style={{ flex: 1 }}>{child.label}</span>
                            {child.badge !== undefined && (
                              <span style={{ fontSize: '10px', color: colors.gray.mid }}>{child.badge}</span>
                            )}
                          </button>
                        );
                      })}
                    </div>
                  )}
                </React.Fragment>
              );
            })}
          </div>
        ))}
      </div>

      {footer && (
        <div
          style={{
            padding: collapsed ? spacing.sm : spacing.md,
            borderTop: '1px solid rgba(255,255,255,0.06)',
            flexShrink: 0,
          }}
        >
          {footer}
        </div>
      )}
    </nav>
  );
};

Sidebar.displayName = 'Sidebar';

interface AppShellProps {
  children: React.ReactNode;
  style?: React.CSSProperties;
}

export const AppShell: React.FC<AppShellProps> = ({ children, style }) => (
  <div
    style={{
      display: 'flex',
      height: '100vh',
      background: colors.bg.dark,
      overflow: 'hidden',
      ...style,
    }}
  >
    {children}
  </div>
);

AppShell.displayName = 'AppShell';
