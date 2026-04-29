import { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
	import {
	  Search,
	  LayoutDashboard,
	  Globe,
	  Target,
	  UserPlus,
	  Activity,
	  Server,
	  Package,
	  Settings,
	  HelpCircle,
	  BookOpen,
	  Command as CommandIcon,
  ArrowRight,
  Sun,
  Moon,
  RefreshCw,
  PanelLeft,
  Search as SearchIcon,
  Cpu,
  History,
  Code,
  ShieldAlert,
  ShieldCheck,
  RotateCw,
  MoveRight,
	  Zap,
	  BarChart3,
	} from 'lucide-react';
import { clsx } from 'clsx';
import { useSocSensor } from '../../hooks/soc/useSocSensor';
import { useDemoMode } from '../../stores/demoModeStore';
import { useCommandStore } from '../../stores/commandStore';
import { useHorizonStore } from '../../stores/horizonStore';
import { usePlaybooks } from '../../hooks/fleet/usePlaybooks';
import { fetchFleetActors, fetchSessions } from '../../hooks/soc/api';
import { apiFetch } from '../../lib/api';
import { useToast } from './Toast';
import type { SocActor, SocSession } from '../../types/soc';
import { colors, Spinner, Stack } from '@/ui';

interface CommandItem {
  id: string;
  label: string;
  category: 'Navigation' | 'Actions' | 'Quick Search' | 'Recent' | 'Command' | 'Page Actions' | 'Smart Answer' | 'Playbook';
  icon: React.ElementType;
  shortcut?: string;
  onSelect: () => void;
  metadata?: string;
  renderAnswer?: () => React.ReactNode;
}

interface RecentItem {
  id: string;
  label: string;
  path: string;
  type: 'actor' | 'session' | 'sensor' | 'endpoint' | 'page' | 'playbook';
  timestamp: number;
}

const RECENT_ITEMS_KEY = 'signal-horizon:recent-commands';

const COMMAND_VERBS = {
  block: { icon: ShieldAlert, color: 'text-ac-red', label: 'Block' },
  unblock: { icon: ShieldCheck, color: 'text-ac-green', label: 'Unblock' },
  reboot: { icon: RotateCw, color: 'text-ac-orange', label: 'Reboot' },
  reset: { icon: RefreshCw, color: 'text-ac-blue', label: 'Reset' },
  goto: { icon: MoveRight, color: 'text-ac-sky-blue', label: 'Go to' },
  run: { icon: Zap, color: 'text-ac-blue-tint', label: 'Run' },
};

interface CommandPaletteProps {
  isOpen: boolean;
  onClose: () => void;
  theme: 'light' | 'dark';
  setTheme: (theme: 'light' | 'dark') => void;
  toggleSidebar: () => void;
}

export function CommandPalette({
  isOpen,
  onClose,
  theme,
  setTheme,
  toggleSidebar,
}: CommandPaletteProps) {
  const [query, setQuery] = useState('');
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [isSearching, setIsSearching] = useState(false);
  const [searchResults, setSearchResults] = useState<CommandItem[]>([]);
  const [recentItems, setRecentItems] = useState<RecentItem[]>([]);
  const navigate = useNavigate();
  const { toast } = useToast();
  const inputRef = useRef<HTMLInputElement>(null);
  const { sensorId } = useSocSensor();
  const { isEnabled: isDemoMode } = useDemoMode();
  const contextualCommands = useCommandStore((s) => s.contextualCommands);
  const horizonStats = useHorizonStore((s) => s.stats);
  const activeCampaignsCount = useHorizonStore((s) => s.campaigns.filter(c => c.status === 'ACTIVE').length);
  const { playbooks } = usePlaybooks();

  // Load recent items
  useEffect(() => {
    if (isOpen) {
      const stored = localStorage.getItem(RECENT_ITEMS_KEY);
      if (stored) {
        try {
          setRecentItems(JSON.parse(stored));
        } catch (e) {
          console.error('Failed to parse recent items', e);
        }
      }
    }
  }, [isOpen]);

  const addToRecent = useCallback((item: Omit<RecentItem, 'timestamp'>) => {
    const newItem = { ...item, timestamp: Date.now() };
    setRecentItems(prev => {
      const filtered = prev.filter(i => i.id !== item.id);
      const updated = [newItem, ...filtered].slice(0, 5);
      localStorage.setItem(RECENT_ITEMS_KEY, JSON.stringify(updated));
      return updated;
    });
  }, []);

  const navigationItems: CommandItem[] = [
    { id: 'nav-overview', label: 'Threat Overview', category: 'Navigation', icon: LayoutDashboard, onSelect: () => navigate('/') },
    { id: 'nav-map', label: 'Live Threat Map', category: 'Navigation', icon: Globe, onSelect: () => navigate('/live-map') },
    { id: 'nav-campaigns', label: 'Campaigns', category: 'Navigation', icon: Target, onSelect: () => navigate('/campaigns') },
    { id: 'nav-actors', label: 'Actors', category: 'Navigation', icon: UserPlus, onSelect: () => navigate('/actors') },
    { id: 'nav-sessions', label: 'Sessions', category: 'Navigation', icon: Activity, onSelect: () => navigate('/sessions') },
    { id: 'nav-hunting', label: 'Threat Hunting', category: 'Navigation', icon: SearchIcon, onSelect: () => navigate('/hunting') },
    { id: 'nav-fleet', label: 'Fleet Overview', category: 'Navigation', icon: Server, onSelect: () => navigate('/fleet') },
    { id: 'nav-intel', label: 'Global Intel', category: 'Navigation', icon: Activity, onSelect: () => navigate('/intel') },
    { id: 'nav-api', label: 'API Intelligence', category: 'Navigation', icon: Package, onSelect: () => navigate('/api-intelligence') },
    { id: 'nav-settings', label: 'Admin Settings', category: 'Navigation', icon: Settings, onSelect: () => navigate('/settings/admin') },
    { id: 'nav-support', label: 'Support & Docs', category: 'Navigation', icon: HelpCircle, onSelect: () => navigate('/support') },
  ];

  const actionItems: CommandItem[] = [
    {
      id: 'action-theme',
      label: `Switch to ${theme === 'dark' ? 'Light' : 'Dark'} Mode`,
      category: 'Actions',
      icon: theme === 'dark' ? Sun : Moon,
      onSelect: () => setTheme(theme === 'dark' ? 'light' : 'dark'),
    },
    {
      id: 'action-sidebar',
      label: 'Toggle Sidebar',
      category: 'Actions',
      shortcut: 'B',
      icon: PanelLeft,
      onSelect: toggleSidebar,
    },
    {
      id: 'action-refresh',
      label: 'Refresh All Data',
      category: 'Actions',
      icon: RefreshCw,
      onSelect: () => window.location.reload(),
    },
  ];

  // Smart Query Logic
  const smartAnswers = useMemo<CommandItem[]>(() => {
    if (!query) return [];
    const q = query.toLowerCase().trim();
    
    if (['status', 'health', 'fleet'].includes(q)) {
      return [{
        id: 'smart-status',
        label: 'Fleet Health Summary',
        category: 'Smart Answer',
        icon: Zap,
        onSelect: () => navigate('/fleet'),
        renderAnswer: () => (
          <div className="p-4 bg-surface-base border border-border-subtle grid grid-cols-3 gap-4">
            <div>
              <div className="text-[10px] text-ink-muted uppercase font-bold">Online</div>
              <div className="text-xl text-ac-green">{horizonStats.sensorsOnline}</div>
            </div>
            <div>
              <div className="text-[10px] text-ink-muted uppercase font-bold">Active</div>
              <div className="text-xl text-ac-blue">{activeCampaignsCount}</div>
            </div>
            <div>
              <div className="text-[10px] text-ink-muted uppercase font-bold">Blocked</div>
              <div className="text-xl text-ac-red">{horizonStats.blockedIndicators}</div>
            </div>
          </div>
        )
      }];
    }
    
    if (['metrics', 'traffic', 'load'].includes(q)) {
      return [{
        id: 'smart-metrics',
        label: 'Traffic Intelligence',
        category: 'Smart Answer',
        icon: BarChart3,
        onSelect: () => navigate('/intel'),
        renderAnswer: () => (
          <div className="p-4 bg-surface-base border border-border-subtle space-y-2">
            <div className="flex justify-between items-center">
              <span className="text-xs text-ink-secondary">Discovery Events</span>
              <span className="text-xs font-mono font-bold text-ac-blue">{horizonStats.apiStats?.discoveryEvents || 0}</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-xs text-ink-secondary">Schema Violations</span>
              <span className="text-xs font-mono font-bold text-ac-orange">{horizonStats.apiStats?.schemaViolations || 0}</span>
            </div>
            <div className="h-1 bg-surface-subtle w-full overflow-hidden">
              <div className="h-full bg-ac-blue w-[75%]" />
            </div>
          </div>
        )
      }];
    }

    return [];
  }, [query, horizonStats, activeCampaignsCount, navigate]);

  // Command Parser Logic
  const commandItems = useMemo<CommandItem[]>(() => {
    if (!query) return [];
    
    const parts = query.trim().split(/\s+/);
    if (parts.length < 1) return [];
    
    const verb = parts[0].toLowerCase() as keyof typeof COMMAND_VERBS;
    const object = parts.slice(1).join(' ');
    
    if (COMMAND_VERBS[verb]) {
      const config = COMMAND_VERBS[verb];
      
      // Special case for 'run' - search playbooks
      if (verb === 'run') {
        const matches = playbooks.filter(p => p.name.toLowerCase().includes(object.toLowerCase()));
        return matches.map(p => ({
          id: `cmd-run-${p.id}`,
          label: `Run Playbook: ${p.name}`,
          category: 'Playbook',
          icon: Zap,
          metadata: p.description || 'Manual automation workflow',
          onSelect: () => {
            addToRecent({ id: p.id, label: `Run: ${p.name}`, path: '/fleet/health', type: 'playbook' });
            toast.success(`Triggered playbook: ${p.name}`);
          }
        }));
      }

      // If object is provided, suggest specific action
      if (object) {
        return [{
          id: `cmd-${verb}-${object}`,
          label: `${config.label} ${object}`,
          category: 'Command',
          icon: config.icon,
          metadata: `Execute ${verb} operation on ${object}`,
          onSelect: () => {
            if (!window.confirm(`Confirm: ${verb} ${object}?`)) return;
            toast.success(`Executing: ${verb} ${object}`);
          }
        }];
      }
      
      // Otherwise suggest based on verb
      return [{
        id: `cmd-prompt-${verb}`,
        label: `${config.label}...`,
        category: 'Command',
        icon: config.icon,
        metadata: `Specify an ID or target to ${verb}`,
        onSelect: () => {
          setQuery(`${verb} `);
          inputRef.current?.focus();
        }
      }];
    }
    
    return [];
  }, [query, toast, playbooks, addToRecent]);

  // API Search Logic
  useEffect(() => {
    if (!query || query.length < 2 || commandItems.length > 0 || smartAnswers.length > 0) {
      setSearchResults([]);
      return;
    }

    const controller = new AbortController();
    const { signal } = controller;

    const timer = setTimeout(async () => {
      setIsSearching(true);
      try {
        const results: CommandItem[] = [];

        if (!isDemoMode) {
          // 1. Search Actors (fleet-deduped per ADR-0002)
          const actorsResp = await fetchFleetActors({ ip: query, limit: 3 });
          if (signal.aborted) return;
          actorsResp.aggregate.forEach((actor: SocActor) => {
            results.push({
              id: `actor-${actor.actorId}`,
              label: `Actor: ${actor.actorId}`,
              category: 'Quick Search',
              icon: UserPlus,
              metadata: `Risk: ${Math.round(actor.riskScore)} · ${actor.ips[0] || 'No IP'}`,
              onSelect: () => {
                addToRecent({ id: actor.actorId, label: `Actor: ${actor.actorId}`, path: `/actors/${actor.actorId}`, type: 'actor' });
                navigate(`/actors/${actor.actorId}`);
              },
            });
          });

          // 2. Search Sessions
          const sessionsResp = await fetchSessions(sensorId, { limit: 10 });
          if (signal.aborted) return;
          const matchedSessions = sessionsResp.sessions.filter(s => s.sessionId.includes(query)).slice(0, 2);
          matchedSessions.forEach((session: SocSession) => {
            results.push({
              id: `session-${session.sessionId}`,
              label: `Session: ${session.sessionId}`,
              category: 'Quick Search',
              icon: Activity,
              metadata: `Requests: ${session.requestCount} · ${session.boundIp}`,
              onSelect: () => {
                addToRecent({ id: session.sessionId, label: `Session: ${session.sessionId}`, path: `/sessions/${session.sessionId}`, type: 'session' });
                navigate(`/sessions/${session.sessionId}`);
              },
            });
          });

          // 3. Search Sensors
          try {
            const sensorsResp = await apiFetch<any>('/fleet/sensors');
            if (signal.aborted) return;
            const sensors = Array.isArray(sensorsResp) ? sensorsResp : sensorsResp.sensors || [];
            const matchedSensors = sensors.filter((s: any) => s.name.toLowerCase().includes(query.toLowerCase())).slice(0, 2);
            matchedSensors.forEach((sensor: any) => {
              results.push({
                id: `sensor-${sensor.id}`,
                label: `Sensor: ${sensor.name}`,
                category: 'Quick Search',
                icon: Server,
                metadata: `${sensor.region} · ${sensor.connectionState || 'ONLINE'}`,
                onSelect: () => {
                  addToRecent({ id: sensor.id, label: `Sensor: ${sensor.name}`, path: `/fleet/sensors/${sensor.id}`, type: 'sensor' });
                  navigate(`/fleet/sensors/${sensor.id}`);
                },
              });
            });
          } catch (e) { console.debug('Sensor search failed:', e); }

          // 4. Search API Endpoints
          try {
            const apiResp = await apiFetch<any>('/api-intelligence/endpoints?limit=50');
            if (signal.aborted) return;
            const endpoints = apiResp.endpoints || [];
            const matchedEndpoints = endpoints.filter((e: any) => e.path.toLowerCase().includes(query.toLowerCase())).slice(0, 2);
            matchedEndpoints.forEach((ep: any) => {
              results.push({
                id: `endpoint-${ep.id}`,
                label: `API: ${ep.method} ${ep.path}`,
                category: 'Quick Search',
                icon: Code,
                metadata: `${ep.service} · Risk: ${ep.riskLevel}`,
                onSelect: () => {
                  addToRecent({ id: ep.id, label: `${ep.method} ${ep.path}`, path: `/api-intelligence`, type: 'endpoint' });
                  navigate(`/api-intelligence`);
                },
              });
            });
          } catch (e) { console.debug('API search failed:', e); }

          // 5. Search Documentation
          try {
            const docsResp = await apiFetch<any[]>(`/docs/search?q=${encodeURIComponent(query)}`);
            if (signal.aborted) return;
            docsResp.forEach((doc: any) => {
              const isHighConfidence = doc.title.toLowerCase().includes(query.toLowerCase());
              results.push({
                id: `doc-${doc.id}`,
                label: `Docs: ${doc.title}`,
                category: isHighConfidence ? 'Smart Answer' : 'Quick Search',
                icon: BookOpen,
                metadata: `${doc.category}${isHighConfidence ? '' : ` · ${doc.snippet.substring(0, 40)}...`}`,
                onSelect: () => {
                  addToRecent({ id: doc.id, label: doc.title, path: `/support/${doc.id}`, type: 'page' });
                  navigate(`/support/${doc.id}`);
                },
                renderAnswer: isHighConfidence ? () => (
                  <div className="mt-2 p-3 bg-ac-blue/5 border-l-2 border-ac-blue rounded-r text-[11px] leading-relaxed text-ink-secondary italic">
                    {doc.snippet}
                  </div>
                ) : undefined
              });
            });
          } catch (e) { console.debug('Docs search failed:', e); }

        } else {
          // Demo mode mock results
          if ('actor'.includes(query.toLowerCase())) {
            results.push({
              id: 'demo-actor',
              label: 'Actor: actor-demo-1',
              category: 'Quick Search',
              icon: UserPlus,
              metadata: 'Risk: 86 · 203.0.113.10',
              onSelect: () => navigate('/actors/actor-demo-1'),
            });
          }
        }

        if (!signal.aborted) {
          setSearchResults(results);
        }
      } catch (err) {
        if (!signal.aborted) {
          console.error('Command Palette Search Error:', err);
        }
      } finally {
        if (!signal.aborted) {
          setIsSearching(false);
        }
      }
    }, 300);

    return () => {
      clearTimeout(timer);
      controller.abort();
    };
  }, [query, sensorId, isDemoMode, navigate, addToRecent, commandItems, smartAnswers.length]);

  const recentCommandItems = useMemo<CommandItem[]>(() => {
    return recentItems.map(item => ({
      id: `recent-${item.id}`,
      label: item.label,
      category: 'Recent',
      icon: item.type === 'actor' ? UserPlus : 
            item.type === 'session' ? Activity :
            item.type === 'sensor' ? Server :
            item.type === 'endpoint' ? Code :
            item.type === 'playbook' ? Zap : History,
      metadata: item.type.toUpperCase(),
      onSelect: () => navigate(item.path),
    }));
  }, [recentItems, navigate]);

	  const filteredItems = useMemo<CommandItem[]>(() => {
	    const pageCommandItems = contextualCommands.map((c) => ({
	      ...c,
	      category: 'Page Actions' as const,
	    })) as CommandItem[];
	    const staticItems = [...navigationItems, ...actionItems];
	    
	    if (!query) {
	      return [...pageCommandItems, ...recentCommandItems, ...staticItems];
    }

    if (smartAnswers.length > 0) {
      return smartAnswers;
    }

    if (commandItems.length > 0) {
      return commandItems;
    }

    const lowerQuery = query.toLowerCase();
    const filteredStatic = staticItems.filter(
      (item) =>
        item.label.toLowerCase().includes(lowerQuery) ||
        item.category.toLowerCase().includes(lowerQuery)
    );

    const filteredPageCommands = pageCommandItems.filter(
      (item) => item.label.toLowerCase().includes(lowerQuery)
    );

    return [...filteredPageCommands, ...searchResults, ...filteredStatic];
	  }, [query, searchResults, recentCommandItems, commandItems, smartAnswers, contextualCommands, theme, navigate, setTheme, toggleSidebar]);

  useEffect(() => {
    setSelectedIndex(0);
  }, [filteredItems.length]);

  useEffect(() => {
    if (isOpen) {
      setTimeout(() => inputRef.current?.focus(), 10);
    } else {
      setQuery('');
    }
  }, [isOpen]);

  const handleKeyDown = useCallback(
    (e: KeyboardEvent) => {
      if (!isOpen) return;

      if (e.key === 'ArrowDown') {
        e.preventDefault();
        setSelectedIndex((prev) => (prev + 1) % filteredItems.length);
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        setSelectedIndex((prev) => (prev - 1 + filteredItems.length) % filteredItems.length);
      } else if (e.key === 'Enter') {
        e.preventDefault();
        const selected = filteredItems[selectedIndex];
        if (selected) {
          selected.onSelect();
          onClose();
        }
      } else if (e.key === 'Escape') {
        onClose();
      }
    },
    [isOpen, filteredItems, selectedIndex, onClose]
  );

  useEffect(() => {
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [handleKeyDown]);

  return (
    <>
      <AnimatePresence>
        {isOpen && (
          <div
            className="z-[100] flex items-start justify-center pt-[15vh] px-4"
            style={{ position: 'fixed', inset: 0 }}
          >
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="bg-black/60 backdrop-blur-sm"
              style={{ position: 'fixed', inset: 0 }}
              onClick={onClose}
            />
            <motion.div
              initial={{ opacity: 0, scale: 0.95, y: -20 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: -20 }}
              className="w-full max-w-2xl bg-surface-card border border-border-strong shadow-2xl relative z-10 overflow-hidden flex flex-col max-h-[70vh] scanlines"
              role="combobox"
              aria-expanded={isOpen}
              aria-haspopup="listbox"
              aria-controls="command-palette-listbox"
            >
              <div className="flex items-center px-4 border-b border-border-subtle bg-surface-subtle/50">
                {isSearching ? (
                  <Spinner size={20} color={colors.blue} />
                ) : (
                  <Search className="w-5 h-5 text-ink-muted" />
                )}
                <input
                  ref={inputRef}
                  type="text"
                  placeholder="Search anything or type a command (block, reboot, run)..."
                  className="w-full h-14 px-4 bg-transparent text-ink-primary focus:outline-none text-lg font-light"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  role="textbox"
                  aria-autocomplete="list"
                  aria-controls="command-palette-listbox"
                  aria-activedescendant={filteredItems[selectedIndex] ? `option-${filteredItems[selectedIndex].id}` : undefined}
                />
                <Stack
                  direction="row"
                  align="center"
                  className="px-2 py-1 border border-border-subtle rounded text-[10px] text-ink-muted uppercase tracking-widest bg-surface-base"
                  style={{ gap: '0.375rem' }}
                >
                  <span>ESC</span>
                </Stack>
              </div>

              <div 
                id="command-palette-listbox"
                className="flex-1 overflow-y-auto p-2 space-y-4"
                role="listbox"
                aria-label="Commands and search results"
              >
                {filteredItems.length === 0 ? (
                  <div className="py-12 text-center" role="option" aria-selected="false">
                    <p className="text-ink-secondary">No results found for "{query}"</p>
                  </div>
                ) : (
                  <div className="space-y-4">
                    {['Smart Answer', 'Page Actions', 'Command', 'Playbook', 'Recent', 'Quick Search', 'Navigation', 'Actions'].map((category) => {
                      const categoryItems = filteredItems.filter((item) => item.category === category);
                      if (categoryItems.length === 0) return null;

                      return (
                        <div key={category} className="space-y-1" role="group" aria-labelledby={`category-${category}`}>
                          <div 
                            id={`category-${category}`}
                            className="px-3 py-2 text-[10px] font-bold uppercase tracking-[0.2em] text-ink-muted flex items-center justify-between"
                          >
                            <Stack direction="row" align="center" gap="sm">
                              {category === 'Recent' && <History className="w-3 h-3 text-ac-sky-blue" />}
                              {category === 'Command' && <CommandIcon className="w-3 h-3 text-ac-magenta" />}
                              {category === 'Page Actions' && <Target className="w-3 h-3 text-ac-blue-tint" />}
                              {category === 'Smart Answer' && <Zap className="w-3 h-3 text-ac-orange animate-pulse" />}
                              {category === 'Playbook' && <Zap className="w-3 h-3 text-ac-blue-tint" />}
                              <span>{category}</span>
                            </Stack>
                            {category === 'Quick Search' && (
                              <Stack direction="row" align="center" gap="xs" className="text-[8px] font-mono text-ink-muted/60">
                                <Cpu className="w-2.5 h-2.5" />
                                <span>{sensorId}</span>
                              </Stack>
                            )}
                          </div>
                          {categoryItems.map((item) => {
                            const itemIndex = filteredItems.indexOf(item);
                            const isSelected = itemIndex === selectedIndex;

                            return (
                              <div key={item.id} className="space-y-1">
                                <button
                                  id={`option-${item.id}`}
                                  role="option"
                                  aria-selected={isSelected}
                                  className={clsx(
                                    'w-full flex items-center justify-between px-3 py-3 text-sm transition-colors group text-left',
                                    isSelected
                                      ? 'bg-ac-navy text-white'
                                      : 'text-ink-secondary hover:bg-surface-subtle hover:text-ink-primary'
                                  )}
                                  onClick={() => {
                                    item.onSelect();
                                    onClose();
                                  }}
                                  onMouseEnter={() => setSelectedIndex(itemIndex)}
                                >
                                  <Stack direction="row" align="center" gap="md" className="min-w-0">
                                    <item.icon className={clsx('w-5 h-5 flex-shrink-0', isSelected ? 'text-ac-sky-blue' : 'text-ink-muted group-hover:text-link')} />
                                    <div className="flex flex-col items-start min-w-0">
                                      <span className="font-light tracking-wide truncate">{item.label}</span>
                                      {item.metadata && (
                                        <span className={clsx('text-[10px] uppercase tracking-wider truncate', isSelected ? 'text-white/60' : 'text-ink-muted')}>
                                          {item.metadata}
                                        </span>
                                      )}
                                    </div>
                                  </Stack>
                                  <Stack direction="row" align="center" gap="sm" className="flex-shrink-0">
                                    {item.shortcut && (
                                      <div className={clsx(
                                        'px-1.5 py-0.5 rounded text-[10px] border',
                                        isSelected ? 'border-white/20 bg-white/10 text-white/80' : 'border-border-subtle bg-surface-base text-ink-muted'
                                      )}>
                                        {item.shortcut}
                                      </div>
                                    )}
                                    {isSelected && <ArrowRight className="w-4 h-4 animate-in slide-in-from-left-2" />}
                                  </Stack>
                                </button>
                                {item.renderAnswer && (
                                  <div className="px-3 pb-2">
                                    {item.renderAnswer()}
                                  </div>
                                )}
                              </div>
                            );
                          })}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>

              <div className="p-4 border-t border-border-subtle bg-surface-subtle/50 flex items-center justify-between text-[10px] uppercase tracking-widest text-ink-muted">
                <Stack direction="row" align="center" gap="md">
                  <Stack direction="row" align="center" style={{ gap: '0.375rem' }}>
                    <div className="p-1 border border-border-subtle bg-surface-base rounded">
                      <ArrowRight className="w-3 h-3 rotate-90" />
                    </div>
                    <span>Select</span>
                  </Stack>
                  <Stack direction="row" align="center" style={{ gap: '0.375rem' }}>
                    <div className="px-1.5 py-0.5 border border-border-subtle bg-surface-base rounded">
                      ENTER
                    </div>
                    <span>Confirm</span>
                  </Stack>
                </Stack>
                <Stack direction="row" align="center" style={{ gap: '0.375rem' }}>
                  <CommandIcon className="w-3 h-3" />
                  <span>Tactical Hub</span>
                </Stack>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </>
  );
}
