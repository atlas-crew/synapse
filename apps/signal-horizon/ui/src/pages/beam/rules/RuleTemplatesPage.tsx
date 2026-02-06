/**
 * Rule Templates Page
 * Pre-built protection templates that can be customized and deployed
 */

import { useState } from 'react';
import { motion } from 'framer-motion';
import {
  Shield,
  ShieldPlus,
  Search,
  Filter,
  Lock,
  Database,
  Code,
  Bot,
  Zap,
  Globe,
  CheckCircle,
} from 'lucide-react';
import { clsx } from 'clsx';
import { CardSkeleton } from '../../../components/LoadingStates';

type TemplateCategory = 'injection' | 'authentication' | 'bot' | 'data' | 'rate-limiting' | 'protocol';

// Demo data - rule templates
const DEMO_TEMPLATES = [
  {
    id: '1',
    name: 'SQL Injection Protection',
    description: 'Comprehensive SQL injection detection with pattern matching for common attack vectors',
    category: 'injection' as TemplateCategory,
    severity: 'critical',
    popularity: 98,
    deployments: 1250,
    patterns: ['UNION SELECT', 'OR 1=1', "' OR '", 'DROP TABLE', 'INSERT INTO'],
    isDeployed: true,
  },
  {
    id: '2',
    name: 'XSS Attack Prevention',
    description: 'Blocks cross-site scripting attempts including reflected and stored XSS',
    category: 'injection' as TemplateCategory,
    severity: 'high',
    popularity: 95,
    deployments: 1180,
    patterns: ['<script>', 'javascript:', 'onerror=', 'onclick=', '<img src='],
    isDeployed: true,
  },
  {
    id: '3',
    name: 'Brute Force Protection',
    description: 'Rate limits authentication endpoints to prevent credential guessing',
    category: 'authentication' as TemplateCategory,
    severity: 'high',
    popularity: 92,
    deployments: 980,
    patterns: ['5 attempts/minute', 'IP blocking', 'account lockout'],
    isDeployed: false,
  },
  {
    id: '4',
    name: 'Bot Detection - Credential Stuffing',
    description: 'Identifies automated login attempts using stolen credentials',
    category: 'bot' as TemplateCategory,
    severity: 'critical',
    popularity: 88,
    deployments: 750,
    patterns: ['fingerprint analysis', 'behavioral detection', 'velocity checks'],
    isDeployed: false,
  },
  {
    id: '5',
    name: 'API Key Exposure Prevention',
    description: 'Monitors responses for accidental API key or secret exposure',
    category: 'data' as TemplateCategory,
    severity: 'high',
    popularity: 85,
    deployments: 620,
    patterns: ['api_key=', 'secret=', 'authorization:', 'bearer '],
    isDeployed: false,
  },
  {
    id: '6',
    name: 'Rate Limiting - General',
    description: 'Configurable rate limits for any endpoint',
    category: 'rate-limiting' as TemplateCategory,
    severity: 'medium',
    popularity: 90,
    deployments: 890,
    patterns: ['requests/minute', 'burst limits', 'sliding window'],
    isDeployed: true,
  },
  {
    id: '7',
    name: 'Path Traversal Prevention',
    description: 'Blocks directory traversal attacks in file path parameters',
    category: 'injection' as TemplateCategory,
    severity: 'high',
    popularity: 82,
    deployments: 540,
    patterns: ['../', '..\\', '%2e%2e', 'etc/passwd'],
    isDeployed: false,
  },
  {
    id: '8',
    name: 'HTTP Protocol Validation',
    description: 'Enforces HTTP protocol compliance and blocks malformed requests',
    category: 'protocol' as TemplateCategory,
    severity: 'medium',
    popularity: 78,
    deployments: 420,
    patterns: ['Content-Length validation', 'header injection', 'method tampering'],
    isDeployed: false,
  },
];

const CATEGORY_CONFIG: Record<TemplateCategory, { icon: React.ElementType; color: string; label: string }> = {
  injection: { icon: Code, color: 'text-red-400 bg-red-500/20', label: 'Injection' },
  authentication: { icon: Lock, color: 'text-sky-400 bg-sky-500/20', label: 'Authentication' },
  bot: { icon: Bot, color: 'text-purple-400 bg-purple-500/20', label: 'Bot Protection' },
  data: { icon: Database, color: 'text-blue-400 bg-blue-500/20', label: 'Data Protection' },
  'rate-limiting': { icon: Zap, color: 'text-orange-400 bg-orange-500/20', label: 'Rate Limiting' },
  protocol: { icon: Globe, color: 'text-green-400 bg-green-500/20', label: 'Protocol' },
};

// Template Card Component
function TemplateCard({
  template,
  onDeploy,
}: {
  template: typeof DEMO_TEMPLATES[0];
  onDeploy: () => void;
}) {
  const categoryConfig = CATEGORY_CONFIG[template.category];
  const CategoryIcon = categoryConfig.icon;

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="bg-surface-card border border-border-subtle p-5 hover:border-border-subtle transition-colors"
    >
      <div className="flex items-start justify-between">
        <div className={clsx('p-2', categoryConfig.color)}>
          <CategoryIcon className="w-5 h-5" />
        </div>
        {template.isDeployed && (
          <span className="flex items-center gap-1 text-green-400 text-xs">
            <CheckCircle className="w-3 h-3" />
            Deployed
          </span>
        )}
      </div>

      <h3 className="text-ink-primary font-medium mt-4">{template.name}</h3>
      <p className="text-sm text-ink-secondary mt-2 line-clamp-2">{template.description}</p>

      <div className="mt-4 flex flex-wrap gap-2">
        {template.patterns.slice(0, 3).map((pattern, idx) => (
          <span
            key={idx}
            className="px-2 py-0.5 bg-surface-subtle text-xs text-ink-secondary"
          >
            {pattern}
          </span>
        ))}
        {template.patterns.length > 3 && (
          <span className="px-2 py-0.5 bg-surface-subtle text-xs text-ink-muted">
            +{template.patterns.length - 3} more
          </span>
        )}
      </div>

      <div className="mt-4 flex items-center justify-between pt-4 border-t border-border-subtle">
        <div className="flex items-center gap-4 text-sm text-ink-secondary">
          <span>{template.deployments.toLocaleString()} deployments</span>
          <span className="flex items-center gap-1">
            <span className="text-sky-400">{template.popularity}%</span> popular
          </span>
        </div>
        <button
          onClick={onDeploy}
          disabled={template.isDeployed}
          className={clsx(
            'px-3 py-1.5 text-sm font-medium transition-colors flex items-center gap-1',
            template.isDeployed
              ? 'bg-surface-subtle text-ink-muted cursor-not-allowed'
              : 'bg-horizon-600 hover:bg-horizon-500 text-white'
          )}
        >
          <ShieldPlus className="w-4 h-4" />
          {template.isDeployed ? 'Deployed' : 'Deploy'}
        </button>
      </div>
    </motion.div>
  );
}

export default function RuleTemplatesPage() {
  const [search, setSearch] = useState('');
  const [categoryFilter, setCategoryFilter] = useState<string>('');
  const [templates, setTemplates] = useState(DEMO_TEMPLATES);
  const isLoading = false;

  // Filter templates
  const filteredTemplates = templates.filter((t) => {
    if (search && !t.name.toLowerCase().includes(search.toLowerCase())) {
      return false;
    }
    if (categoryFilter && t.category !== categoryFilter) {
      return false;
    }
    return true;
  });

  const handleDeploy = (templateId: string) => {
    setTemplates((prev) =>
      prev.map((t) => (t.id === templateId ? { ...t, isDeployed: true } : t))
    );
  };

  if (isLoading) {
    return (
      <div className="p-6 space-y-6">
        <div>
          <h1 className="text-2xl font-bold text-ink-primary">Rule Templates</h1>
          <p className="text-ink-secondary mt-1">Loading templates...</p>
        </div>
        <CardSkeleton />
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-ink-primary">Rule Templates</h1>
          <p className="text-ink-secondary mt-1">Pre-built protection templates</p>
        </div>
        <div className="flex items-center gap-2 text-sm text-ink-secondary">
          <Shield className="w-4 h-4" />
          <span>{templates.filter((t) => t.isDeployed).length} deployed</span>
        </div>
      </div>

      {/* Search and Filters */}
      <div className="flex items-center gap-4">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-ink-secondary" />
          <input
            type="text"
            placeholder="Search templates..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            aria-label="Search templates"
            className="w-full pl-10 pr-4 py-2 bg-surface-card border border-border-subtle text-ink-primary placeholder-ink-muted focus:outline-none focus:ring-2 focus:ring-horizon-500 focus:border-transparent"
          />
        </div>
        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-ink-secondary" />
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="px-3 py-2 bg-surface-card border border-border-subtle text-ink-primary focus:outline-none focus:ring-2 focus:ring-horizon-500"
          >
            <option value="">All Categories</option>
            {Object.entries(CATEGORY_CONFIG).map(([key, config]) => (
              <option key={key} value={key}>
                {config.label}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Templates Grid */}
      <div className="grid grid-cols-3 gap-4">
        {filteredTemplates.map((template) => (
          <TemplateCard
            key={template.id}
            template={template}
            onDeploy={() => handleDeploy(template.id)}
          />
        ))}
      </div>

      {filteredTemplates.length === 0 && (
        <div className="bg-surface-card border border-border-subtle p-8 text-center">
          <p className="text-ink-secondary">No templates match your search</p>
        </div>
      )}
    </div>
  );
}
