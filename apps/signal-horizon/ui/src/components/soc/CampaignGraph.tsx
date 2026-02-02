import { useEffect, useRef, useState, useCallback } from 'react';
import cytoscape from 'cytoscape';
// @ts-expect-error - fcose has no type declarations
import fcose from 'cytoscape-fcose';
import { useDemoMode } from '../../stores/demoModeStore';
import { getDemoData } from '../../lib/demoData';

cytoscape.use(fcose);

interface CampaignGraphProps {
  campaignId?: string;
  sensorId?: string;
}

const API_BASE = import.meta.env.VITE_API_URL || '';
const API_KEY = import.meta.env.VITE_API_KEY || 'demo-key';

const authHeaders = {
  Authorization: `Bearer ${API_KEY}`,
  'Content-Type': 'application/json',
  'X-Admin-Key': API_KEY, // P0: Added for sensor:read scope authentication
};

async function fetchGraphData(sensorId: string, campaignId: string) {
  const response = await fetch(`${API_BASE}/api/v1/synapse/${sensorId}/campaigns/${campaignId}/graph`, { headers: authHeaders });
  if (!response.ok) throw new Error('Failed to fetch graph data');
  const result = await response.json();
  return result.data;
}

interface NodeDetails {
  id: string;
  label: string;
  type: string;
  x: number;
  y: number;
  details?: Record<string, string | number>;
}

// Professional color palette
const colors = {
  campaign: { bg: '#dc2626', border: '#fca5a5' },
  actor: { bg: '#ea580c', border: '#fdba74' },
  ip: { bg: '#0ea5e9', border: '#7dd3fc' },
  sensor: { bg: '#22c55e', border: '#86efac' },
  token: { bg: '#8b5cf6', border: '#c084fc' },
  asn: { bg: '#6366f1', border: '#a5b4fc' },
  edge: {
    attributed: '#ef4444',
    linked: '#f97316',
    uses: '#8b5cf6',
    attacked: '#ef4444',
    default: '#475569',
  },
};

export function CampaignGraph({ campaignId, sensorId }: CampaignGraphProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);
  const [hoveredNode, setHoveredNode] = useState<NodeDetails | null>(null);
  const [isLayoutComplete, setIsLayoutComplete] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { isEnabled: isDemoMode, scenario } = useDemoMode();

  const handleNodeHover = useCallback((node: NodeDetails | null) => {
    setHoveredNode(node);
  }, []);

  useEffect(() => {
    if (!containerRef.current || !campaignId) return;

    let cy: cytoscape.Core | null = null;
    let animationFrame: number | undefined;

    const loadAndInit = async () => {
      try {
        let graphData;
        if (isDemoMode) {
          const demoData = getDemoData(scenario);
          // Try to get graph for specific campaign, or default to camp-001
          graphData = demoData.fleet.campaignGraphs[campaignId] || demoData.fleet.campaignGraphs['camp-001'];
        } else {
          const targetSensorId = sensorId || 'synapse-pingora';
          graphData = await fetchGraphData(targetSensorId, campaignId);
        }

        if (!containerRef.current || !graphData) return;

        cy = cytoscape({
          container: containerRef.current,
          boxSelectionEnabled: false,
          autounselectify: false,

          style: [
            {
              selector: 'node',
              style: {
                'shape': 'ellipse',
                'width': 30,
                'height': 30,
                'background-color': '#64748b',
                'background-opacity': 1,
                'border-width': 2,
                'border-color': '#94a3b8',
                'label': 'data(label)',
                'text-valign': 'bottom',
                'text-halign': 'center',
                'text-margin-y': 6,
                'font-size': '10px',
                'font-family': '"JetBrains Mono", monospace',
                'color': '#cbd5e1',
                'text-background-color': '#0f172a',
                'text-background-opacity': 0.85,
                'text-background-padding': '3px',
                'text-background-shape': 'roundrectangle',
              }
            },
            {
              selector: 'node[type="campaign"]',
              style: {
                'shape': 'diamond',
                'width': 56,
                'height': 56,
                'background-color': colors.campaign.bg,
                'border-color': colors.campaign.border,
                'border-width': 3,
                'z-index': 100,
              }
            },
            {
              selector: 'node[type="actor"]',
              style: {
                'shape': 'round-hexagon',
                'width': 44,
                'height': 44,
                'background-color': colors.actor.bg,
                'border-color': colors.actor.border,
                'z-index': 80,
              }
            },
            {
              selector: 'node[type="ip"]',
              style: {
                'shape': 'ellipse',
                'width': 32,
                'height': 32,
                'background-color': colors.ip.bg,
                'border-color': colors.ip.border,
                'z-index': 60,
              }
            },
            {
              selector: 'node[type="token"]',
              style: {
                'shape': 'tag',
                'width': 36,
                'height': 36,
                'background-color': colors.token.bg,
                'border-color': colors.token.border,
                'z-index': 70,
              }
            },
            {
              selector: 'node[type="asn"]',
              style: {
                'shape': 'round-rectangle',
                'width': 40,
                'height': 40,
                'background-color': colors.asn.bg,
                'border-color': colors.asn.border,
                'z-index': 50,
              }
            },
            { selector: 'node.hover', style: { 'border-width': 4, 'z-index': 150 } },
            { selector: 'node:selected', style: { 'border-width': 4 } },
            { selector: 'node.dimmed', style: { 'opacity': 0.15 } },
            {
              selector: 'edge',
              style: {
                'width': 2,
                'line-color': colors.edge.default,
                'line-opacity': 0.6,
                'curve-style': 'bezier',
                'target-arrow-shape': 'triangle',
                'target-arrow-color': colors.edge.default,
              }
            },
            { selector: 'edge.highlighted', style: { 'width': 4, 'line-opacity': 1, 'z-index': 100 } },
            { selector: 'edge.dimmed', style: { 'line-opacity': 0.06 } },
          ],
          wheelSensitivity: 0.25,
          minZoom: 0.4,
          maxZoom: 3,
        });

        cyRef.current = cy;

        cy.batch(() => {
          cy!.add(graphData.nodes);
          cy!.add(graphData.edges);
          if (cy!.$('#campaign').length === 0) {
            cy!.add({ data: { id: 'campaign', label: 'Campaign Hub', type: 'campaign' } });
            cy!.nodes('[type="ip"]').forEach(node => {
              cy!.add({ data: { id: `e_hub_${node.id()}`, source: 'campaign', target: node.id(), label: 'attributed' } });
            });
          }
        });

        const layout = cy.layout({
          name: 'fcose',
          animate: true,
          animationDuration: 1000,
          fit: true,
          padding: 50,
          randomize: true,
          nodeRepulsion: () => 5500,
          idealEdgeLength: () => 110,
        } as any);

        layout.run();

        layout.on('layoutstop', () => {
          setIsLayoutComplete(true);
          const cyInstance = cyRef.current;
          if (!cyInstance) return;
          const campaignNode = cyInstance.$('#campaign');
          if (campaignNode.length) {
            cyInstance.animate({ center: { eles: campaignNode } }, { duration: 300 });
          }
        });

        cy.on('mouseover', 'node', (e) => {
          const node = e.target;
          const pos = node.renderedPosition();
          const cyInstance = cyRef.current;
          if (!cyInstance) return;
          const neighborhood = node.closedNeighborhood();
          cyInstance.batch(() => {
            cyInstance.elements().addClass('dimmed');
            neighborhood.removeClass('dimmed');
            node.addClass('hover');
            node.connectedEdges().addClass('highlighted');
          });
          handleNodeHover({
            id: node.id(),
            label: node.data('label'),
            type: node.data('type'),
            x: pos.x,
            y: pos.y,
            details: node.data('details') || {},
          });
        });

        cy.on('mouseout', 'node', () => {
          const cyInstance = cyRef.current;
          if (!cyInstance) return;
          cyInstance.batch(() => {
            cyInstance.elements().removeClass('dimmed hover highlighted');
          });
          handleNodeHover(null);
        });

        cy.on('tap', 'node', (e) => {
          const node = e.target;
          const cyInstance = cyRef.current;
          if (!cyInstance) return;
          cyInstance.animate({ center: { eles: node }, zoom: Math.min(cyInstance.zoom() * 1.5, 2.5) }, { duration: 400 });
        });

      } catch (err: any) {
        console.error('Failed to load graph data:', err);
        setError(err.message);
        setIsLayoutComplete(true);
      }
    };

    loadAndInit();

    return () => {
      if (animationFrame) cancelAnimationFrame(animationFrame);
      if (cy) {
        cy.destroy();
        cyRef.current = null;
      }
    };
  }, [campaignId, sensorId, handleNodeHover]);

  useEffect(() => {
    if (!containerRef.current || !cyRef.current) return;
    const resizeObserver = new ResizeObserver(() => {
      const cyInstance = cyRef.current;
      if (cyInstance) {
        cyInstance.resize();
        cyInstance.fit(undefined, 50);
      }
    });
    resizeObserver.observe(containerRef.current);
    return () => resizeObserver.disconnect();
  }, []);

  if (error) {
    return (
      <div className="w-full h-[480px] border border-border-subtle bg-surface-base rounded flex items-center justify-center text-status-error p-6 text-center">
        <div>
          <p className="font-semibold mb-2">Failed to load correlation graph</p>
          <p className="text-sm opacity-80">{error}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="w-full border border-border-subtle bg-surface-base rounded overflow-hidden relative">
      <div className="absolute top-3 left-3 z-10 pointer-events-none">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-ink-muted">Graph Correlation (Real-time)</h3>
        <p className="text-[10px] text-ink-muted/50 mt-0.5">Connecting actors via shared attributes (IP, JA4, JWT)</p>
      </div>

      {!isLayoutComplete && (
        <div className="absolute inset-0 flex items-center justify-center z-20 bg-surface-base/95 backdrop-blur-sm">
          <div className="flex items-center gap-3 text-ink-muted">
            <div className="w-5 h-5 border-2 border-ink-muted/20 border-t-ink-muted rounded-full animate-spin" />
            <span className="text-sm font-medium">Analyzing correlations...</span>
          </div>
        </div>
      )}

      <div
        ref={containerRef}
        className="w-full cursor-grab active:cursor-grabbing"
        style={{
          height: '480px',
          background: 'linear-gradient(180deg, #0a0a0e 0%, #0d0d14 100%)',
        }}
      />

      {hoveredNode && (
        <div
          className="absolute z-30 pointer-events-none"
          style={{
            left: Math.min(hoveredNode.x + 16, (containerRef.current?.clientWidth || 400) - 200),
            top: Math.max(hoveredNode.y - 70, 8),
          }}
        >
          <div className="bg-surface-elevated/95 backdrop-blur border border-border-subtle rounded-lg shadow-xl px-3 py-2.5 min-w-[140px]">
            <div className="text-sm font-medium text-ink-primary">{hoveredNode.label}</div>
            <div className="text-[10px] text-ink-muted uppercase tracking-wide mt-0.5">{hoveredNode.type}</div>
            {hoveredNode.details && Object.keys(hoveredNode.details).length > 0 && (
              <div className="mt-2 pt-2 border-t border-border-subtle space-y-1">
                {Object.entries(hoveredNode.details).map(([key, value]) => (
                  <div key={key} className="flex justify-between gap-4 text-[11px]">
                    <span className="text-ink-muted">{key}</span>
                    <span className="text-ink-primary font-medium tabular-nums">{value}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      <div className="absolute bottom-3 right-3 p-2.5 bg-surface-base/90 backdrop-blur border border-border-subtle rounded text-[10px] z-10">
        <div className="grid grid-cols-2 gap-x-4 gap-y-1.5">
          <div className="flex items-center gap-1.5">
            <div className="w-3 h-3 rounded-sm rotate-45" style={{ background: colors.campaign.bg }} />
            <span className="text-ink-secondary">Campaign</span>
          </div>
          <div className="flex items-center gap-1.5">
            <div className="w-3 h-3" style={{ background: colors.actor.bg, clipPath: 'polygon(50% 0%, 100% 25%, 100% 75%, 50% 100%, 0% 75%, 0% 25%)' }} />
            <span className="text-ink-secondary">Fingerprint</span>
          </div>
          <div className="flex items-center gap-1.5">
            <div className="w-2.5 h-2.5 rounded-full" style={{ background: colors.ip.bg }} />
            <span className="text-ink-secondary">IP Source</span>
          </div>
          <div className="flex items-center gap-1.5">
            <div className="w-2.5 h-2.5 rounded-sm" style={{ background: colors.token.bg }} />
            <span className="text-ink-secondary">Auth Token</span>
          </div>
        </div>
      </div>
    </div>
  );
}