import { ResponsiveContainer, Treemap, Tooltip } from 'recharts';
import type { InventoryService } from '../../hooks/useApiIntelligence';
import { Panel, SectionHeader, CARD_HEADER_TITLE_STYLE, colors, fontFamily } from '@/ui';

const DEMO_TREEMAP_DATA = [
  {
    name: 'Auth Service',
    children: [
      { name: '/login', size: 1200, risk: 80 },
      { name: '/register', size: 800, risk: 60 },
      { name: '/oauth/token', size: 450, risk: 90 },
      { name: '/forgot-password', size: 200, risk: 40 },
    ],
  },
  {
    name: 'User Service',
    children: [
      { name: '/users', size: 2500, risk: 30 },
      { name: '/users/:id', size: 3100, risk: 50 },
      { name: '/users/:id/profile', size: 1200, risk: 20 },
    ],
  },
  {
    name: 'Payment Service',
    children: [
      { name: '/payments', size: 800, risk: 95 },
      { name: '/cards', size: 400, risk: 98 },
      { name: '/transactions', size: 1500, risk: 70 },
    ],
  },
  {
    name: 'Inventory',
    children: [
      { name: '/products', size: 5000, risk: 10 },
      { name: '/categories', size: 1200, risk: 5 },
      { name: '/search', size: 3400, risk: 15 },
    ],
  },
];

// Atlas Crew Brand chart series colors (priority order per chart standards)
const COLORS = [
  colors.blue,
  colors.skyBlue,
  colors.green,
  colors.orange,
  colors.magenta,
  colors.blue,
];

// Simple rect-only content
const CustomizedContent = (props: any) => {
  const { depth, x, y, width, height, index } = props;

  return (
    <g>
      <rect
        x={x}
        y={y}
        width={width}
        height={height}
        fill={depth < 2 ? COLORS[index % COLORS.length] : 'none'}
        stroke={colors.navy}
        strokeWidth={1}
      />
    </g>
  );
};

interface ApiTreemapProps {
  services?: InventoryService[];
}

export function ApiTreemap({ services }: ApiTreemapProps) {
  const hasServiceData = Array.isArray(services);
  const treemapData = hasServiceData
    ? services.map((service) => ({
        name: service.service,
        children: service.endpoints.map((endpoint) => ({
          name: endpoint.pathTemplate || endpoint.path,
          size: Math.max(endpoint.requestCount, 1),
          risk: endpoint.riskScore,
          method: endpoint.method,
        })),
      }))
    : DEMO_TREEMAP_DATA;

  return (
    <Panel tone="default" className="h-[400px]">
      <Panel.Header>
        <SectionHeader
          title="API Surface Area"
          description="Size = Request Volume"
          size="h4"
          style={{ marginBottom: 0 }}
          titleStyle={CARD_HEADER_TITLE_STYLE}
        />
      </Panel.Header>
      <Panel.Body className="flex-1 min-h-0">
        {treemapData.length > 0 ? (
          <ResponsiveContainer width="100%" height="100%">
            <Treemap
              data={treemapData}
              dataKey="size"
              stroke={colors.navy}
              fill={colors.blue}
              content={<CustomizedContent />}
            >
              <Tooltip
                content={({ active, payload }) => {
                  if (active && payload && payload.length) {
                    const data = payload[0].payload;
                    return (
                      <div className="bg-surface-hero border border-border-subtle p-3 shadow-lg text-xs" style={{ fontFamily }}>
                        <p className="font-medium text-ink-primary">{data.name}</p>
                        {data.method && (
                          <p className="text-ink-secondary">Method: {data.method}</p>
                        )}
                        <p className="text-ink-secondary">Volume: {data.size?.toLocaleString()}</p>
                        {data.risk !== undefined && (
                          <p className={data.risk > 70 ? 'text-ac-magenta' : 'text-ac-blue'}>
                            Risk: {data.risk}/100
                          </p>
                        )}
                      </div>
                    );
                  }
                  return null;
                }}
              />
            </Treemap>
          </ResponsiveContainer>
        ) : (
          <div className="h-full flex items-center justify-center text-sm text-ink-muted">
            No API inventory data available yet.
          </div>
        )}
      </Panel.Body>
      {/* Legend — square markers per brand. Rendered outside Panel.Body
          so it sits flush to the bottom of the Panel without inheriting
          the Body's padding. */}
      {treemapData.length > 0 && (
        <div className="px-4 pb-4 flex flex-wrap gap-4">
          {treemapData.map((service, i) => (
            <div key={service.name} className="flex items-center gap-2">
              <div
                className="w-3 h-3"
                style={{ backgroundColor: COLORS[i % COLORS.length] }}
              />
              <span className="text-xs text-ink-secondary" style={{ fontFamily }}>{service.name}</span>
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}
