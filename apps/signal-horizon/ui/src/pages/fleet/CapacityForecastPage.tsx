import { useMemo, useState } from 'react';
import {
  ComposedChart,
  Line,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  ReferenceLine,
  Legend,
} from 'recharts';
import { 
  TrendingUp, 
  TrendingDown, 
  AlertTriangle, 
  Calendar,
  Server
} from 'lucide-react';
import { clsx } from 'clsx';
import { linearRegression, predict, daysUntilThreshold } from '../../utils/math';
import { axisDefaults, colors, gridDefaultsSoft, legendDefaults, tooltipDefaults } from '@/ui';

// =============================================================================
// Mock Data Generation
// =============================================================================

const REGIONS = ['US-East', 'EU-West', 'AP-South'];
const HISTORY_DAYS = 30;
const FORECAST_DAYS = 14;
const xAxisNoLine = { ...axisDefaults.x, axisLine: false };

interface DailyMetric {
  day: number;
  date: string;
  usage: number; // 0-100%
}

// Generate realistic looking trend data with noise
function generateRegionData(baseLoad: number, growthRate: number): DailyMetric[] {
  const data: DailyMetric[] = [];
  const now = new Date();
  
  for (let i = HISTORY_DAYS; i >= 0; i--) {
    const date = new Date(now);
    date.setDate(date.getDate() - i);
    
    // Linear trend + Random Noise + Weekly Seasonality (sine wave)
    const trend = baseLoad + (growthRate * (HISTORY_DAYS - i));
    const noise = (Math.random() - 0.5) * 5;
    const seasonality = Math.sin((i / 7) * Math.PI * 2) * 3;
    
    data.push({
      day: -i, // -30 to 0
      date: date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }),
      usage: Math.max(0, Math.min(100, trend + noise + seasonality)),
    });
  }
  return data;
}

export default function CapacityForecastPage() {
  const [selectedRegion, setSelectedRegion] = useState(REGIONS[0]);

  // Generate data per region
  const regionData = useMemo(() => ({
    'US-East': generateRegionData(45, 0.8), // Fast growth
    'EU-West': generateRegionData(60, 0.1), // Stable
    'AP-South': generateRegionData(30, 1.2), // Very fast growth
  }), []);

  // Calculate Forecast
  const { combinedData, forecastStats } = useMemo(() => {
    const currentHistory = regionData[selectedRegion as keyof typeof regionData];
    
    // Prepare points for regression (x=day index, y=usage)
    const points = currentHistory.map((d, i) => ({ x: i, y: d.usage }));
    const { slope, intercept } = linearRegression(points);
    
    const lastDayIndex = points.length - 1;
    const currentUsage = currentHistory[lastDayIndex].usage;
    
    // Generate Forecast Points
    const forecastPoints = [];
    const now = new Date();
    
    for (let i = 1; i <= FORECAST_DAYS; i++) {
      const date = new Date(now);
      date.setDate(date.getDate() + i);
      
      // Project using the linear model (x extends beyond history)
      const projectedX = lastDayIndex + i;
      const predictedUsage = predict(projectedX, slope, intercept);
      
      forecastPoints.push({
        day: i,
        date: date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }),
        forecast: Math.max(0, Math.min(100, predictedUsage)),
        // Confidence interval (simple widening cone)
        ciHigh: Math.min(100, predictedUsage + (i * 0.5)), 
        ciLow: Math.max(0, predictedUsage - (i * 0.5)),
      });
    }

    // Days until 100% capacity
    // Slope represents usage increase per day index (approx per day)
    const daysToSaturation = daysUntilThreshold(currentUsage, 100, slope);
    const daysToWarning = daysUntilThreshold(currentUsage, 80, slope);

    return {
      combinedData: [
        ...currentHistory.map(d => ({ ...d, forecast: null, ciHigh: null, ciLow: null })),
        ...forecastPoints.map(d => ({ ...d, usage: null })),
      ],
      forecastStats: {
        slope,
        currentUsage,
        daysToSaturation,
        daysToWarning,
        trendDirection: slope > 0 ? 'increasing' : slope < 0 ? 'decreasing' : 'stable',
      }
    };
  }, [selectedRegion, regionData]);

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-light text-ink-primary">Capacity Forecasting</h1>
          <p className="text-ink-secondary mt-1">
            Predictive resource planning based on historical trends
          </p>
        </div>
        
        {/* Region Selector */}
        <div className="flex bg-surface-subtle p-1 border border-border-subtle">
          {REGIONS.map(region => (
            <button
              key={region}
              onClick={() => setSelectedRegion(region)}
              className={clsx(
                "px-4 py-2 text-sm font-medium transition-colors ",
                selectedRegion === region
                  ? "bg-surface-base text-ink-primary shadow-sm"
                  : "text-ink-secondary hover:text-ink-primary"
              )}
            >
              {region}
            </button>
          ))}
        </div>
      </div>

      {/* Insight Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <InsightCard 
          label="Current Utilization"
          value={`${forecastStats.currentUsage.toFixed(1)}%`}
          trend={forecastStats.slope * 7} // Weekly trend
          subtext="Avg. CPU Load"
          icon={Server}
        />
        
        <InsightCard 
          label="Growth Trend"
          value={`${(forecastStats.slope * 30).toFixed(1)}%`}
          valueSuffix="/ mo"
          trend={forecastStats.slope} // Just to show direction color
          subtext="Projected monthly increase"
          icon={TrendingUp}
        />

        <InsightCard 
          label="Time to Saturation"
          value={forecastStats.daysToSaturation === Infinity ? '> 1 Year' : `${forecastStats.daysToSaturation} Days`}
          subtext="Until 100% capacity reached"
          icon={Calendar}
          alertLevel={
            forecastStats.daysToSaturation < 14 ? 'critical' : 
            forecastStats.daysToSaturation < 30 ? 'warning' : 'good'
          }
        />
      </div>

      {/* Main Chart */}
      <div className="card p-6">
        <div className="flex items-center justify-between mb-6">
          <h2 className="font-medium text-ink-primary flex items-center gap-2">
            <TrendingUp className="w-5 h-5 text-ac-blue" />
            Load Projection (30 Days History + 14 Day Forecast)
          </h2>
          {forecastStats.daysToWarning < 14 && forecastStats.daysToWarning > 0 && (
            <div className="flex items-center gap-2 px-3 py-1.5 bg-ac-orange/10 border border-ac-orange/30 text-ac-orange text-sm font-medium">
              <AlertTriangle className="w-4 h-4" />
              Projected to hit 80% warning threshold in {forecastStats.daysToWarning} days
            </div>
          )}
        </div>

        <div className="h-[400px] w-full">
          <ResponsiveContainer width="100%" height="100%">
            <ComposedChart data={combinedData} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
              <defs>
                <linearGradient id="usageGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={colors.skyBlue} stopOpacity={0.5}/>
                  <stop offset="50%" stopColor={colors.blue} stopOpacity={0.25}/>
                  <stop offset="100%" stopColor={colors.blue} stopOpacity={0.05}/>
                </linearGradient>
                <linearGradient id="forecastGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={colors.magenta} stopOpacity={0.3}/>
                  <stop offset="100%" stopColor={colors.magenta} stopOpacity={0.05}/>
                </linearGradient>
              </defs>

              <CartesianGrid {...gridDefaultsSoft} />
              <XAxis
                dataKey="date"
                {...xAxisNoLine}
                minTickGap={30}
              />
              <YAxis {...axisDefaults.y} unit="%" domain={[0, 100]} />
              <Tooltip
                {...tooltipDefaults}
                formatter={(val: number) => typeof val === 'number' ? val.toFixed(1) + '%' : val}
              />
              <Legend {...legendDefaults} verticalAlign="top" height={36} />

              {/* Threshold Lines */}
              <ReferenceLine y={80} stroke={colors.orange} strokeDasharray="3 3" strokeWidth={1.5} label={{ position: 'right', value: 'Warning (80%)', fill: colors.orange, fontSize: 10 }} />
              <ReferenceLine y={100} stroke={colors.red} strokeDasharray="3 3" strokeWidth={1.5} label={{ position: 'right', value: 'Capacity (100%)', fill: colors.red, fontSize: 10 }} />

              {/* Historical Usage Area */}
              <Area
                type="monotone"
                dataKey="usage"
                name="Historical Usage"
                stroke={colors.skyBlue}
                fill="url(#usageGradient)"
                strokeWidth={2.5}
              />

              {/* Forecast Confidence Interval (Range) */}
              <Area
                type="monotone"
                dataKey="ciHigh"
                data={combinedData}
                stroke="none"
                fill="url(#forecastGradient)"
                fillOpacity={1}
                name="Forecast Confidence"
                connectNulls
              />

              {/* Forecast Line */}
              <Line
                type="monotone"
                dataKey="forecast"
                name="Projected Trend"
                stroke={colors.magenta}
                strokeWidth={2.5}
                strokeDasharray="5 5"
                dot={false}
                connectNulls
              />
            </ComposedChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}

// =============================================================================
// Helper Components
// =============================================================================

function InsightCard({ 
  label, 
  value, 
  valueSuffix = '', 
  trend, 
  subtext, 
  icon: Icon,
  alertLevel
}: any) {
  let trendColor = 'text-ink-muted';
  let TrendIcon = null;

  if (trend !== undefined) {
    if (trend > 0.1) {
      trendColor = 'text-ac-red';
      TrendIcon = TrendingUp;
    } else if (trend < -0.1) {
      trendColor = 'text-ac-green';
      TrendIcon = TrendingDown;
    } else {
      trendColor = 'text-ink-muted';
    }
  }

  // Override color for "Time to Saturation" logic (lower is bad)
  if (alertLevel === 'critical') trendColor = 'text-ac-red';
  if (alertLevel === 'warning') trendColor = 'text-ac-orange';
  if (alertLevel === 'good') trendColor = 'text-ac-green';

  return (
    <div className={clsx("card p-5 border-l-4", 
      alertLevel === 'critical' ? 'border-l-ac-red' : 
      alertLevel === 'warning' ? 'border-l-ac-orange' : 
      'border-l-ac-blue'
    )}>
      <div className="flex justify-between items-start">
        <div>
          <p className="text-sm font-medium text-ink-secondary">{label}</p>
          <div className="mt-2 flex items-baseline gap-1">
            <span className="text-2xl font-light text-ink-primary">{value}</span>
            {valueSuffix && <span className="text-sm text-ink-secondary">{valueSuffix}</span>}
          </div>
        </div>
        <div className={clsx("p-2  bg-surface-subtle", trendColor)}>
          <Icon className="w-5 h-5" />
        </div>
      </div>
      
      <div className="mt-3 flex items-center gap-2 text-xs">
        {TrendIcon && trend !== undefined && (
          <span className={clsx("flex items-center gap-1 font-medium", trendColor)}>
            <TrendIcon className="w-3 h-3" />
            {Math.abs(trend).toFixed(1)}% {trend > 0 ? 'Increase' : 'Decrease'}
          </span>
        )}
        <span className="text-ink-muted">{subtext}</span>
      </div>
    </div>
  );
}
