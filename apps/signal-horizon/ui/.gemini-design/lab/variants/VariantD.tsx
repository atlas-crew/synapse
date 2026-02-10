import { ScatterChart, Scatter, XAxis, YAxis, ZAxis, Tooltip, ResponsiveContainer } from 'recharts';
import { riskHeatmap } from '../data/fixtures';

export const VariantD = () => {
  return (
    <div className="bg-black border border-ac-magenta/30 p-4 relative overflow-hidden">
      <div className="absolute top-0 right-0 w-32 h-32 bg-ac-magenta/5 blur-3xl pointer-events-none"></div>
      
      <div className="mb-6">
        <div className="text-ac-magenta text-[10px] font-bold tracking-[0.2em] mb-1">THREAT_CORRELATION_MATRIX</div>
        <div className="text-white text-xl font-light">ANOMALY HEATMAP</div>
      </div>
      
      <div className="h-[300px]">
        <ResponsiveContainer width="100%" height="100%">
          <ScatterChart margin={{ top: 20, right: 20, bottom: 20, left: 20 }}>
            <XAxis 
              type="number" 
              dataKey="hour" 
              name="hour" 
              domain={[0, 23]} 
              stroke="#444" 
              fontSize={10} 
              tickCount={24}
              label={{ value: 'Hour of Day', position: 'bottom', fill: '#666', fontSize: 10 }}
            />
            <YAxis 
              type="number" 
              dataKey="day" 
              name="day" 
              domain={[0, 6]} 
              stroke="#444" 
              fontSize={10} 
              tickCount={7}
              label={{ value: 'Day', angle: -90, position: 'left', fill: '#666', fontSize: 10 }}
            />
            <ZAxis type="number" dataKey="value" range={[50, 400]} />
            <Tooltip cursor={{ strokeDasharray: '3 3' }} contentStyle={{ backgroundColor: '#000', border: '1px solid #D62598', borderRadius: 0 }} />
            <Scatter name="Risk Score" data={riskHeatmap} fill="#D62598" opacity={0.6}>
              {riskHeatmap.map((entry, index) => (
                <path 
                  key={`cell-${index}`} 
                  d={`M0,0 L5,5 L0,10 L-5,5 Z`} 
                  fill={entry.value > 80 ? '#D62598' : entry.value > 50 ? '#A400FF' : '#3298BC'}
                />
              ))}
            </Scatter>
          </ScatterChart>
        </ResponsiveContainer>
      </div>
      
      <div className="mt-6 flex flex-wrap gap-4 text-[10px] font-mono">
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 bg-ac-magenta"></div>
          <span className="text-white">CRITICAL_ANOMALY</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 bg-ac-purple"></div>
          <span className="text-white/60">HEURISTIC_MATCH</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 bg-ac-sky"></div>
          <span className="text-white/60">BASELINE_TRAFFIC</span>
        </div>
      </div>
    </div>
  );
};