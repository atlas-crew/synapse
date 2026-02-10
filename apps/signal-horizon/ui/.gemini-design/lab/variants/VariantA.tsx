import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { timeSeriesData, threatDistribution } from '../data/fixtures';

export const VariantA = () => {
  return (
    <div className="bg-[#121212] border border-[#3f3f46] p-4 font-mono text-[11px] uppercase tracking-tighter shadow-card">
      <div className="flex justify-between border-b border-[#3f3f46] pb-2 mb-4">
        {/* Rubik Medium Heading for on-brand clarity */}
        <span className="text-[#0057B7] font-medium font-sans text-[14px] tracking-normal">A. BLOOMBERG_DENSITY_PROTOCOL</span>
        <span className="text-[#a1a1aa] text-[11px]">TX_FLEET_CORRELATION [ACTIVE]</span>
      </div>
      
      <div className="grid grid-cols-4 gap-2 h-[320px]">
        <div className="col-span-3 border border-[#3f3f46]/50 p-2 bg-[#18181b] relative">
          <div className="absolute top-2 left-4 z-10">
             <div className="text-[11px] text-[#a1a1aa] font-sans font-medium">REQUEST_VOLUME_STEP</div>
          </div>
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={timeSeriesData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#27272a" vertical={false} />
              <XAxis dataKey="timestamp" hide />
              <YAxis stroke="#71717a" fontSize={10} tickLine={false} axisLine={false} />
              <Tooltip 
                contentStyle={{ backgroundColor: '#121212', border: '1px solid #3f3f46', fontSize: '10px' }}
                itemStyle={{ padding: 0 }}
              />
              <Area 
                type="stepAfter" 
                dataKey="requests" 
                stroke="#0057B7" 
                fill="#0057B7" 
                fillOpacity={0.1} 
                strokeWidth={1.5}
                isAnimationActive={false}
              />
              <Area 
                type="stepAfter" 
                dataKey="threats" 
                stroke="#D62598" 
                fill="#D62598" 
                fillOpacity={0.2} 
                strokeWidth={1.5}
                isAnimationActive={false}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
        
        <div className="border border-[#3f3f46]/50 p-3 overflow-hidden bg-[#18181b]">
          <div className="text-[#a1a1aa] mb-2 font-sans font-medium text-[11px]">SIGNAL_DISTRIBUTION</div>
          {threatDistribution.map(item => (
            <div key={item.name} className="flex justify-between items-center mb-1.5 border-b border-white/5 py-0.5">
              <span className="truncate pr-2 text-white/60 font-sans text-[12px]">{item.name}</span>
              {/* Rubik Medium for values */}
              <span className="font-sans font-medium text-[13px]" style={{ color: item.color }}>{item.value.toLocaleString()}</span>
            </div>
          ))}
        </div>
      </div>
      
      <div className="mt-4 grid grid-cols-6 gap-2">
        {Array.from({ length: 6 }).map((_, i) => (
          <div key={i} className="border border-[#3f3f46]/50 p-3 bg-[#18181b]">
            <div className="text-[#a1a1aa] mb-1 font-sans font-medium text-[10px]">NODE_{i+101}</div>
            {/* Rubik Medium for prominent values */}
            <div className="text-xl font-medium font-sans text-white leading-none">{(Math.random() * 100).toFixed(1)}%</div>
            <div className={`h-1.5 w-full mt-2 ${i % 3 === 0 ? 'bg-[#D62598]' : 'bg-[#0057B7]'}`}></div>
          </div>
        ))}
      </div>
    </div>
  );
};
