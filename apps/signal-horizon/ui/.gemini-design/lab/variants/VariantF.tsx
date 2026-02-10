import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import { timeSeriesData, threatDistribution } from '../data/fixtures';

export const VariantF = () => {
  return (
    <div className="bg-[#121212] border border-[#3f3f46] p-4 font-mono text-[11px] uppercase tracking-tighter shadow-card-strong">
      <div className="flex justify-between border-b border-[#3f3f46] pb-3 mb-5">
        <span className="text-[#0057B7] font-medium font-sans text-[16px] tracking-normal bg-white px-2 py-0.5">A. EXECUTIVE_ANALYST_PROTOCOL</span>
        <span className="text-[#a1a1aa] text-[12px] font-sans font-bold flex items-center gap-2">
          <span className="w-2 h-2 bg-[#008731] animate-pulse"></span>
          TX_FLEET_CORRELATION [ACTIVE]
        </span>
      </div>
      
      <div className="mb-4 border border-[#3f3f46] p-4 bg-[#18181b] relative">
        <div className="absolute top-4 left-6 z-10">
          <div className="text-[12px] text-[#a1a1aa] font-sans font-medium uppercase tracking-widest">TRAFFIC_THROUGHPUT_CORRELATION</div>
        </div>
        <div className="h-[240px]">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={timeSeriesData} margin={{ top: 20, right: 10, left: 0, bottom: 0 }}>
              <defs>
                <linearGradient id="fillBlue" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#0057B7" stopOpacity={0.4}/>
                  <stop offset="95%" stopColor="#0057B7" stopOpacity={0.05}/>
                </linearGradient>
                <linearGradient id="fillMagenta" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#D62598" stopOpacity={0.4}/>
                  <stop offset="95%" stopColor="#D62598" stopOpacity={0.05}/>
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="0" stroke="#27272a" vertical={false} />
              <XAxis dataKey="timestamp" hide />
              <YAxis stroke="#71717a" fontSize={11} tickLine={false} axisLine={false} />
              <Tooltip 
                contentStyle={{ backgroundColor: '#121212', border: '1px solid #3f3f46', fontSize: '12px', color: '#FFFFFF', borderRadius: 0 }}
                itemStyle={{ padding: '2px 0' }}
              />
              <Legend verticalAlign="top" align="right" iconType="rect" wrapperStyle={{ paddingBottom: '20px', fontSize: '10px', textTransform: 'uppercase' }} />
              <Area 
                name="Total Requests"
                type="monotone" 
                dataKey="requests" 
                stroke="#0057B7" 
                fill="url(#fillBlue)" 
                strokeWidth={3}
                isAnimationActive={false}
              />
              <Area 
                name="Security Threats"
                type="monotone" 
                dataKey="threats" 
                stroke="#D62598" 
                fill="url(#fillMagenta)" 
                strokeWidth={3}
                isAnimationActive={false}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="grid grid-cols-4 gap-3 h-[280px]">
        <div className="col-span-3 border border-[#3f3f46] p-4 relative bg-[#18181b]">
          <div className="absolute top-4 left-6 z-10">
             <div className="text-[12px] text-[#a1a1aa] font-sans font-medium uppercase tracking-widest">SIGNAL_STEP_SCANNER</div>
          </div>
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={timeSeriesData}>
              <CartesianGrid strokeDasharray="0" stroke="#27272a" vertical={false} />
              <XAxis dataKey="timestamp" hide />
              <YAxis stroke="#71717a" fontSize={11} tickLine={false} axisLine={false} />
              <Tooltip 
                contentStyle={{ backgroundColor: '#121212', border: '1px solid #3f3f46', fontSize: '12px', color: '#FFFFFF', borderRadius: 0 }}
              />
              <Area 
                type="stepAfter" 
                dataKey="requests" 
                stroke="#0057B7" 
                fill="#0057B7" 
                fillOpacity={0.15} 
                strokeWidth={2}
                isAnimationActive={false}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
        
        <div className="border border-[#3f3f46] p-4 overflow-hidden bg-[#18181b]">
          <div className="text-[#a1a1aa] mb-4 font-sans font-medium text-[12px] uppercase tracking-wider border-b border-[#3f3f46] pb-2">SIGNAL_DISTRIBUTION</div>
          {threatDistribution.map(item => (
            <div key={item.name} className="flex justify-between items-center mb-3 border-b border-white/5 py-1.5">
              <span className="truncate pr-2 font-sans text-[13px] text-white/80">{item.name}</span>
              <span className="font-sans font-medium text-[16px]" style={{ color: item.color }}>{item.value.toLocaleString()}</span>
            </div>
          ))}
        </div>
      </div>
      
      <div className="mt-4 grid grid-cols-6 gap-3">
        {Array.from({ length: 6 }).map((_, i) => (
          <div key={i} className="border border-[#3f3f46] p-5 bg-[#18181b] relative overflow-hidden group hover:border-[#0057B7] transition-colors">
            <div className="text-[#a1a1aa] mb-1 font-sans font-medium text-[11px] uppercase tracking-wider">NODE_{i+101}</div>
            <div className="text-[32px] font-medium font-sans text-white leading-none tracking-tighter">{(Math.random() * 100).toFixed(1)}%</div>
            <div className={`h-2 w-full mt-4 ${i % 3 === 0 ? 'bg-[#D62598]' : 'bg-[#0057B7]'}`}></div>
            <div className={`absolute top-0 right-0 w-2 h-2 ${i % 3 === 0 ? 'bg-[#EF3340]' : 'bg-[#008731]'}`}></div>
          </div>
        ))}
      </div>
    </div>
  );
};