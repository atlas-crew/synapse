import { ComposedChart, Area, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { timeSeriesData } from '../data/fixtures';

export const VariantE = () => {
  return (
    <div className="bg-[#101928] border border-white/10 p-8 shadow-card-strong">
      <div className="mb-10">
        <h3 className="text-2xl font-light tracking-tight mb-2">NETWORK PERFORMANCE</h3>
        <p className="text-white/40 text-sm">Real-time throughput and error rate correlation across global fleet.</p>
      </div>
      
      <div className="h-[400px]">
        <ResponsiveContainer width="100%" height="100%">
          <ComposedChart data={timeSeriesData}>
            <defs>
              <linearGradient id="colorRequests" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#0057B7" stopOpacity={0.3}/>
                <stop offset="95%" stopColor="#0057B7" stopOpacity={0}/>
              </linearGradient>
            </defs>
            <CartesianGrid stroke="#1e293b" vertical={false} />
            <XAxis dataKey="timestamp" hide />
            <YAxis stroke="#475569" fontSize={11} axisLine={false} tickLine={false} />
            <Tooltip 
              contentStyle={{ backgroundColor: '#1e293b', border: 'none', boxShadow: '0 4px 12px rgba(0,0,0,0.5)' }}
            />
            <Area 
              type="monotone" 
              dataKey="requests" 
              stroke="#0057B7" 
              strokeWidth={3}
              fillOpacity={1} 
              fill="url(#colorRequests)" 
            />
            <Bar 
              dataKey="threats" 
              barSize={4} 
              fill="#D62598" 
              radius={0}
            />
          </ComposedChart>
        </ResponsiveContainer>
      </div>
      
      <div className="mt-8 grid grid-cols-3 gap-6">
        <div className="p-4 border border-white/5 bg-white/[0.02]">
          <div className="text-[11px] text-white/40 uppercase tracking-widest mb-1">Peak Throughput</div>
          <div className="text-2xl font-semibold">1.4 GB/S</div>
        </div>
        <div className="p-4 border border-white/5 bg-white/[0.02]">
          <div className="text-[11px] text-white/40 uppercase tracking-widest mb-1">Error Rate</div>
          <div className="text-2xl font-semibold text-ac-magenta">0.04%</div>
        </div>
        <div className="p-4 border border-white/5 bg-white/[0.02]">
          <div className="text-[11px] text-white/40 uppercase tracking-widest mb-1">Active Nodes</div>
          <div className="text-2xl font-semibold text-ac-blue">2,841</div>
        </div>
      </div>
    </div>
  );
};