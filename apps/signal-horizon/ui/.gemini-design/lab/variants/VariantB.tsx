import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import { threatDistribution } from '../data/fixtures';

export const VariantB = () => {
  return (
    <div className="bg-ac-navy border-l-4 border-ac-blue p-6 shadow-card">
      <div className="flex items-center gap-3 mb-6">
        <div className="w-12 h-12 bg-ac-blue flex items-center justify-center text-white font-bold text-xl">AC</div>
        <div>
          <h3 className="text-lg font-medium leading-none">THREAT LANDSCAPE</h3>
          <p className="text-ac-sky text-xs font-bold tracking-widest mt-1">GLOBAL_DISTRIBUTION</p>
        </div>
      </div>
      
      <div className="h-[400px]">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={threatDistribution} layout="vertical" margin={{ left: 100 }}>
            <CartesianGrid strokeDasharray="0" stroke="#1a2b4a" horizontal={false} />
            <XAxis type="number" hide />
            <YAxis 
              dataKey="name" 
              type="category" 
              stroke="#fff" 
              fontSize={12} 
              tickLine={false} 
              axisLine={false}
              width={150}
            />
            <Tooltip 
              cursor={{ fill: 'rgba(255,255,255,0.05)' }}
              contentStyle={{ backgroundColor: '#001E62', border: '2px solid #0057B7', borderRadius: 0 }}
            />
            <Bar dataKey="value" radius={0} barSize={32}>
              {threatDistribution.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
      
      <div className="mt-8 flex gap-8 border-t border-white/10 pt-6">
        <div>
          <div className="text-ac-sky text-[10px] font-bold tracking-widest uppercase">Total Volume</div>
          <div className="text-3xl font-light tracking-tighter">1,248,392</div>
        </div>
        <div>
          <div className="text-ac-magenta text-[10px] font-bold tracking-widest uppercase">High Severity</div>
          <div className="text-3xl font-light tracking-tighter">42,901</div>
        </div>
      </div>
    </div>
  );
};