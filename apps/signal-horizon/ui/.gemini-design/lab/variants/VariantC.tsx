import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import { timeSeriesData } from '../data/fixtures';

export const VariantC = () => {
  return (
    <div className="bg-[#0b0c0e] border border-[#202226] p-4">
      <div className="flex items-center justify-between mb-4 px-2">
        <h4 className="text-[#d8d9da] text-sm font-semibold flex items-center gap-2">
          <span className="w-1 h-4 bg-ac-blue"></span>
          REQUESTS_VS_LATENCY
        </h4>
        <div className="flex gap-2">
          <button className="px-2 py-0.5 bg-[#202226] border border-[#2c3235] text-[10px] text-[#9fef00]">LIVE</button>
        </div>
      </div>
      
      <div className="h-[350px]">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={timeSeriesData}>
            <CartesianGrid stroke="#2c3235" vertical={false} strokeDasharray="3 3" />
            <XAxis dataKey="timestamp" hide />
            <YAxis yAxisId="left" stroke="#9fef00" fontSize={10} axisLine={false} tickLine={false} />
            <YAxis yAxisId="right" orientation="right" stroke="#70BAF7" fontSize={10} axisLine={false} tickLine={false} />
            <Tooltip 
              contentStyle={{ backgroundColor: '#111217', border: '1px solid #2c3235', fontSize: '11px' }}
              itemStyle={{ padding: '2px 0' }}
            />
            <Legend iconType="rect" iconSize={10} wrapperStyle={{ fontSize: '10px', paddingTop: '10px' }} />
            <Line 
              yAxisId="left" 
              type="monotone" 
              dataKey="requests" 
              stroke="#9fef00" 
              strokeWidth={1.5} 
              dot={false} 
              isAnimationActive={false}
            />
            <Line 
              yAxisId="right" 
              type="monotone" 
              dataKey="latency" 
              stroke="#70BAF7" 
              strokeWidth={1.5} 
              dot={false} 
              isAnimationActive={false}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
};