export const timeSeriesData = Array.from({ length: 100 }, (_, i) => ({
  timestamp: new Date(Date.now() - (100 - i) * 60000).toISOString(),
  requests: Math.floor(Math.random() * 500) + 100,
  threats: Math.floor(Math.random() * 20),
  latency: Math.floor(Math.random() * 50) + 10,
}));

export const threatDistribution = [
  { name: 'SQL Injection', value: 400, color: '#BF3A30' },
  { name: 'Cross-Site Scripting', value: 300, color: '#D62598' },
  { name: 'DDoS Path', value: 300, color: '#C24900' },
  { name: 'Credential Stuffing', value: 200, color: '#A400FF' },
  { name: 'Bot Activity', value: 100, color: '#3298BC' },
];

export const riskHeatmap = Array.from({ length: 7 }, (_, day) => 
  Array.from({ length: 24 }, (_, hour) => ({
    day,
    hour,
    value: Math.floor(Math.random() * 100),
  }))
).flat();
