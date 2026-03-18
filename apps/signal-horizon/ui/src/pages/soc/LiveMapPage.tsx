import { LiveAttackMap } from '../../components/soc/LiveAttackMap';
import { Shield, Globe } from 'lucide-react';
import { useDocumentTitle } from '../../hooks/useDocumentTitle';
import { SectionHeader, Stack, StatusBadge, Box, Text } from '@/ui';

export default function LiveMapPage() {
  useDocumentTitle('SOC - Live Map');
  
  return (
    <Box p="xl">
      <Stack gap="xl">
        <SectionHeader
          title="Live Threat Map"
          description="Real-time visualization of fleet-wide attack vectors"
          size="h2"
          actions={
            <Stack direction="row" align="center" gap="sm">
              <StatusBadge status="info" variant="subtle" size="sm">
                <Stack as="span" inline direction="row" align="center" gap="sm">
                  <Globe aria-hidden="true" className="w-4 h-4" />
                  <Text variant="small" weight="medium" noMargin>Global Fleet Connected</Text>
                  <Box
                    className="w-2 h-2 animate-pulse"
                    style={{ background: 'var(--ac-green)', display: 'inline-block' }}
                  />
                </Stack>
              </StatusBadge>
            </Stack>
          }
        />
        
        <Box bg="card" border="subtle" p="none" style={{ position: 'relative', overflow: 'hidden' }}>
          <LiveAttackMap />
        </Box>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <StatMiniCard 
            label="Critical Threats (Last 5m)" 
            value="142" 
            indicatorColor="var(--ac-red)" 
          />
          <StatMiniCard 
            label="High Severity" 
            value="853" 
            indicatorColor="var(--ac-orange)" 
          />
          <StatMiniCard 
            label="Auto-Blocked" 
            value="98.4%" 
            icon={Shield}
            iconColor="var(--ac-green)" 
          />
        </div>
      </Stack>
    </Box>
  );
}

function StatMiniCard({ 
  label, 
  value, 
  indicatorColor, 
  icon: Icon,
  iconColor 
}: { 
  label: string; 
  value: string; 
  indicatorColor?: string;
  icon?: any;
  iconColor?: string;
}) {
  return (
    <Box bg="card" border="subtle" p="lg">
      <Stack gap="sm">
        <Stack direction="row" align="center" gap="sm">
          {indicatorColor && (
            <Box style={{ width: 8, height: 8, background: indicatorColor }} />
          )}
          {Icon && (
            <Icon size={16} style={{ color: iconColor }} />
          )}
          <Text variant="small" color="secondary" weight="medium" noMargin>
            {label}
          </Text>
        </Stack>
        <Text variant="metric" noMargin>{value}</Text>
      </Stack>
    </Box>
  );
}
