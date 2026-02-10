import { LabShell } from './components/LabShell';
import { VariantA } from './variants/VariantA';
import { VariantB } from './variants/VariantB';
import { VariantC } from './variants/VariantC';
import { VariantD } from './variants/VariantD';
import { VariantE } from './variants/VariantE';
import { VariantF } from './variants/VariantF';

const DesignLabPage = () => {
  return (
    <LabShell 
      title="SOC Data Visualization Reference" 
      description="Exploring high-density, WCAG AA compliant data visualizations for the Signal Horizon SOC. These variants focus on brand identity, security aesthetics, and professional monitoring requirements."
    >
      <section id="variant-f">
        <div className="mb-4">
          <h2 className="text-xl font-bold text-white border-l-4 border-ac-magenta pl-3">Variant F: The Executive Analyst (Refined)</h2>
          <p className="text-white/40 text-sm italic">Synthesized Bloomberg density with Rubik Medium headings and prominent metrics for professional clarity.</p>
        </div>
        <VariantF />
      </section>

      <section id="variant-a">
        <div className="mb-4">
          <h2 className="text-xl font-bold text-white">Variant A: The Bloomberg Density Protocol</h2>
          <p className="text-white/40 text-sm italic">Extreme density, monospace focus, step-after paths, and secondary metadata columns.</p>
        </div>
        <VariantA />
      </section>

      <section id="variant-b">
        <div className="mb-4">
          <h2 className="text-xl font-bold text-white">Variant B: The Atlas Crew Brand Framework</h2>
          <p className="text-white/40 text-sm italic">Dominant brand colors, strict rectangular hierarchy, and bold typographic signals.</p>
        </div>
        <BarChartComparison />
      </section>

      <section id="variant-c">
        <div className="mb-4">
          <h2 className="text-xl font-bold text-white">Variant C: The Grafana Observability Model</h2>
          <p className="text-white/40 text-sm italic">Multi-axis time series, status-color integration, and optimized grid systems.</p>
        </div>
        <VariantC />
      </section>

      <section id="variant-d">
        <div className="mb-4">
          <h2 className="text-xl font-bold text-white">Variant D: Security Signal Correlation</h2>
          <p className="text-white/40 text-sm italic">Heatmap matrix using Atlas Crew Magenta for anomalies and diamond-marker signals.</p>
        </div>
        <VariantD />
      </section>

      <section id="variant-e">
        <div className="mb-4">
          <h2 className="text-xl font-bold text-white">Variant E: Clean Tech Modernist</h2>
          <p className="text-white/40 text-sm italic">High contrast, refined whitespace, and gradient-stroke performance indicators.</p>
        </div>
        <VariantE />
      </section>
    </LabShell>
  );
};

// Internal wrapper to avoid export issues in the shell
const BarChartComparison = () => <VariantB />;

export default DesignLabPage;