interface LabShellProps {
  children: React.ReactNode;
  title: string;
  description: string;
}

export const LabShell: React.FC<LabShellProps> = ({ children, title, description }) => {
  return (
    <div className="min-h-screen bg-[#09090b] text-white font-sans selection:bg-ac-blue/30">
      <header className="border-b border-[#3f3f46] p-6 bg-[#121212] sticky top-0 z-50 backdrop-blur-md">
        <div className="flex items-center justify-between max-w-[1600px] mx-auto">
          <div>
            <h1 className="text-2xl font-light tracking-tight text-[#0057B7]">
              SIGNAL <span className="font-bold text-white">HORIZON</span> DESIGN LAB
            </h1>
            <p className="text-[#a1a1aa] text-sm mt-1 uppercase tracking-widest font-medium">{title}</p>
          </div>
          <div className="text-right">
            <span className="text-xs font-mono text-white/40">WCAG AA COMPLIANT REFERENCE</span>
          </div>
        </div>
      </header>
      
      <main className="max-w-[1600px] mx-auto p-8">
        <div className="mb-12">
          <p className="text-[#a1a1aa] text-lg max-w-3xl leading-relaxed">
            {description}
          </p>
        </div>
        
        <div className="grid grid-cols-1 gap-12">
          {children}
        </div>
      </main>
      
      <footer className="border-t border-[#3f3f46] p-8 mt-20 bg-[#121212]">
        <div className="max-w-[1600px] mx-auto text-xs text-white/30 flex justify-between">
          <span>Atlas Crew NETWORKS PROPRIETARY</span>
          <span>SYSTEM DESIGN: RUBIK + 0PX RADIUS</span>
        </div>
      </footer>
    </div>
  );
};
