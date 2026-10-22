import React, { useState, useEffect } from 'react';
import { Maximize2, Minimize2, RotateCw, ShieldCheck, Sparkles, Monitor } from 'lucide-react';

export const NativeAppTitleBar: React.FC = () => {
  const [isStandalone, setIsStandalone] = useState<boolean>(false);
  const [isFullscreen, setIsFullscreen] = useState<boolean>(false);

  useEffect(() => {
    const checkStandalone = () => {
      const isPWA = window.matchMedia('(display-mode: standalone)').matches ||
                    (window.navigator as any).standalone ||
                    window.location.search.includes('mode=standalone');
      setIsStandalone(Boolean(isPWA));
    };

    checkStandalone();
    window.addEventListener('resize', checkStandalone);
    return () => window.removeEventListener('resize', checkStandalone);
  }, []);

  const toggleFullscreen = () => {
    if (!document.fullscreenElement) {
      document.documentElement.requestFullscreen().catch(() => {});
      setIsFullscreen(true);
    } else {
      if (document.exitFullscreen) {
        document.exitFullscreen().catch(() => {});
        setIsFullscreen(false);
      }
    }
  };

  const handleRefresh = () => {
    window.location.reload();
  };

  if (!isStandalone) {
    return null;
  }

  return (
    <div className="h-8 bg-graphite-950 border-b border-cyan-500/30 px-3 flex items-center justify-between text-xs select-none z-50 sticky top-0 font-mono">
      {/* Left: Emblem & Project Heading */}
      <div className="flex items-center space-x-2">
        <img src="/logo.png" alt="Logo" className="w-4 h-4 object-contain rounded" />
        <span className="font-bold text-white tracking-wider">
          SENTINEL<span className="text-cyan-400">-X</span>
        </span>
        <span className="text-slate-500 text-[10px]">|</span>
        <span className="text-slate-300 text-[11px] font-medium hidden sm:inline">
          Unified Cyber Defense, Testing & Forensics
        </span>
        <span className="px-1.5 py-0.2 rounded bg-cyan-950/80 text-cyan-400 border border-cyan-500/40 text-[9px] font-bold">
          STANDALONE APP
        </span>
      </div>

      {/* Center: Real-Time Shield Posture */}
      <div className="hidden md:flex items-center space-x-1.5 text-emerald-400 text-[11px]">
        <ShieldCheck className="w-3.5 h-3.5 animate-pulse" />
        <span className="font-medium">ZERO-TRUST SHIELD ONLINE</span>
      </div>

      {/* Right: Window Controls */}
      <div className="flex items-center space-x-2">
        <button
          onClick={handleRefresh}
          className="p-1 text-slate-400 hover:text-cyan-300 hover:bg-slate-800 rounded transition"
          title="Reload Sentinel-X App Shell"
        >
          <RotateCw className="w-3 h-3" />
        </button>
        <button
          onClick={toggleFullscreen}
          className="p-1 text-slate-400 hover:text-cyan-300 hover:bg-slate-800 rounded transition"
          title="Toggle Fullscreen Dedicated View"
        >
          {isFullscreen ? <Minimize2 className="w-3 h-3" /> : <Maximize2 className="w-3 h-3" />}
        </button>
      </div>
    </div>
  );
};
