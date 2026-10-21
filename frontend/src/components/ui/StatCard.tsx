import React from 'react';

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: React.ReactNode;
  trend?: string;
  variant?: 'cyan' | 'rose' | 'amber' | 'emerald';
}

export const StatCard: React.FC<StatCardProps> = ({
  title,
  value,
  subtitle,
  icon,
  trend,
  variant = 'cyan',
}) => {
  const borderVariants = {
    cyan: 'border-cyan-500/20 hover:border-cyan-500/40',
    rose: 'border-rose-500/20 hover:border-rose-500/40',
    amber: 'border-amber-500/20 hover:border-amber-500/40',
    emerald: 'border-emerald-500/20 hover:border-emerald-500/40',
  };

  const iconVariants = {
    cyan: 'bg-cyan-950/40 text-cyan-400 border-cyan-800/40',
    rose: 'bg-rose-950/40 text-rose-400 border-rose-800/40',
    amber: 'bg-amber-950/40 text-amber-400 border-amber-800/40',
    emerald: 'bg-emerald-950/40 text-emerald-400 border-emerald-800/40',
  };

  return (
    <div className={`bg-graphite-900 border rounded-lg p-4 transition-all duration-150 ${borderVariants[variant]}`}>
      <div className="flex items-center justify-between">
        <span className="text-xs uppercase tracking-wider font-semibold text-slate-400">{title}</span>
        <div className={`p-2 rounded-md border ${iconVariants[variant]}`}>
          {icon}
        </div>
      </div>
      <div className="mt-3 flex items-baseline justify-between">
        <div className="text-2xl font-bold font-mono tracking-tight text-white">{value}</div>
        {trend && <span className="text-xs font-mono text-cyan-400 font-medium">{trend}</span>}
      </div>
      {subtitle && <p className="mt-1 text-xs text-slate-400">{subtitle}</p>}
    </div>
  );
};
