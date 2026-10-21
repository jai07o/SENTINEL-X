import React from 'react';
import { Severity, IncidentStatus } from '../../types';

interface StatusBadgeProps {
  severity?: Severity | string;
  status?: IncidentStatus | string;
  size?: 'sm' | 'md';
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ severity, status, size = 'sm' }) => {
  const sizeClasses = size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-2.5 py-1 text-sm font-medium';

  if (severity) {
    const sev = severity.toUpperCase();
    let colorClasses = 'bg-slate-800 text-slate-300 border-slate-700';

    switch (sev) {
      case 'CRITICAL':
        colorClasses = 'bg-rose-950/60 text-rose-300 border-rose-600/50 shadow-sm shadow-rose-950';
        break;
      case 'HIGH':
        colorClasses = 'bg-orange-950/60 text-orange-300 border-orange-600/50';
        break;
      case 'MEDIUM':
        colorClasses = 'bg-amber-950/60 text-amber-300 border-amber-600/50';
        break;
      case 'LOW':
        colorClasses = 'bg-sky-950/60 text-sky-300 border-sky-600/50';
        break;
      case 'INFO':
      case 'INFORMATIONAL':
        colorClasses = 'bg-cyan-950/40 text-cyan-300 border-cyan-800/40';
        break;
    }

    return (
      <span className={`inline-flex items-center font-mono font-semibold rounded border ${colorClasses} ${sizeClasses}`}>
        <span className="w-1.5 h-1.5 rounded-full mr-1.5 bg-current opacity-80" />
        {sev}
      </span>
    );
  }

  if (status) {
    let colorClasses = 'bg-slate-800 text-slate-300 border-slate-700';
    switch (status) {
      case 'New':
        colorClasses = 'bg-rose-950/40 text-rose-300 border-rose-700/40';
        break;
      case 'Triaged':
        colorClasses = 'bg-amber-950/40 text-amber-300 border-amber-700/40';
        break;
      case 'Investigating':
        colorClasses = 'bg-cyan-950/50 text-cyan-300 border-cyan-600/50';
        break;
      case 'Contained':
        colorClasses = 'bg-purple-950/50 text-purple-300 border-purple-600/50';
        break;
      case 'Resolved':
      case 'Closed':
        colorClasses = 'bg-emerald-950/50 text-emerald-300 border-emerald-600/50';
        break;
    }

    return (
      <span className={`inline-flex items-center font-medium rounded border ${colorClasses} ${sizeClasses}`}>
        {status}
      </span>
    );
  }

  return null;
};
