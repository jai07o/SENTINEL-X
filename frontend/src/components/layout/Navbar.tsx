import React from 'react';
import { useAuth } from '../../context/AuthContext';
import { useWebSocket } from '../../context/WebSocketContext';
import { Link } from 'react-router-dom';
import { Shield, Bell, LogOut, Radio, User, Laptop } from 'lucide-react';

export const Navbar: React.FC = () => {
  const { user, logout } = useAuth();
  const { isConnected, unreadAlertCount, clearAlerts } = useWebSocket();

  return (
    <header className="h-14 bg-graphite-900 border-b border-slate-800/80 px-4 flex items-center justify-between sticky top-0 z-30">
      {/* Brand & Health Status */}
      <div className="flex items-center space-x-3">
        <div className="flex items-center space-x-2">
          <div className="p-1 bg-cyan-950/80 border border-cyan-500/40 rounded-lg shadow-sm shadow-cyan-950 flex items-center justify-center">
            <img src="/logo.png" alt="SENTINEL-X Logo" className="w-6 h-6 rounded object-contain" />
          </div>
          <span className="font-bold tracking-wider text-white text-base">
            SENTINEL<span className="text-cyan-400">-X</span>
          </span>
          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700 ml-1">
            v0.1.0-alpha
          </span>
        </div>

        {/* WebSocket Telemetry Stream Pulse */}
        <div className="hidden md:flex items-center space-x-2 border-l border-slate-800 pl-4 py-1">
          <Radio className={`w-3.5 h-3.5 ${isConnected ? 'text-emerald-400 animate-pulse' : 'text-slate-500'}`} />
          <span className="text-xs font-mono text-slate-400">
            Stream: {isConnected ? <span className="text-emerald-400 font-medium">LIVE</span> : <span className="text-slate-500">OFFLINE</span>}
          </span>
        </div>

        {/* Active Local System Guard Pill */}
        <Link
          to="/active-system"
          className="hidden lg:flex items-center space-x-1.5 px-2.5 py-1 rounded-md bg-cyan-950/40 border border-cyan-500/30 hover:border-cyan-400 text-xs font-mono text-cyan-300 transition"
          title="Active System & Connected Devices Real-Time Guard"
        >
          <Laptop className="w-3.5 h-3.5 text-cyan-400" />
          <span>ACTIVE HOST & DEVICES GUARD</span>
        </Link>
      </div>

      {/* Right Controls: Notifications, User, Logout */}
      <div className="flex items-center space-x-3">
        {/* Alerts Bell */}
        <button
          onClick={clearAlerts}
          className="relative p-2 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800/80 transition-colors"
          title="Live Alert Notifications"
        >
          <Bell className="w-4 h-4" />
          {unreadAlertCount > 0 && (
            <span className="absolute top-1 right-1 w-4 h-4 bg-rose-500 text-white text-[10px] font-bold rounded-full flex items-center justify-center font-mono animate-bounce">
              {unreadAlertCount > 9 ? '9+' : unreadAlertCount}
            </span>
          )}
        </button>

        {/* User Profile Badge */}
        {user && (
          <div className="flex items-center space-x-2 bg-slate-800/60 border border-slate-700/60 rounded-lg px-2.5 py-1">
            <div className="w-6 h-6 rounded-full bg-cyan-950 border border-cyan-500/40 text-cyan-300 flex items-center justify-center text-xs font-bold">
              {user.username.charAt(0).toUpperCase()}
            </div>
            <div className="text-left hidden sm:block">
              <div className="text-xs font-medium text-slate-200 leading-none">{user.username}</div>
              <div className="text-[10px] text-cyan-400 uppercase tracking-wider font-mono mt-0.5 leading-none">
                {user.role?.name || 'analyst'}
              </div>
            </div>
          </div>
        )}

        {/* Logout */}
        <button
          onClick={logout}
          className="p-2 rounded-lg text-slate-400 hover:text-rose-400 hover:bg-rose-950/30 transition-colors"
          title="Sign Out"
        >
          <LogOut className="w-4 h-4" />
        </button>
      </div>
    </header>
  );
};
