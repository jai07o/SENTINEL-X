import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { api } from '../api/client';
import { Shield, Lock, User, AlertCircle, KeyRound, Sparkles, Check, Copy } from 'lucide-react';

interface SystemCredentialsInfo {
  status: string;
  system_hostname: string;
  operating_system: string;
  os_slug: string;
  host_username: string;
  admin_username: string;
  system_password: string;
  vault_path: string;
  is_local_deployment: boolean;
}

export const LoginPage: React.FC = () => {
  const { login, user } = useAuth();
  const navigate = useNavigate();
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('');
  const [systemCreds, setSystemCreds] = useState<SystemCredentialsInfo | null>(null);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    if (user) {
      navigate('/', { replace: true });
    }
  }, [user, navigate]);

  useEffect(() => {
    // Fetch dynamically generated host credentials based on active OS & system deployment
    api
      .get<SystemCredentialsInfo>('/auth/system-credentials-info')
      .then((res) => {
        setSystemCreds(res.data);
        if (res.data.system_password) {
          setUsername(res.data.host_username || 'admin');
          setPassword(res.data.system_password);
        }
      })
      .catch(() => {
        // Fallback
      });
  }, []);

  const copyPassword = () => {
    if (systemCreds?.system_password) {
      navigator.clipboard.writeText(systemCreds.system_password);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const applyCredentials = (userToUse: string) => {
    if (systemCreds) {
      setUsername(userToUse);
      setPassword(systemCreds.system_password);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsSubmitting(true);
    try {
      await login(username, password);
      navigate('/', { replace: true });
    } catch (err: any) {
      setError(err.message || 'Authentication failed. Please check credentials.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-graphite-950 px-4 py-8">
      <div className="max-w-md w-full bg-graphite-900 border border-slate-800 rounded-2xl p-8 shadow-2xl shadow-cyan-950/20 space-y-6">
        <div className="flex flex-col items-center text-center">
          <div className="p-2 bg-cyan-950/80 border border-cyan-500/40 rounded-2xl mb-3 shadow-lg shadow-cyan-950/50 flex items-center justify-center">
            <img src="/logo.png" alt="SENTINEL-X" className="w-14 h-14 rounded-xl object-contain shadow" />
          </div>
          <h1 className="text-xl font-bold tracking-wider text-white">
            SENTINEL<span className="text-cyan-400">-X</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">Unified Cyber Defense, Forensic Containment & Investigation</p>
        </div>

        {/* Dynamic System & OS Derived Credentials Badge */}
        {systemCreds && (
          <div className="p-3.5 bg-gradient-to-r from-cyan-950/70 to-slate-900 border border-cyan-500/40 rounded-xl space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono uppercase tracking-wider text-cyan-300 font-bold flex items-center space-x-1.5">
                <Sparkles className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
                <span>SYSTEM-DERIVED CREDENTIALS</span>
              </span>
              <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-emerald-950 text-emerald-400 border border-emerald-500/30">
                ZERO DEFAULT PASSWORDS
              </span>
            </div>
            <div className="text-[11px] text-slate-300 flex items-center space-x-1.5">
              <KeyRound className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
              <span>
                Generated for <strong className="text-white">{systemCreds.system_hostname}</strong> ({systemCreds.os_slug})
              </span>
            </div>
            <div className="flex items-center justify-between bg-slate-950/80 p-2 rounded-lg border border-slate-800 font-mono text-[11px]">
              <span className="text-slate-400 truncate max-w-[210px]">{systemCreds.system_password}</span>
              <button
                type="button"
                onClick={copyPassword}
                className="text-cyan-400 hover:text-cyan-300 flex items-center space-x-1 text-[10px] px-1.5 py-0.5 bg-cyan-950/80 rounded border border-cyan-500/30 transition"
              >
                {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                <span>{copied ? 'Copied' : 'Copy'}</span>
              </button>
            </div>
            <div className="flex items-center space-x-2 pt-0.5">
              <button
                type="button"
                onClick={() => applyCredentials(systemCreds.host_username)}
                className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 text-[10px] font-mono border border-slate-700 transition"
              >
                Use: {systemCreds.host_username}
              </button>
              <button
                type="button"
                onClick={() => applyCredentials('admin')}
                className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 text-[10px] font-mono border border-slate-700 transition"
              >
                Use: admin
              </button>
            </div>
          </div>
        )}

        {error && (
          <div className="p-3 bg-rose-950/50 border border-rose-800/60 rounded-xl flex items-start space-x-2.5 text-xs text-rose-300">
            <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1.5">Username or Analyst ID</label>
            <div className="relative">
              <User className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                className="w-full bg-graphite-950 border border-slate-800 rounded-xl pl-9 pr-3 py-2 text-xs text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 font-mono"
                placeholder="Enter username"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1.5">Password</label>
            <div className="relative">
              <Lock className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                className="w-full bg-graphite-950 border border-slate-800 rounded-xl pl-9 pr-3 py-2 text-xs text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 font-mono"
                placeholder="Enter password"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={isSubmitting}
            className="w-full mt-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-bold py-2.5 rounded-xl text-xs transition-colors flex items-center justify-center space-x-2 shadow-lg shadow-cyan-950/50 disabled:opacity-50"
          >
            {isSubmitting ? (
              <>
                <div className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                <span>Authenticating...</span>
              </>
            ) : (
              <span>Authorize Session</span>
            )}
          </button>
        </form>

        <div className="pt-2 text-center">
          <p className="text-[10px] text-slate-500">
            Unique cryptographic credentials seeded dynamically from active hardware fingerprint.
          </p>
        </div>
      </div>
    </div>
  );
};
