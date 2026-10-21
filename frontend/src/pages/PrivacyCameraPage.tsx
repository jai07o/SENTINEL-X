import React, { useState, useEffect } from 'react';
import { ApiClient } from '../api/client';
import { Camera, CameraOff, Smartphone, Laptop, AlertOctagon, ShieldAlert, ShieldCheck, RefreshCw, XCircle, Eye, EyeOff } from 'lucide-react';

export const PrivacyCameraPage: React.FC = () => {
  const [privacyData, setPrivacyData] = useState<any>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [activeTab, setActiveTab] = useState<'all' | 'laptop' | 'mobile'>('all');
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  const fetchPrivacyStatus = async () => {
    setIsLoading(true);
    try {
      const data = await ApiClient.getCameraStatus();
      setPrivacyData(data);
    } catch (err) {
      console.error('Failed to load privacy camera status:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchPrivacyStatus();
    const interval = setInterval(fetchPrivacyStatus, 4000);
    return () => clearInterval(interval);
  }, []);

  const handleTerminateApp = async (pid: number, appName: string) => {
    if (!window.confirm(`Are you sure you want to terminate app '${appName}' (PID: ${pid}) accessing camera?`)) {
      return;
    }
    try {
      const res = await ApiClient.terminatePrivacyApp(pid);
      setActionMessage(res.message);
      fetchPrivacyStatus();
      setTimeout(() => setActionMessage(null), 4000);
    } catch (err: any) {
      setActionMessage(`Error: ${err.message}`);
    }
  };

  const summary = privacyData?.summary || {};
  const isCameraInUse = summary.active_camera_in_use;
  const backgroundViolations = summary.unauthorized_background_violations || 0;

  const eventsToShow = (
    activeTab === 'laptop'
      ? privacyData?.laptop_webcam_events || []
      : activeTab === 'mobile'
      ? privacyData?.mobile_telemetry_events || []
      : privacyData?.all_events || []
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <Camera className="w-5 h-5 text-cyan-400" />
            <h1 className="text-xl font-bold tracking-tight text-white">Camera & Microphone Privacy Sentinel</h1>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Detects apps on laptops and mobile devices that automatically open camera/mic in the background while not in use.
          </p>
        </div>
        <div className="flex items-center space-x-3">
          <button
            onClick={fetchPrivacyStatus}
            disabled={isLoading}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-graphite-900 border border-slate-800 text-xs text-slate-300 hover:text-white hover:bg-slate-800 transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-cyan-400' : ''}`} />
            <span>Audit Sensors</span>
          </button>
        </div>
      </div>

      {actionMessage && (
        <div className="p-3 bg-cyan-950/60 border border-cyan-800/80 rounded-lg text-xs text-cyan-200 flex items-center justify-between">
          <span>{actionMessage}</span>
          <button onClick={() => setActionMessage(null)} className="text-cyan-400 hover:text-white">
            <XCircle className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Primary Real-Time Sensor Alert Banner */}
      <div
        className={`p-5 rounded-2xl border transition-all ${
          isCameraInUse
            ? 'bg-rose-950/40 border-rose-600/80 shadow-2xl shadow-rose-950/50'
            : backgroundViolations > 0
            ? 'bg-amber-950/30 border-amber-600/60'
            : 'bg-emerald-950/20 border-emerald-500/30'
        }`}
      >
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-start space-x-3">
            <div
              className={`p-3 rounded-xl ${
                isCameraInUse
                  ? 'bg-rose-600/30 text-rose-400 animate-pulse'
                  : backgroundViolations > 0
                  ? 'bg-amber-600/30 text-amber-400'
                  : 'bg-emerald-600/20 text-emerald-400'
              }`}
            >
              {isCameraInUse ? (
                <Eye className="w-8 h-8" />
              ) : (
                <EyeOff className="w-8 h-8" />
              )}
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-sm font-bold uppercase font-mono tracking-wider text-white">
                  {isCameraInUse
                    ? '🔴 HARDWARE SENSORS ACTIVELY STREAMING'
                    : '🟢 SENSORS SECURED & STANDING GUARD'}
                </span>
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                    isCameraInUse
                      ? 'bg-rose-950 text-rose-300 border border-rose-700'
                      : 'bg-emerald-950 text-emerald-300 border border-emerald-700'
                  }`}
                >
                  {isCameraInUse ? 'RECORDING ACTIVE' : 'NO UNAUTHORIZED CAPTURE'}
                </span>
              </div>
              <p className="text-xs text-slate-300 mt-1">
                {isCameraInUse
                  ? 'An application is currently streaming camera frames. Check the active access cards below.'
                  : backgroundViolations > 0
                  ? `Identified ${backgroundViolations} background sensor activations where apps requested camera while dormant.`
                  : 'All laptop webcams and connected mobile companion sensors are currently dormant with zero unauthorized background capture.'}
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-4 border-t md:border-t-0 md:border-l border-slate-800/80 pt-3 md:pt-0 md:pl-5">
            <div className="text-center">
              <div className="text-xs text-slate-400 font-mono">BACKGROUND VIOLATIONS</div>
              <div className="text-xl font-bold text-rose-400 font-mono mt-0.5">{backgroundViolations}</div>
            </div>
            <div className="text-center">
              <div className="text-xs text-slate-400 font-mono">DEVICES AUDITED</div>
              <div className="text-xl font-bold text-white font-mono mt-0.5">{summary.total_monitored_devices || 1}</div>
            </div>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex items-center space-x-2 border-b border-slate-800 pb-3">
        <button
          onClick={() => setActiveTab('all')}
          className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition ${
            activeTab === 'all'
              ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <span>All Devices ({privacyData?.all_events?.length || 0})</span>
        </button>

        <button
          onClick={() => setActiveTab('laptop')}
          className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition ${
            activeTab === 'laptop'
              ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Laptop className="w-3.5 h-3.5" />
          <span>Laptop Webcam ({privacyData?.laptop_webcam_events?.length || 0})</span>
        </button>

        <button
          onClick={() => setActiveTab('mobile')}
          className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition ${
            activeTab === 'mobile'
              ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Smartphone className="w-3.5 h-3.5" />
          <span>Mobile Endpoints ({privacyData?.mobile_telemetry_events?.length || 0})</span>
        </button>
      </div>

      {/* Access Event Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {eventsToShow.length === 0 ? (
          <div className="col-span-full bg-graphite-900 border border-slate-800 rounded-xl p-8 text-center text-xs text-slate-500">
            No camera or microphone access events recorded.
          </div>
        ) : (
          eventsToShow.map((ev: any) => {
            const isMobile = ev.device_type?.toLowerCase().includes('mobile');
            const isCritical = ev.threat_level === 'CRITICAL';
            const isCurrentlyActive = ev.is_currently_active;

            return (
              <div
                key={ev.id}
                className={`bg-graphite-900 rounded-xl border p-4 flex flex-col justify-between space-y-3 transition shadow-lg ${
                  isCurrentlyActive
                    ? 'border-rose-500 shadow-rose-950/30'
                    : isCritical
                    ? 'border-rose-900/60'
                    : 'border-slate-800'
                }`}
              >
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center space-x-1.5">
                      {isMobile ? (
                        <Smartphone className="w-4 h-4 text-cyan-400" />
                      ) : (
                        <Laptop className="w-4 h-4 text-cyan-400" />
                      )}
                      <span className="text-xs font-mono text-slate-300">{ev.device_type}</span>
                    </div>

                    <span
                      className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                        isCurrentlyActive
                          ? 'bg-rose-950 text-rose-300 border border-rose-700 animate-pulse'
                          : ev.threat_level === 'CRITICAL'
                          ? 'bg-rose-950 text-rose-400'
                          : ev.threat_level === 'WARNING'
                          ? 'bg-amber-950 text-amber-300'
                          : ev.threat_level === 'SUSPICIOUS'
                          ? 'bg-amber-950/60 text-amber-400'
                          : 'bg-emerald-950/60 text-emerald-400'
                      }`}
                    >
                      {isCurrentlyActive ? 'CAPTURING NOW' : ev.threat_level}
                    </span>
                  </div>

                  <h3 className="text-sm font-semibold text-white truncate">{ev.app_name}</h3>
                  <div className="text-[11px] font-mono text-slate-400 truncate mt-0.5">
                    {ev.executable_path || ev.package_id || 'System Driver'}
                  </div>

                  <div className="mt-3 p-2.5 rounded bg-graphite-950 border border-slate-800/80 text-[11px] space-y-1">
                    <div className="flex justify-between text-slate-400">
                      <span>Background App:</span>
                      <span className={ev.is_background ? 'text-rose-400 font-bold' : 'text-slate-300'}>
                        {ev.is_background ? 'YES (Unauthorized)' : 'No (Foreground)'}
                      </span>
                    </div>
                    {ev.pid && (
                      <div className="flex justify-between text-slate-400 font-mono">
                        <span>PID:</span>
                        <span className="text-slate-200">{ev.pid}</span>
                      </div>
                    )}
                    {ev.last_used_start && (
                      <div className="flex justify-between text-slate-400 text-[10px]">
                        <span>Last Session:</span>
                        <span className="text-slate-300">
                          {new Date(ev.last_used_start).toLocaleTimeString()}
                        </span>
                      </div>
                    )}
                  </div>

                  {ev.threat_reason && (
                    <div
                      className={`mt-2.5 text-[11px] p-2 rounded flex items-start space-x-1.5 ${
                        isCritical
                          ? 'bg-rose-950/80 border border-rose-800/80 text-rose-300'
                          : 'bg-slate-950 text-slate-300'
                      }`}
                    >
                      <AlertOctagon className="w-3.5 h-3.5 shrink-0 mt-0.5 text-rose-400" />
                      <span>{ev.threat_reason}</span>
                    </div>
                  )}
                </div>

                {ev.pid && (
                  <div className="pt-2 border-t border-slate-800 flex justify-end">
                    <button
                      onClick={() => handleTerminateApp(ev.pid, ev.app_name)}
                      className="px-2.5 py-1 rounded bg-rose-950/80 hover:bg-rose-900 border border-rose-800 text-rose-300 text-xs font-medium transition"
                    >
                      Terminate App
                    </button>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
