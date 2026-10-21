import React, { useEffect, useState } from 'react';
import { ApiClient } from '../api/client';
import { EvidenceItem, ForensicCase } from '../types';
import { Fingerprint, CheckCircle2, AlertTriangle, ShieldCheck, RefreshCw, Upload, Clock } from 'lucide-react';

export const EvidenceViewerPage: React.FC = () => {
  const [evidenceList, setEvidenceList] = useState<EvidenceItem[]>([]);
  const [cases, setCases] = useState<ForensicCase[]>([]);
  const [verificationResults, setVerificationResults] = useState<{ [id: string]: { isValid: boolean; hash: string } }>({});
  const [isVerifying, setIsVerifying] = useState<{ [id: string]: boolean }>({});
  const [isIntaking, setIsIntaking] = useState(false);
  
  // Intake form
  const [selectedCaseId, setSelectedCaseId] = useState('');
  const [name, setName] = useState('');
  const [sourceDesc, setSourceDesc] = useState('');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);

  const fetchEvidence = async () => {
    try {
      const caseData: ForensicCase[] = await ApiClient.getForensicCases();
      setCases(caseData || []);
      const allEvidence: EvidenceItem[] = [];
      for (const c of caseData) {
        if (c.evidence_items) {
          allEvidence.push(...c.evidence_items);
        }
      }
      setEvidenceList(allEvidence);
      if (caseData.length > 0 && !selectedCaseId) {
        setSelectedCaseId(caseData[0].id);
      }
    } catch (err) {
      console.error('Failed to load evidence items', err);
    }
  };

  useEffect(() => {
    fetchEvidence();
  }, []);

  const handleVerifyIntegrity = async (evidenceId: string) => {
    setIsVerifying((prev) => ({ ...prev, [evidenceId]: true }));
    try {
      const res = await ApiClient.verifyEvidenceHash(evidenceId);
      setVerificationResults((prev) => ({
        ...prev,
        [evidenceId]: { isValid: res.is_integrity_valid, hash: res.calculated_sha256 },
      }));
    } catch (err) {
      console.error('Verification failed', err);
    } finally {
      setIsVerifying((prev) => ({ ...prev, [evidenceId]: false }));
    }
  };

  const handleIntakeEvidence = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedCaseId || !selectedFile) return;

    try {
      await ApiClient.intakeEvidence(selectedCaseId, name, sourceDesc, selectedFile);
      setIsIntaking(false);
      setName('');
      setSourceDesc('');
      setSelectedFile(null);
      fetchEvidence();
    } catch (err: any) {
      alert(`Evidence intake error: ${err.message}`);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center space-x-2">
            <Fingerprint className="w-5 h-5 text-cyan-400" />
            <span>Digital Evidence Vault & Chain of Custody</span>
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Tamper-evident read-only vault with deterministic SHA-256 integrity verification and custody logs.
          </p>
        </div>

        <button
          onClick={() => setIsIntaking(true)}
          className="flex items-center space-x-1.5 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-md text-xs font-medium transition-colors"
        >
          <Upload className="w-3.5 h-3.5" />
          <span>Intake Evidence Item</span>
        </button>
      </div>

      {/* Intake Modal */}
      {isIntaking && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <form onSubmit={handleIntakeEvidence} className="bg-graphite-900 border border-slate-800 rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <h2 className="text-sm font-bold text-white uppercase tracking-wider font-mono">Evidence Vault Intake</h2>
            <div>
              <label className="block text-xs text-slate-300 mb-1">Target Forensic Case</label>
              <select
                value={selectedCaseId}
                onChange={(e) => setSelectedCaseId(e.target.value)}
                required
                className="w-full bg-graphite-950 border border-slate-800 rounded px-3 py-1.5 text-xs text-white font-mono"
              >
                {cases.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.case_number} — {c.title}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-xs text-slate-300 mb-1">Evidence Label</label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
                placeholder="e.g., Target Host Volatile RAM Dump"
                className="w-full bg-graphite-950 border border-slate-800 rounded px-3 py-1.5 text-xs text-white focus:outline-none focus:border-cyan-500"
              />
            </div>
            <div>
              <label className="block text-xs text-slate-300 mb-1">Source Description & Acquisition Context</label>
              <textarea
                value={sourceDesc}
                onChange={(e) => setSourceDesc(e.target.value)}
                required
                rows={2}
                placeholder="Acquired live via LiME /proc/kcore from ubuntu-srv01."
                className="w-full bg-graphite-950 border border-slate-800 rounded px-3 py-1.5 text-xs text-white focus:outline-none focus:border-cyan-500"
              />
            </div>
            <div>
              <label className="block text-xs text-slate-300 mb-1">Evidence File</label>
              <input
                type="file"
                onChange={(e) => setSelectedFile(e.target.files?.[0] || null)}
                required
                className="w-full text-xs text-slate-400 file:mr-3 file:py-1.5 file:px-3 file:rounded file:border-0 file:bg-slate-800 file:text-cyan-400 font-mono"
              />
            </div>
            <div className="flex justify-end space-x-2 pt-2">
              <button
                type="button"
                onClick={() => setIsIntaking(false)}
                className="px-3 py-1.5 bg-slate-800 text-slate-300 rounded text-xs"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded text-xs font-medium"
              >
                Store in Vault
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Notice Banner */}
      <div className="p-3 bg-graphite-900 border border-slate-800 rounded-lg text-xs text-slate-400 flex items-start space-x-2.5">
        <ShieldCheck className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
        <div>
          <span className="font-semibold text-slate-200">Forensic Integrity Guarantee:</span> Cryptographic SHA-256 hashes detect any subsequent tampering or bit rot, but do not independently prove original authenticity. All vault items are mounted with read-only attributes.
        </div>
      </div>

      {/* Evidence Items */}
      <div className="space-y-4">
        {evidenceList.length === 0 ? (
          <div className="p-8 bg-graphite-900 border border-dashed border-slate-800 rounded-lg text-center text-xs text-slate-500">
            Evidence vault empty. Intake an evidence file to calculate initial cryptographic hashes and start the custody ledger.
          </div>
        ) : (
          evidenceList.map((item) => {
            const result = verificationResults[item.id];
            const verifying = isVerifying[item.id];

            return (
              <div key={item.id} className="bg-graphite-900 border border-slate-800 rounded-lg p-5 space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
                  <div className="flex items-center space-x-2">
                    <span className="font-mono text-cyan-400 font-bold text-xs">{item.evidence_number}</span>
                    <h3 className="text-sm font-semibold text-white">{item.name}</h3>
                  </div>

                  <div className="flex items-center space-x-2">
                    <button
                      onClick={() => handleVerifyIntegrity(item.id)}
                      disabled={verifying}
                      className="flex items-center space-x-1.5 px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs font-mono border border-slate-700 transition-colors"
                    >
                      <RefreshCw className={`w-3 h-3 ${verifying ? 'animate-spin' : ''}`} />
                      <span>{verifying ? 'Verifying...' : 'Verify Cryptographic Hash'}</span>
                    </button>
                  </div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono">
                  <div className="bg-graphite-950 p-3 rounded border border-slate-800 space-y-1">
                    <div className="text-slate-500 uppercase text-[10px]">Intake Fingerprint (SHA-256)</div>
                    <div className="text-cyan-300 truncate">{item.sha256_hash}</div>
                    <div className="text-slate-400 text-[11px]">Size: {(item.file_size_bytes / 1024).toFixed(1)} KB</div>
                  </div>

                  <div className="bg-graphite-950 p-3 rounded border border-slate-800 space-y-1">
                    <div className="text-slate-500 uppercase text-[10px]">Disk Integrity Status</div>
                    {result ? (
                      <div className="flex items-center space-x-2 mt-0.5">
                        {result.isValid ? (
                          <span className="text-emerald-400 flex items-center space-x-1 font-bold">
                            <CheckCircle2 className="w-4 h-4 shrink-0" />
                            <span>HASH MATCHES ORIGINAL (NO TAMPERING)</span>
                          </span>
                        ) : (
                          <span className="text-rose-400 flex items-center space-x-1 font-bold">
                            <AlertTriangle className="w-4 h-4 shrink-0" />
                            <span>TAMPERING DETECTED! DISK MISMATCH</span>
                          </span>
                        )}
                      </div>
                    ) : (
                      <span className="text-slate-500 text-xs">Ready for verification query.</span>
                    )}
                  </div>
                </div>

                {/* Chain of Custody Records */}
                {item.custody_records && item.custody_records.length > 0 && (
                  <div className="pt-2 border-t border-slate-800">
                    <span className="text-[10px] font-mono uppercase text-slate-500 font-semibold mb-2 block">
                      Chain of Custody Ledger ({item.custody_records.length} records)
                    </span>
                    <div className="space-y-1.5">
                      {item.custody_records.map((rec) => (
                        <div key={rec.id} className="p-2 bg-graphite-950 rounded border border-slate-800/80 flex items-center justify-between text-xs">
                          <div className="flex items-center space-x-2 font-mono">
                            <span className="px-1.5 py-0.5 bg-slate-800 text-cyan-300 rounded text-[10px]">
                              {rec.action}
                            </span>
                            <span className="text-slate-300">{rec.notes}</span>
                          </div>
                          <span className="font-mono text-[10px] text-slate-500">
                            {new Date(rec.timestamp).toLocaleTimeString()}
                          </span>
                        </div>
                      ))}
                    </div>
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
