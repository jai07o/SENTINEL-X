import React, { useEffect, useState } from 'react';
import { ApiClient } from '../api/client';
import { SecurityReport } from '../types';
import { FileText, Plus, Download, Eye, X, RefreshCw } from 'lucide-react';

export const ReportsPage: React.FC = () => {
  const [reports, setReports] = useState<SecurityReport[]>([]);
  const [isGenerating, setIsGenerating] = useState(false);
  const [title, setTitle] = useState('');
  const [reportType, setReportType] = useState('INCIDENT_DOSSIER');
  const [viewingReport, setViewingReport] = useState<any | null>(null);

  const fetchReports = async () => {
    try {
      const data = await ApiClient.getReports();
      setReports(data || []);
    } catch (err) {
      console.error('Failed to load reports', err);
    }
  };

  useEffect(() => {
    fetchReports();
  }, []);

  const handleGenerateReport = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await ApiClient.generateReport(title, reportType);
      setIsGenerating(false);
      setTitle('');
      fetchReports();
    } catch (err: any) {
      alert(`Error generating report: ${err.message}`);
    }
  };

  const handleViewReport = async (id: string) => {
    try {
      const content = await ApiClient.getReportContent(id);
      setViewingReport(content);
    } catch (err) {
      console.error('Failed to load report content', err);
    }
  };

  const handleDownloadMarkdown = (report: any) => {
    const element = document.createElement('a');
    const file = new Blob([report.content_markdown], { type: 'text/markdown' });
    element.href = URL.createObjectURL(file);
    element.download = `${report.report_number}_Report.md`;
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center space-x-2">
            <FileText className="w-5 h-5 text-cyan-400" />
            <span>Security Reports & Investigation Dossiers</span>
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Exportable incident dossiers, vulnerability assessments, and digital forensics case reports.
          </p>
        </div>

        <button
          onClick={() => setIsGenerating(true)}
          className="flex items-center space-x-1.5 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-md text-xs font-medium transition-colors"
        >
          <Plus className="w-3.5 h-3.5" />
          <span>Generate Security Report</span>
        </button>
      </div>

      {/* Modal */}
      {isGenerating && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <form onSubmit={handleGenerateReport} className="bg-graphite-900 border border-slate-800 rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <h2 className="text-sm font-bold text-white uppercase tracking-wider font-mono">Generate Security Report</h2>
            <div>
              <label className="block text-xs text-slate-300 mb-1">Report Title</label>
              <input
                type="text"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                required
                placeholder="e.g., Q4 Security Operations Review"
                className="w-full bg-graphite-950 border border-slate-800 rounded px-3 py-1.5 text-xs text-white focus:outline-none focus:border-cyan-500"
              />
            </div>
            <div>
              <label className="block text-xs text-slate-300 mb-1">Dossier Classification Type</label>
              <select
                value={reportType}
                onChange={(e) => setReportType(e.target.value)}
                className="w-full bg-graphite-950 border border-slate-800 rounded px-3 py-1.5 text-xs text-white font-mono"
              >
                <option value="INCIDENT_DOSSIER">Incident Investigation Dossier</option>
                <option value="VULN_ASSESSMENT">Vulnerability Assessment Report</option>
                <option value="FORENSIC_CASE">Forensic Evidence Case Report</option>
                <option value="COMPLIANCE_SUMMARY">Compliance & Fleet Posture Summary</option>
              </select>
            </div>
            <div className="flex justify-end space-x-2 pt-2">
              <button
                type="button"
                onClick={() => setIsGenerating(false)}
                className="px-3 py-1.5 bg-slate-800 text-slate-300 rounded text-xs"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded text-xs font-medium"
              >
                Generate Report
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Reports List */}
      <div className="bg-graphite-900 border border-slate-800 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left table-dense">
            <thead>
              <tr>
                <th>Report #</th>
                <th>Title</th>
                <th>Type</th>
                <th>Created At</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {reports.length === 0 ? (
                <tr>
                  <td colSpan={5} className="text-center py-8 text-xs text-slate-500">
                    No reports generated yet. Click 'Generate Security Report' to create an exportable dossier.
                  </td>
                </tr>
              ) : (
                reports.map((r) => (
                  <tr key={r.id} className="hover:bg-slate-800/30">
                    <td className="font-mono text-cyan-400 font-bold text-xs">{r.report_number}</td>
                    <td className="font-semibold text-slate-200">{r.title}</td>
                    <td>
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono text-xs">
                        {r.report_type}
                      </span>
                    </td>
                    <td className="font-mono text-xs text-slate-400">
                      {new Date(r.created_at).toLocaleString()}
                    </td>
                    <td>
                      <button
                        onClick={() => handleViewReport(r.id)}
                        className="p-1 hover:bg-slate-800 rounded text-cyan-400 mr-2"
                        title="View Report Content"
                      >
                        <Eye className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Report Viewing Modal */}
      {viewingReport && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-graphite-900 border border-slate-800 rounded-xl max-w-3xl w-full max-h-[85vh] flex flex-col shadow-2xl">
            <div className="flex items-center justify-between p-4 border-b border-slate-800">
              <div>
                <h3 className="text-sm font-semibold text-white">{viewingReport.title}</h3>
                <span className="font-mono text-xs text-cyan-400">{viewingReport.report_number}</span>
              </div>
              <div className="flex items-center space-x-2">
                <button
                  onClick={() => handleDownloadMarkdown(viewingReport)}
                  className="flex items-center space-x-1 px-2.5 py-1 bg-cyan-950 border border-cyan-500/40 text-cyan-300 rounded text-xs font-mono hover:bg-cyan-900"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Download .md</span>
                </button>
                <button
                  onClick={() => setViewingReport(null)}
                  className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>

            <div className="p-4 overflow-y-auto">
              <pre className="p-4 bg-graphite-950 rounded-lg text-xs font-mono text-slate-300 overflow-x-auto whitespace-pre-wrap">
                {viewingReport.content_markdown}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
