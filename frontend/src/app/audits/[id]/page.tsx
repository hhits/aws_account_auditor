"use client";
import { useEffect, useState, useCallback } from "react";
import { useRouter, useParams } from "next/navigation";
import { supabase } from "@/lib/supabase";
import { api, type AuditJob, type Finding, type JobSummary } from "@/lib/api";
import { Nav } from "@/components/nav";
import { FindingsTable } from "@/components/findings-table";
import { SeverityBadge } from "@/components/severity-badge";

const SEVERITIES = ["", "Critical", "High", "Medium", "Low"];
const STATUSES   = ["", "FAIL", "WARNING", "PASS", "ERROR", "SKIPPED"];

export default function AuditDetailPage() {
  const router = useRouter();
  const { id } = useParams<{ id: string }>();

  const [job, setJob] = useState<AuditJob | null>(null);
  const [summary, setSummary] = useState<JobSummary | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [service, setService] = useState("");
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    supabase.auth.getSession().then(({ data }) => {
      if (!data.session) router.replace("/auth/login");
    });
    api.getAudit(id).then(setJob);
    api.getSummary(id).then(setSummary);
  }, [id]);

  const loadFindings = useCallback(async () => {
    setLoading(true);
    const params: Record<string, string> = { page: String(page), page_size: "50" };
    if (severity) params.severity = severity;
    if (status)   params.status   = status;
    if (service)  params.service  = service;
    const data = await api.getFindings(id, params);
    setFindings(data);
    setLoading(false);
  }, [id, severity, status, service, page]);

  useEffect(() => { loadFindings(); }, [loadFindings]);

  const services = summary ? Object.keys(summary.by_service).sort() : [];

  return (
    <>
      <Nav />
      <main className="max-w-7xl mx-auto px-6 py-8 space-y-6">
        <div className="flex items-center gap-4">
          <button onClick={() => router.back()} className="text-sm text-gray-500 hover:text-gray-800">← Back</button>
          <h1 className="text-2xl font-bold">Audit Results</h1>
          {job && <span className="text-sm text-gray-400">{new Date(job.created_at).toLocaleString()}</span>}
        </div>

        {summary && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {["Critical", "High", "Medium", "Low"].map(s => (
              <div key={s} className="bg-white rounded-xl border p-4 shadow-sm flex items-center justify-between">
                <SeverityBadge severity={s} />
                <span className="text-2xl font-bold">{summary.by_severity[s] ?? 0}</span>
              </div>
            ))}
          </div>
        )}

        {/* Filters */}
        <div className="flex flex-wrap gap-3 bg-white rounded-xl border p-4 shadow-sm">
          <select value={severity} onChange={e => { setSeverity(e.target.value); setPage(1); }}
            className="border rounded-lg px-3 py-1.5 text-sm">
            {SEVERITIES.map(s => <option key={s} value={s}>{s || "All severities"}</option>)}
          </select>
          <select value={status} onChange={e => { setStatus(e.target.value); setPage(1); }}
            className="border rounded-lg px-3 py-1.5 text-sm">
            {STATUSES.map(s => <option key={s} value={s}>{s || "All statuses"}</option>)}
          </select>
          <select value={service} onChange={e => { setService(e.target.value); setPage(1); }}
            className="border rounded-lg px-3 py-1.5 text-sm">
            <option value="">All services</option>
            {services.map(s => <option key={s} value={s}>{s}</option>)}
          </select>
          <span className="ml-auto text-sm text-gray-500 self-center">
            {summary?.total ?? 0} total findings
          </span>
        </div>

        {loading ? (
          <p className="text-gray-400 text-sm">Loading findings…</p>
        ) : (
          <FindingsTable findings={findings} />
        )}

        <div className="flex items-center gap-3">
          <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
            className="text-sm text-brand hover:underline disabled:opacity-40">Previous</button>
          <span className="text-sm text-gray-500">Page {page}</span>
          <button onClick={() => setPage(p => p + 1)} disabled={findings.length < 50}
            className="text-sm text-brand hover:underline disabled:opacity-40">Next</button>
        </div>
      </main>
    </>
  );
}
