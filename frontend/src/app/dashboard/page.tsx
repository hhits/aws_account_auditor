"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { supabase } from "@/lib/supabase";
import { api, type AuditJob, type JobSummary } from "@/lib/api";
import { Nav } from "@/components/nav";
import { SeverityBadge } from "@/components/severity-badge";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from "recharts";

const SEV_COLORS: Record<string, string> = { Critical: "#dc2626", High: "#f97316", Medium: "#eab308", Low: "#22c55e" };

export default function DashboardPage() {
  const router = useRouter();
  const [jobs, setJobs] = useState<AuditJob[]>([]);
  const [summary, setSummary] = useState<JobSummary | null>(null);
  const [triggering, setTriggering] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    supabase.auth.getSession().then(({ data }) => {
      if (!data.session) router.replace("/auth/login");
    });
    loadJobs();
  }, []);

  async function loadJobs() {
    try {
      const data = await api.listAudits();
      setJobs(data);
      const latest = data.find(j => j.status === "completed");
      if (latest) setSummary(await api.getSummary(latest.id));
    } catch {
      setError("Failed to load audits");
    }
  }

  async function triggerAudit() {
    setTriggering(true);
    setError("");
    try {
      await api.triggerAudit();
      await loadJobs();
      // Poll until running job completes
      const poll = setInterval(async () => {
        const fresh = await api.listAudits();
        setJobs(fresh);
        const running = fresh.find(j => j.status === "pending" || j.status === "running");
        if (!running) {
          clearInterval(poll);
          setTriggering(false);
          const latest = fresh.find(j => j.status === "completed");
          if (latest) setSummary(await api.getSummary(latest.id));
        }
      }, 5000);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to start audit");
      setTriggering(false);
    }
  }

  const sevData = summary
    ? ["Critical", "High", "Medium", "Low"].map(s => ({ name: s, count: summary.by_severity[s] ?? 0 }))
    : [];

  return (
    <>
      <Nav />
      <main className="max-w-6xl mx-auto px-6 py-8 space-y-8">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-bold">Dashboard</h1>
          <button onClick={triggerAudit} disabled={triggering}
            className="bg-brand text-white px-4 py-2 rounded-lg font-medium hover:bg-brand-dark disabled:opacity-50 flex items-center gap-2">
            {triggering ? "Running audit…" : "Run New Audit"}
          </button>
        </div>

        {error && <p className="text-red-600 bg-red-50 rounded-lg p-3 text-sm">{error}</p>}

        {summary && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {sevData.map(({ name, count }) => (
              <div key={name} className="bg-white rounded-xl border p-4 shadow-sm">
                <p className="text-sm text-gray-500 mb-1">{name}</p>
                <p className="text-3xl font-bold" style={{ color: SEV_COLORS[name] }}>{count}</p>
              </div>
            ))}
          </div>
        )}

        {sevData.length > 0 && (
          <div className="bg-white rounded-xl border p-6 shadow-sm">
            <h2 className="font-semibold mb-4">Findings by Severity</h2>
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={sevData}>
                <XAxis dataKey="name" />
                <YAxis allowDecimals={false} />
                <Tooltip />
                <Bar dataKey="count">
                  {sevData.map(({ name }) => <Cell key={name} fill={SEV_COLORS[name]} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}

        <div className="bg-white rounded-xl border shadow-sm">
          <div className="px-6 py-4 border-b">
            <h2 className="font-semibold">Recent Audits</h2>
          </div>
          <div className="divide-y">
            {jobs.length === 0 && <p className="px-6 py-4 text-sm text-gray-500">No audits yet. Click Run New Audit to get started.</p>}
            {jobs.map(job => (
              <div key={job.id} className="px-6 py-4 flex items-center justify-between hover:bg-gray-50">
                <div>
                  <p className="text-sm font-medium">{new Date(job.created_at).toLocaleString()}</p>
                  <p className="text-xs text-gray-500">{job.accounts_audited.length} accounts · {job.total_findings} findings</p>
                </div>
                <div className="flex items-center gap-3">
                  <StatusBadge status={job.status} />
                  {job.status === "completed" && (
                    <a href={`/audits/${job.id}`} className="text-sm text-brand hover:underline">View</a>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      </main>
    </>
  );
}

function StatusBadge({ status }: { status: string }) {
  const cls: Record<string, string> = {
    completed: "bg-green-100 text-green-800",
    running:   "bg-blue-100 text-blue-800",
    pending:   "bg-yellow-100 text-yellow-800",
    failed:    "bg-red-100 text-red-800",
  };
  return <span className={`text-xs font-medium px-2 py-1 rounded-full ${cls[status] ?? "bg-gray-100 text-gray-700"}`}>{status}</span>;
}
