"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { supabase } from "@/lib/supabase";
import { api, type AuditJob } from "@/lib/api";
import { Nav } from "@/components/nav";
import Link from "next/link";

export default function AuditsPage() {
  const router = useRouter();
  const [jobs, setJobs] = useState<AuditJob[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    supabase.auth.getSession().then(({ data }) => {
      if (!data.session) { router.replace("/auth/login"); return; }
    });
    api.listAudits().then(data => { setJobs(data); setLoading(false); });
  }, []);

  const statusStyle: Record<string, string> = {
    completed: "bg-green-100 text-green-800",
    running:   "bg-blue-100 text-blue-800",
    pending:   "bg-yellow-100 text-yellow-800",
    failed:    "bg-red-100 text-red-800",
  };

  return (
    <>
      <Nav />
      <main className="max-w-5xl mx-auto px-6 py-8 space-y-6">
        <h1 className="text-2xl font-bold">Audit History</h1>
        <div className="bg-white rounded-xl border shadow-sm overflow-hidden">
          <table className="min-w-full divide-y divide-gray-200 text-sm">
            <thead className="bg-gray-50">
              <tr>
                {["Started", "Status", "Accounts", "Findings", "Duration", ""].map(h => (
                  <th key={h} className="px-5 py-3 text-left text-xs font-semibold text-gray-500 uppercase">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100 bg-white">
              {loading && <tr><td colSpan={6} className="px-5 py-6 text-center text-gray-400">Loading…</td></tr>}
              {!loading && jobs.length === 0 && (
                <tr><td colSpan={6} className="px-5 py-6 text-center text-gray-400">No audits yet.</td></tr>
              )}
              {jobs.map(job => {
                const duration = job.started_at && job.completed_at
                  ? Math.round((new Date(job.completed_at).getTime() - new Date(job.started_at).getTime()) / 1000)
                  : null;
                return (
                  <tr key={job.id} className="hover:bg-gray-50">
                    <td className="px-5 py-4">{new Date(job.created_at).toLocaleString()}</td>
                    <td className="px-5 py-4">
                      <span className={`text-xs font-medium px-2 py-1 rounded-full ${statusStyle[job.status] ?? "bg-gray-100 text-gray-700"}`}>
                        {job.status}
                      </span>
                    </td>
                    <td className="px-5 py-4">{job.accounts_audited.length}</td>
                    <td className="px-5 py-4 font-semibold">{job.total_findings}</td>
                    <td className="px-5 py-4 text-gray-500">{duration != null ? `${duration}s` : "—"}</td>
                    <td className="px-5 py-4">
                      {job.status === "completed" && (
                        <Link href={`/audits/${job.id}`} className="text-brand text-sm hover:underline">View</Link>
                      )}
                      {job.error_message && (
                        <span className="text-xs text-red-600 truncate max-w-xs block" title={job.error_message}>
                          {job.error_message}
                        </span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </main>
    </>
  );
}
