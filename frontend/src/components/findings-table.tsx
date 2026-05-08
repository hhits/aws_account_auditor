"use client";
import { useState } from "react";
import type { Finding } from "@/lib/api";
import { SeverityBadge } from "./severity-badge";

interface Props {
  findings: Finding[];
}

const STATUS_COLOR: Record<string, string> = {
  FAIL:    "text-red-700",
  WARNING: "text-yellow-700",
  PASS:    "text-green-700",
  ERROR:   "text-gray-500",
  SKIPPED: "text-gray-400",
};

export function FindingsTable({ findings }: Props) {
  const [expanded, setExpanded] = useState<string | null>(null);

  if (!findings.length) {
    return <p className="text-gray-500 text-sm py-4">No findings match the current filters.</p>;
  }

  return (
    <div className="overflow-x-auto rounded-xl border">
      <table className="min-w-full divide-y divide-gray-200 text-sm">
        <thead className="bg-gray-50">
          <tr>
            {["Account", "Region", "Service", "Check", "Status", "Severity", "Details"].map(h => (
              <th key={h} className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">{h}</th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-100 bg-white">
          {findings.map(f => (
            <>
              <tr key={f.id} className="hover:bg-gray-50 cursor-pointer" onClick={() => setExpanded(expanded === f.id ? null : f.id)}>
                <td className="px-4 py-3 font-mono text-xs">{f.account_id}</td>
                <td className="px-4 py-3 text-xs">{f.region}</td>
                <td className="px-4 py-3 font-medium">{f.service}</td>
                <td className="px-4 py-3 text-xs text-gray-700">{f.check_name}</td>
                <td className={`px-4 py-3 font-semibold text-xs ${STATUS_COLOR[f.status] ?? ""}`}>{f.status}</td>
                <td className="px-4 py-3"><SeverityBadge severity={f.severity} /></td>
                <td className="px-4 py-3 max-w-xs truncate text-gray-600">{f.details}</td>
              </tr>
              {expanded === f.id && (
                <tr key={`${f.id}-detail`} className="bg-blue-50">
                  <td colSpan={7} className="px-6 py-4 text-sm space-y-2">
                    <p><span className="font-semibold">Details:</span> {f.details}</p>
                    <p><span className="font-semibold">Recommendation:</span> {f.recommendation}</p>
                    {Object.keys(f.compliance).length > 0 && (
                      <p><span className="font-semibold">Compliance:</span> {JSON.stringify(f.compliance)}</p>
                    )}
                  </td>
                </tr>
              )}
            </>
          ))}
        </tbody>
      </table>
    </div>
  );
}
