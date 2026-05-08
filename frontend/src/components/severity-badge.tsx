import clsx from "clsx";

const styles: Record<string, string> = {
  Critical: "bg-red-100 text-red-800 border-red-200",
  High:     "bg-orange-100 text-orange-800 border-orange-200",
  Medium:   "bg-yellow-100 text-yellow-800 border-yellow-200",
  Low:      "bg-green-100 text-green-800 border-green-200",
};

export function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span className={clsx("inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border", styles[severity] ?? "bg-gray-100 text-gray-700 border-gray-200")}>
      {severity}
    </span>
  );
}
