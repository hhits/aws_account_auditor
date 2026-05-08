"use client";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { supabase } from "@/lib/supabase";
import clsx from "clsx";

const links = [
  { href: "/dashboard", label: "Dashboard" },
  { href: "/audits",    label: "Audits"    },
  { href: "/config",    label: "Settings"  },
];

export function Nav() {
  const pathname = usePathname();
  const router   = useRouter();

  async function signOut() {
    await supabase.auth.signOut();
    router.replace("/auth/login");
  }

  return (
    <nav className="bg-white border-b px-6 py-3 flex items-center justify-between">
      <div className="flex items-center gap-6">
        <span className="font-bold text-brand text-lg">AWS Auditor</span>
        {links.map(l => (
          <Link key={l.href} href={l.href}
            className={clsx("text-sm font-medium transition-colors",
              pathname.startsWith(l.href) ? "text-brand" : "text-gray-600 hover:text-gray-900")}>
            {l.label}
          </Link>
        ))}
      </div>
      <button onClick={signOut} className="text-sm text-gray-500 hover:text-gray-800">Sign out</button>
    </nav>
  );
}
