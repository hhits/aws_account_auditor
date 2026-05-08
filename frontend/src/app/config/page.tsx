"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { supabase } from "@/lib/supabase";
import { api, type AwsConfigIn, type AwsAccount } from "@/lib/api";
import { Nav } from "@/components/nav";

const ALL_REGIONS = ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-southeast-1", "ap-northeast-1"];
const ALL_AUDITS  = ["iam", "network", "exposure", "cloudtrail", "security_hub", "cost_optimization", "cyber"];

const DEFAULT_CONFIG: AwsConfigIn = {
  deployer_role_arn: "",
  deployer_external_id: "",
  audit_role_name: "AuditRole",
  audit_role_external_id: "audit-access",
  regions: ["us-east-1", "us-east-2", "us-west-1", "us-west-2"],
  use_organizations: false,
  enabled_audits: [...ALL_AUDITS],
};

export default function ConfigPage() {
  const router = useRouter();
  const [config, setConfig] = useState<AwsConfigIn>(DEFAULT_CONFIG);
  const [accounts, setAccounts] = useState<AwsAccount[]>([]);
  const [newAccountId, setNewAccountId] = useState("");
  const [newAccountName, setNewAccountName] = useState("");
  const [saving, setSaving] = useState(false);
  const [addingAccount, setAddingAccount] = useState(false);
  const [msg, setMsg] = useState<{ type: "ok" | "err"; text: string } | null>(null);

  useEffect(() => {
    supabase.auth.getSession().then(({ data }) => {
      if (!data.session) { router.replace("/auth/login"); return; }
    });
    api.getConfig().then(c => setConfig({
      deployer_role_arn: c.deployer_role_arn,
      deployer_external_id: c.deployer_external_id,
      audit_role_name: c.audit_role_name,
      audit_role_external_id: c.audit_role_external_id,
      regions: c.regions,
      use_organizations: c.use_organizations,
      enabled_audits: c.enabled_audits,
    })).catch(() => {/* first time user, keep defaults */});
    api.listAccounts().then(setAccounts).catch(() => {});
  }, []);

  function toggleItem<T>(arr: T[], item: T): T[] {
    return arr.includes(item) ? arr.filter(x => x !== item) : [...arr, item];
  }

  async function saveConfig(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true); setMsg(null);
    try {
      await api.saveConfig(config);
      setMsg({ type: "ok", text: "Configuration saved." });
    } catch (err: unknown) {
      setMsg({ type: "err", text: err instanceof Error ? err.message : "Save failed" });
    } finally { setSaving(false); }
  }

  async function addAccount(e: React.FormEvent) {
    e.preventDefault();
    setAddingAccount(true);
    try {
      const acc = await api.addAccount({ account_id: newAccountId.trim(), account_name: newAccountName.trim() });
      setAccounts(prev => [...prev, acc]);
      setNewAccountId(""); setNewAccountName("");
    } catch (err: unknown) {
      setMsg({ type: "err", text: err instanceof Error ? err.message : "Failed to add account" });
    } finally { setAddingAccount(false); }
  }

  async function removeAccount(accountId: string) {
    await api.removeAccount(accountId);
    setAccounts(prev => prev.filter(a => a.account_id !== accountId));
  }

  return (
    <>
      <Nav />
      <main className="max-w-3xl mx-auto px-6 py-8 space-y-8">
        <h1 className="text-2xl font-bold">Settings</h1>

        {msg && (
          <p className={`text-sm rounded-lg p-3 ${msg.type === "ok" ? "bg-green-50 text-green-800" : "bg-red-50 text-red-700"}`}>
            {msg.text}
          </p>
        )}

        {/* AWS Role Config */}
        <div className="bg-white rounded-xl border shadow-sm p-6 space-y-4">
          <h2 className="font-semibold text-lg">AWS Role Configuration</h2>
          <p className="text-sm text-gray-500">
            Deploy the <code className="bg-gray-100 px-1 rounded">auditrole_stackset_template.yaml</code> to your accounts,
            then create an <strong>AuditDeployer</strong> role in your management account that trusts this SaaS app.
          </p>
          <form onSubmit={saveConfig} className="space-y-4">
            <Field label="Deployer Role ARN" hint="arn:aws:iam::MGMT_ACCOUNT:role/AuditDeployer">
              <input required value={config.deployer_role_arn}
                onChange={e => setConfig(c => ({ ...c, deployer_role_arn: e.target.value }))}
                placeholder="arn:aws:iam::123456789012:role/AuditDeployer"
                className="input" />
            </Field>
            <Field label="Deployer ExternalId" hint="Secret value configured in the deployer role trust policy">
              <input required value={config.deployer_external_id}
                onChange={e => setConfig(c => ({ ...c, deployer_external_id: e.target.value }))}
                className="input" />
            </Field>
            <div className="grid grid-cols-2 gap-4">
              <Field label="Audit Role Name">
                <input required value={config.audit_role_name}
                  onChange={e => setConfig(c => ({ ...c, audit_role_name: e.target.value }))}
                  className="input" />
              </Field>
              <Field label="Audit Role ExternalId">
                <input required value={config.audit_role_external_id}
                  onChange={e => setConfig(c => ({ ...c, audit_role_external_id: e.target.value }))}
                  className="input" />
              </Field>
            </div>

            <Field label="Regions">
              <div className="flex flex-wrap gap-2">
                {ALL_REGIONS.map(r => (
                  <label key={r} className="flex items-center gap-1 text-sm cursor-pointer">
                    <input type="checkbox" checked={config.regions.includes(r)}
                      onChange={() => setConfig(c => ({ ...c, regions: toggleItem(c.regions, r) }))} />
                    {r}
                  </label>
                ))}
              </div>
            </Field>

            <Field label="Audit Modules">
              <div className="flex flex-wrap gap-2">
                {ALL_AUDITS.map(a => (
                  <label key={a} className="flex items-center gap-1 text-sm cursor-pointer">
                    <input type="checkbox" checked={config.enabled_audits.includes(a)}
                      onChange={() => setConfig(c => ({ ...c, enabled_audits: toggleItem(c.enabled_audits, a) }))} />
                    {a}
                  </label>
                ))}
              </div>
            </Field>

            <label className="flex items-center gap-2 text-sm cursor-pointer">
              <input type="checkbox" checked={config.use_organizations}
                onChange={e => setConfig(c => ({ ...c, use_organizations: e.target.checked }))} />
              Discover accounts from AWS Organizations automatically
            </label>

            <button type="submit" disabled={saving}
              className="bg-brand text-white px-5 py-2 rounded-lg font-medium hover:bg-brand-dark disabled:opacity-50">
              {saving ? "Saving…" : "Save Configuration"}
            </button>
          </form>
        </div>

        {/* Account List */}
        {!config.use_organizations && (
          <div className="bg-white rounded-xl border shadow-sm p-6 space-y-4">
            <h2 className="font-semibold text-lg">AWS Accounts</h2>
            <form onSubmit={addAccount} className="flex gap-2">
              <input required value={newAccountId} onChange={e => setNewAccountId(e.target.value)}
                placeholder="Account ID (12 digits)" className="input flex-1" pattern="\d{12}" />
              <input value={newAccountName} onChange={e => setNewAccountName(e.target.value)}
                placeholder="Label (optional)" className="input w-40" />
              <button type="submit" disabled={addingAccount}
                className="bg-brand text-white px-4 py-2 rounded-lg font-medium hover:bg-brand-dark disabled:opacity-50">
                Add
              </button>
            </form>
            <ul className="divide-y">
              {accounts.length === 0 && <p className="text-sm text-gray-500">No accounts added yet.</p>}
              {accounts.map(a => (
                <li key={a.id} className="flex items-center justify-between py-2">
                  <div>
                    <span className="font-mono text-sm">{a.account_id}</span>
                    {a.account_name && <span className="ml-2 text-gray-500 text-sm">{a.account_name}</span>}
                  </div>
                  <button onClick={() => removeAccount(a.account_id)}
                    className="text-red-500 hover:text-red-700 text-sm">Remove</button>
                </li>
              ))}
            </ul>
          </div>
        )}
      </main>
      <style jsx global>{`.input { width: 100%; border: 1px solid #d1d5db; border-radius: 0.5rem; padding: 0.5rem 0.75rem; font-size: 0.875rem; outline: none; } .input:focus { ring: 2px; ring-color: #2563eb; border-color: #2563eb; }`}</style>
    </>
  );
}

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <div>
      <label className="block text-sm font-medium mb-1">{label}</label>
      {hint && <p className="text-xs text-gray-400 mb-1">{hint}</p>}
      {children}
    </div>
  );
}
