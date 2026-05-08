-- Run this in your Supabase SQL editor or against your PostgreSQL instance.
-- Supabase already manages the auth.users table.

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS aws_configs (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL UNIQUE REFERENCES auth.users(id) ON DELETE CASCADE,
    deployer_role_arn       TEXT NOT NULL,
    deployer_external_id    TEXT NOT NULL,
    audit_role_name         TEXT NOT NULL DEFAULT 'AuditRole',
    audit_role_external_id  TEXT NOT NULL,
    regions        TEXT[]   NOT NULL DEFAULT ARRAY['us-east-1','us-east-2','us-west-1','us-west-2'],
    use_organizations BOOLEAN NOT NULL DEFAULT FALSE,
    enabled_audits TEXT[]   NOT NULL DEFAULT ARRAY['iam','network','exposure','cloudtrail','security_hub','cost_optimization','cyber'],
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS aws_accounts (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    account_id  TEXT NOT NULL,
    account_name TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, account_id)
);

CREATE TABLE IF NOT EXISTS audit_jobs (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id          UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    status           TEXT NOT NULL DEFAULT 'pending',
    started_at       TIMESTAMPTZ,
    completed_at     TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    accounts_audited TEXT[]  NOT NULL DEFAULT '{}',
    total_findings   INTEGER NOT NULL DEFAULT 0,
    error_message    TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id          UUID NOT NULL REFERENCES audit_jobs(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    account_id      TEXT NOT NULL,
    region          TEXT NOT NULL DEFAULT '',
    service         TEXT NOT NULL DEFAULT '',
    check_name      TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT '',
    severity        TEXT NOT NULL DEFAULT 'Low',
    finding_type    TEXT NOT NULL DEFAULT '',
    details         TEXT NOT NULL DEFAULT '',
    recommendation  TEXT NOT NULL DEFAULT '',
    timestamp       TIMESTAMPTZ,
    compliance      JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_findings_job_id   ON findings(job_id);
CREATE INDEX IF NOT EXISTS idx_findings_user_id  ON findings(user_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_audit_jobs_user   ON audit_jobs(user_id);

-- Row-level security: users only see their own data
ALTER TABLE aws_configs    ENABLE ROW LEVEL SECURITY;
ALTER TABLE aws_accounts   ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_jobs     ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings       ENABLE ROW LEVEL SECURITY;

CREATE POLICY "own_config"   ON aws_configs   USING (auth.uid() = user_id);
CREATE POLICY "own_accounts" ON aws_accounts  USING (auth.uid() = user_id);
CREATE POLICY "own_jobs"     ON audit_jobs    USING (auth.uid() = user_id);
CREATE POLICY "own_findings" ON findings      USING (auth.uid() = user_id);
