-- SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
-- SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
-- SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Sign
-- SPDX-License-Identifier: Apache-2.0

-- Sentin8:Sign - electronic signature ceremony service.
-- Design: sentin8-sign/DESIGN.md §3 (data model).
--
-- Documents are STORAGE REFERENCES ONLY (never inline bytes); provider
-- credentials are SECRET REFERENCES ONLY; completed evidence is
-- append-only; every state transition writes its outbox event row in
-- the SAME transaction as the domain change.

CREATE SCHEMA IF NOT EXISTS sign;

-- ── Signature requests (design §3) ────────────────────────────────────────

CREATE TABLE IF NOT EXISTS sign.signature_requests (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title           TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'open'
                    CHECK (status IN ('open', 'completed', 'declined', 'expired', 'failed')),
    signature_level TEXT NOT NULL DEFAULT 'ades'
                    CHECK (signature_level IN ('ades', 'qes')),
    documents       JSONB NOT NULL,           -- [{ref, name, hash}] storage refs only
    idempotency_key TEXT,                     -- optional client-supplied create dedupe
    expires_at      TIMESTAMPTZ,              -- nullable; expiry sweep closes stale opens
    created_by      TEXT NOT NULL,
    env_id          UUID NOT NULL,
    completed_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (env_id, idempotency_key)
);

CREATE INDEX IF NOT EXISTS idx_sign_requests_env ON sign.signature_requests (env_id);
CREATE INDEX IF NOT EXISTS idx_sign_requests_env_status
    ON sign.signature_requests (env_id, status);

-- Per-signer ceremony record. Session binding is recorded at approval
-- time: approval binds to the signer's live session (same rule as
-- CIBA - replayed or cross-session approvals are rejected in the
-- handler, DESIGN.md §4 approve sequence).
CREATE TABLE IF NOT EXISTS sign.signers (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id      UUID NOT NULL REFERENCES sign.signature_requests(id) ON DELETE CASCADE,
    user_id         TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'viewed', 'signed', 'declined')),
    viewed_at       TIMESTAMPTZ,
    signed_at       TIMESTAMPTZ,
    session_id      TEXT,                      -- session binding recorded at approval
    signature_value TEXT,                      -- provider-minted signature (append-only once set)
    evidence        JSONB,                     -- provider attestation + ceremony snapshot
    env_id          UUID NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (request_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_sign_signers_request ON sign.signers (request_id);
CREATE INDEX IF NOT EXISTS idx_sign_signers_env_user ON sign.signers (env_id, user_id);

-- ── Row-Level Security (mandatory hardening - principles §4.3d) ───────────

ALTER TABLE sign.signature_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE sign.signature_requests FORCE ROW LEVEL SECURITY;
ALTER TABLE sign.signers ENABLE ROW LEVEL SECURITY;
ALTER TABLE sign.signers FORCE ROW LEVEL SECURITY;

-- Standard tenant match policy on every sign table (isolation only -
-- never business logic; db-design §7.0 binding rule).
DROP POLICY IF EXISTS requests_select ON sign.signature_requests;
CREATE POLICY requests_select ON sign.signature_requests
    FOR SELECT USING (sentin8_current_env_id() = env_id);
DROP POLICY IF EXISTS requests_insert ON sign.signature_requests;
CREATE POLICY requests_insert ON sign.signature_requests
    FOR INSERT WITH CHECK (sentin8_current_env_id() = env_id);
DROP POLICY IF EXISTS requests_update ON sign.signature_requests;
CREATE POLICY requests_update ON sign.signature_requests
    FOR UPDATE USING (sentin8_current_env_id() = env_id);
DROP POLICY IF EXISTS requests_delete ON sign.signature_requests;
CREATE POLICY requests_delete ON sign.signature_requests
    FOR DELETE USING (sentin8_current_env_id() = env_id);

DROP POLICY IF EXISTS signers_select ON sign.signers;
CREATE POLICY signers_select ON sign.signers
    FOR SELECT USING (sentin8_current_env_id() = env_id);
DROP POLICY IF EXISTS signers_insert ON sign.signers;
CREATE POLICY signers_insert ON sign.signers
    FOR INSERT WITH CHECK (sentin8_current_env_id() = env_id);
DROP POLICY IF EXISTS signers_update ON sign.signers;
CREATE POLICY signers_update ON sign.signers
    FOR UPDATE USING (sentin8_current_env_id() = env_id);
DROP POLICY IF EXISTS signers_delete ON sign.signers;
CREATE POLICY signers_delete ON sign.signers
    FOR DELETE USING (sentin8_current_env_id() = env_id);

-- ── Grants ─────────────────────────────────────────────────────────────────

GRANT USAGE ON SCHEMA sign TO sentin8_sign_service;
GRANT SELECT, INSERT, UPDATE, DELETE ON
    sign.signature_requests, sign.signers
    TO sentin8_sign_service;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA sign TO sentin8_sign_service;

-- ── Local outbox (DBX, architecture-principles §6.7) ─────────────────────
-- Producer path: sign.outbox rows commit in the SAME transaction as the
-- domain change; a post-commit relay pushes them to Bus POST /v1/produce.
-- Generated from sentin8-outbox::outbox_table_sql("sign").
CREATE TABLE IF NOT EXISTS sign.outbox (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    event_type      TEXT NOT NULL,
    stream_family   TEXT NOT NULL,
    payload         JSONB NOT NULL,
    publisher_id_token  TEXT,
    publisher_subject   TEXT,
    relayed         BOOLEAN NOT NULL DEFAULT false,
    relayed_at      TIMESTAMPTZ,
    relay_attempts  INT NOT NULL DEFAULT 0,
    next_retry_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_sign_outbox_unrelayed
    ON sign.outbox (created_at) WHERE relayed = false;
ALTER TABLE sign.outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE sign.outbox FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS outbox_select ON sign.outbox;
CREATE POLICY outbox_select ON sign.outbox FOR SELECT
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS outbox_insert ON sign.outbox;
CREATE POLICY outbox_insert ON sign.outbox FOR INSERT
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS outbox_update ON sign.outbox;
CREATE POLICY outbox_update ON sign.outbox FOR UPDATE
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
CREATE OR REPLACE FUNCTION sign.sign_notify_outbox() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    PERFORM pg_notify('sign_outbox_changed', '');
    RETURN NEW;
END;
$fn$;
DROP TRIGGER IF EXISTS outbox_notify_trigger ON sign.outbox;
CREATE TRIGGER outbox_notify_trigger
    AFTER INSERT ON sign.outbox
    FOR EACH ROW
    EXECUTE FUNCTION sign.sign_notify_outbox();

-- ── Local audit journal (DBX §6.8) ────────────────────────────────────────
-- Spill journal for the canonical audit push: rows written same-tx as the
-- domain change, pushed to Sys POST /v1/audit (sentin8:sys:audit:write), then
-- marked pushed. A Sys outage never drops audit. Generated from
-- sentin8-audit::audit_journal_sql("sign").
CREATE TABLE IF NOT EXISTS sign.audit_journal (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    action          TEXT NOT NULL,
    target_resource_type TEXT,
    target_resource_id    TEXT,
    actor_user_id   TEXT,
    actor_subject_type TEXT,
    severity        TEXT NOT NULL DEFAULT 'info',
    correlation_id  TEXT,
    before_state    JSONB,
    after_state     JSONB,
    details         JSONB,
    pushed          BOOLEAN NOT NULL DEFAULT false,
    pushed_at       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_sign_audit_journal_unpushed
    ON sign.audit_journal (created_at) WHERE pushed = false;
ALTER TABLE sign.audit_journal ENABLE ROW LEVEL SECURITY;
ALTER TABLE sign.audit_journal FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_journal_dml ON sign.audit_journal;
CREATE POLICY audit_journal_dml ON sign.audit_journal
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id())
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());

GRANT SELECT, INSERT, UPDATE, DELETE ON sign.outbox TO sentin8_sign_service;
GRANT SELECT, INSERT, UPDATE, DELETE ON sign.audit_journal TO sentin8_sign_service;