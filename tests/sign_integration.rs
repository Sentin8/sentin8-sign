// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Sign
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for Sentin8:Sign.
//!
//! DB-backed tests run against a provisioned PostgreSQL (testing-strategy
//! §3): infra up + the sign SQL applied, then run. Naming follows
//! `[layer_]area_behavior` with the `sec_` security prefix.

use sqlx::PgPool;

/// Provision: connect + tenant context helper. Returns the pool and the
/// test env id (a fresh env per run keeps rows isolated).
async fn provision() -> Option<PgPool> {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sentin8@localhost:5432/sentin8".into());
    let pool = PgPool::connect(&url).await.ok()?;
    // Skip silently when not provisioned (CI without infra).
    if sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = 'signature_requests'",
    )
    .fetch_one(&pool)
    .await
    .ok()?
        == 0
    {
        return None;
    }
    Some(pool)
}

/// Set tenant context inside a pool transaction (context is
/// transaction-local) and return it. The transaction owns its
/// connection for its lifetime.
async fn set_ctx(pool: &PgPool, env_id: uuid::Uuid) -> sqlx::Transaction<'static, sqlx::Postgres> {
    let mut tx = pool.begin().await.expect("tx");
    sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *tx)
        .await
        .expect("set tenant context");
    tx
}

// ── sec_sign_rls_env_isolation ───────────────────────────────────────────

#[tokio::test]
async fn sec_sign_rls_env_isolation() {
    // RLS: a row from env A is invisible inside env B's context.
    let Some(pool) = provision().await else {
        return;
    };
    let env_a = uuid::Uuid::new_v4();
    let env_b = uuid::Uuid::new_v4();

    // Write a request inside env A.
    let mut tx = set_ctx(&pool, env_a).await;
    let id: uuid::Uuid = sqlx::query_scalar(
        r#"INSERT INTO sign.signature_requests
             (title, status, signature_level, documents, created_by, env_id)
         VALUES ('isolation-test', 'open', 'ades', '[{"ref":"storage://doc"}]'::jsonb,
                 'tester', $1)
         RETURNING id"#,
    )
    .bind(env_a)
    .fetch_one(&mut *tx)
    .await
    .expect("insert in env A");
    tx.commit().await.expect("commit A");

    // Read inside env B - the row must be invisible.
    let mut tx = set_ctx(&pool, env_b).await;
    let seen: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sign.signature_requests WHERE id = $1",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    .expect("count in env B");
    tx.commit().await.expect("commit B");
    assert_eq!(seen, 0, "RLS must isolate signature requests per env");
}

// ── sign_request_state_transitions ───────────────────────────────────────

#[tokio::test]
async fn sign_request_state_transitions() {
    let Some(pool) = provision().await else {
        return;
    };
    let env_id = uuid::Uuid::new_v4();

    // Create open request + two signers in one tx (the handler shape).
    let mut tx = set_ctx(&pool, env_id).await;
    let (id,): (uuid::Uuid,) = sqlx::query_as(
        r#"INSERT INTO sign.signature_requests
             (title, status, signature_level, documents, created_by, env_id)
         VALUES ('state-test', 'open', 'ades', '[{"ref":"storage://doc"}]'::jsonb,
                 'tester', $1)
         RETURNING id"#,
    )
    .bind(env_id)
    .fetch_one(&mut *tx)
    .await
    .expect("insert request");
    for user in ["alice", "bob"] {
        sqlx::query("INSERT INTO sign.signers (request_id, user_id, env_id) VALUES ($1, $2, $3)")
            .bind(id)
            .bind(user)
            .bind(env_id)
            .execute(&mut *tx)
            .await
            .expect("insert signer");
    }
    tx.commit().await.expect("commit");

    // Alice signs -> still open (one pending).
    let mut tx = set_ctx(&pool, env_id).await;
    sqlx::query(
        "UPDATE sign.signers SET status = 'signed', signed_at = now(), session_id = 'sess-1',
             signature_value = 'sig-a', evidence = '{}'::jsonb
         WHERE request_id = $1 AND user_id = 'alice'",
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .expect("alice signs");
    let pending: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sign.signers WHERE request_id = $1 AND status <> 'signed'",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    .expect("pending count");
    assert_eq!(pending, 1);
    tx.commit().await.expect("commit");

    // Bob signs -> completion flips the request.
    let mut tx = set_ctx(&pool, env_id).await;
    sqlx::query(
        "UPDATE sign.signers SET status = 'signed', signed_at = now(), session_id = 'sess-2',
             signature_value = 'sig-b', evidence = '{}'::jsonb
         WHERE request_id = $1 AND user_id = 'bob'",
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .expect("bob signs");
    let pending: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sign.signers WHERE request_id = $1 AND status <> 'signed'",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    .expect("pending count 2");
    assert_eq!(pending, 0, "all signers signed");
    sqlx::query(
        "UPDATE sign.signature_requests SET status = 'completed', completed_at = now() WHERE id = $1",
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .expect("complete");
    let status: String = sqlx::query_scalar(
        "SELECT status FROM sign.signature_requests WHERE id = $1",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    .expect("status read");
    tx.commit().await.expect("commit 2");
    assert_eq!(status, "completed");
}

// ── sec_sign_signer_uniqueness ───────────────────────────────────────────

#[tokio::test]
async fn sec_sign_signer_uniqueness() {
    // The signer set is fixed after creation: duplicate (request, user)
    // pairs are rejected by the unique constraint.
    let Some(pool) = provision().await else {
        return;
    };
    let env_id = uuid::Uuid::new_v4();
    let mut tx = set_ctx(&pool, env_id).await;
    let (id,): (uuid::Uuid,) = sqlx::query_as(
        r#"INSERT INTO sign.signature_requests
             (title, status, signature_level, documents, created_by, env_id)
         VALUES ('unique-test', 'open', 'ades', '[{"ref":"storage://doc"}]'::jsonb,
                 'tester', $1)
         RETURNING id"#,
    )
    .bind(env_id)
    .fetch_one(&mut *tx)
    .await
    .expect("insert request");
    sqlx::query("INSERT INTO sign.signers (request_id, user_id, env_id) VALUES ($1, 'alice', $2)")
        .bind(id)
        .bind(env_id)
        .execute(&mut *tx)
        .await
        .expect("insert signer");
    let dup = sqlx::query(
        "INSERT INTO sign.signers (request_id, user_id, env_id) VALUES ($1, 'alice', $2)",
    )
    .bind(id)
    .bind(env_id)
    .execute(&mut *tx)
    .await;
    assert!(dup.is_err(), "duplicate signer must be rejected");
}

// ── sec_sign_idempotency_key_dedupe ─────────────────────────────────────

#[tokio::test]
async fn sec_sign_idempotency_key_dedupe() {
    let Some(pool) = provision().await else {
        return;
    };
    let env_id = uuid::Uuid::new_v4();
    let mut tx = set_ctx(&pool, env_id).await;
    sqlx::query(
        r#"INSERT INTO sign.signature_requests
             (title, status, signature_level, documents, idempotency_key, created_by, env_id)
         VALUES ('idem-test', 'open', 'ades', '[{"ref":"storage://doc"}]'::jsonb,
                 'idem-1', 'tester', $1)"#,
    )
    .bind(env_id)
    .execute(&mut *tx)
    .await
    .expect("first insert");
    let dup = sqlx::query(
        r#"INSERT INTO sign.signature_requests
             (title, status, signature_level, documents, idempotency_key, created_by, env_id)
         VALUES ('idem-test-2', 'open', 'ades', '[{"ref":"storage://doc"}]'::jsonb,
                 'idem-1', 'tester', $1)"#,
    )
    .bind(env_id)
    .execute(&mut *tx)
    .await;
    assert!(dup.is_err(), "idempotency key reuse must be rejected");
}

// ── sign_contract_event_shape ─────────────────────────────────────────────

#[test]
fn sign_contract_event_shape() {
    // The consumer contract: the SignEvent payload parses the exact
    // shape the handlers emit (payload-complete; no call-backs).
    let ev = sentin8_sign::SignEvent {
        request_id: uuid::Uuid::new_v4(),
        signer: Some("alice".into()),
        signature_level: sentin8_sign::SignatureLevel::Qes.as_str().into(),
        at: chrono::Utc::now().to_rfc3339(),
        documents: None,
        signers: None,
    };
    let json = serde_json::to_value(&ev).expect("serialize");
    assert_eq!(json["signature_level"], "qes");
    assert!(json["documents"].is_null());
    let back: sentin8_sign::SignEvent =
        serde_json::from_value(json).expect("deserialize round trip");
    assert_eq!(back.signer.as_deref(), Some("alice"));
}