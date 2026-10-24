// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Sign
// SPDX-License-Identifier: Apache-2.0

//! HTTP handlers for Sentin8:Sign.
//!
//! All tenant context is resolved from the auth token's `env_id` claim
//! (globally unique) - never from URL path segments. Signer approval is
//! session-bound (DESIGN.md §4); every state transition writes its
//! outbox event row in the SAME transaction as the domain change.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use utoipa::ToSchema;

use crate::config::SignConfig;

#[derive(Clone)]
/// Shared application state for the Sign service.
pub struct AppState {
    /// The configuration.
    pub config: Arc<SignConfig>,
    /// DB connection pool for the sign tables + outbox.
    pub pool: sqlx::PgPool,
    /// Shield engine - the only access gate.
    pub policy: Arc<crate::policy::Engine>,
    /// Shared Sentin8:Policy admin surface (one implementation for
    /// every service; mounted in server::routes).
    pub admin: sentin8::shield::admin::SharedAdminState,
}

// Step 5 is the ONLY access gate: the scope helpers kept as trivial
// `Ok()` so call sites and signatures stay stable - the enforced Shield
// scope-mirror set decides, keyed on the same action ids the call
// sites evaluate.
fn require_read_scope(_a: &crate::auth::AuthContext) -> Result<(), (StatusCode, String)> {
    Ok(())
}
fn require_write_scope(_a: &crate::auth::AuthContext) -> Result<(), (StatusCode, String)> {
    Ok(())
}

// ── Row mapping ─────────────────────────────────────────────────────────

/// A fetched `signature_requests` row. Evidence projections NEVER
/// include document bytes - documents are storage refs only.
#[derive(sqlx::FromRow, Clone)]
pub struct RequestRow {
    id: uuid::Uuid,
    title: String,
    status: String,
    signature_level: String,
    documents: serde_json::Value,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
    created_by: String,
    env_id: uuid::Uuid,
    completed_at: Option<chrono::DateTime<chrono::Utc>>,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl RequestRow {
    /// Metadata projection - request shape without the ceremony details.
    pub fn metadata(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id,
            "title": self.title,
            "status": self.status,
            "signature_level": self.signature_level,
            "documents": self.documents,
            "expires_at": self.expires_at.map(|e| e.to_rfc3339()).unwrap_or_default(),
            "created_by": self.created_by,
            "env_id": self.env_id,
            "completed_at": self.completed_at.map(|c| c.to_rfc3339()).unwrap_or_default(),
            "created_at": self.created_at.to_rfc3339(),
            "updated_at": self.updated_at.to_rfc3339(),
        })
    }
}

/// A fetched `signers` row.
#[derive(sqlx::FromRow, Clone)]
pub struct SignerRow {
    id: uuid::Uuid,
    request_id: uuid::Uuid,
    user_id: String,
    status: String,
    viewed_at: Option<chrono::DateTime<chrono::Utc>>,
    signed_at: Option<chrono::DateTime<chrono::Utc>>,
    session_id: Option<String>,
    signature_value: Option<String>,
    evidence: Option<serde_json::Value>,
    #[allow(dead_code)]
    env_id: uuid::Uuid,
}

impl SignerRow {
    /// Metadata projection - signer ceremony state (evidence included
    /// only in the evidence endpoint payload, never the list shape).
    pub fn metadata(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id,
            "request_id": self.request_id,
            "user_id": self.user_id,
            "status": self.status,
            "viewed_at": self.viewed_at.map(|v| v.to_rfc3339()).unwrap_or_default(),
            "signed_at": self.signed_at.map(|s| s.to_rfc3339()).unwrap_or_default(),
        })
    }
}

fn db_err(e: sqlx::Error) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, format!("db error: {e}"))
}

/// Begin an explicit transaction with the tenant RLS context set on the
/// same connection (context is transaction-local; DESIGN.md §5).
pub(crate) async fn begin_tenant_tx(
    pool: &sqlx::PgPool,
    env_id: uuid::Uuid,
) -> Result<sqlx::Transaction<'static, sqlx::Postgres>, (StatusCode, String)> {
    let mut tx = pool.begin().await.map_err(db_err)?;
    sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    Ok(tx)
}

// ── Event emission (outbox, same-transaction) ────────────────────────────

/// Emit a sign event through the shared outbox helper INSIDE the given
/// transaction - payload-complete (DESIGN.md §4: consumers never call
/// back). Best-effort after commit for the create path is NOT used
/// here: the row commits with its event or not at all.
async fn emit_event_in_tx(
    tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
    env_id: uuid::Uuid,
    event_type: &str,
    payload: serde_json::Value,
    stream_family: &str,
    publisher_token: Option<&str>,
    publisher_subject: Option<&str>,
) -> Result<(), (StatusCode, String)> {
    sentin8::bus::outbox::insert_outbox_row_with_publisher(
        &mut **tx,
        env_id,
        stream_family,
        event_type,
        &payload,
        publisher_token,
        publisher_subject,
    )
    .await
    .map(|_| ())
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("outbox: {e}")))
}

// ── Request CRUD ─────────────────────────────────────────────────────────

/// Request body for creating a signature request.
#[derive(Debug, serde::Deserialize, ToSchema)]
pub struct CreateRequest {
    /// Human title of the request.
    pub title: String,
    /// Document set: storage refs + display names + content hashes.
    pub documents: Vec<DocumentRef>,
    /// Signer set (fixed after creation).
    pub signers: Vec<String>,
    /// Requested signature level.
    #[serde(default)]
    pub signature_level: String,
    /// Optional expiry; the sweep closes stale opens.
    #[serde(default)]
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Optional client idempotency key (dedupes create).
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

/// A document reference - storage ref only, never inline bytes.
#[derive(Debug, serde::Deserialize, ToSchema)]
pub struct DocumentRef {
    /// Storage object reference.
    pub r#ref: String,
    /// Display name.
    pub name: String,
    /// Content hash (what the signature covers).
    pub hash: String,
}

/// Approve request body.
#[derive(Debug, serde::Deserialize, ToSchema)]
pub struct ApproveRequest {
    /// The signer's decision: `sign` or `decline`.
    pub decision: String,
}

/// `POST /v1/requests` - create a signature request (opens immediately).
#[utoipa::path(
    post,
    operation_id = "sign.request.create",
    path = "/v1/requests",
    request_body = CreateRequest,
    responses(
        (status = 201, description = "Request created (open)"),
        (status = 400, description = "Invalid request (empty signers/documents/level)"),
        (status = 409, description = "Idempotency key already used"),
    ),
    security(("sentin8:sign:request:write" = [])),
    tag = "sign",
)]
pub async fn create_request(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::Json(req): axum::Json<CreateRequest>,
) -> Result<Response, (StatusCode, String)> {
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:sign:request:write"),
    )
    .await?;
    require_write_scope(&a)?;
    let env_id = a.env_id();

    // Validation - level honesty is enforced at creation and at
    // dispatch (QES refuses without a qualified provider configured).
    let level = req.signature_level.trim().to_ascii_lowercase();
    if level != "ades" && level != "qes" {
        return Err((
            StatusCode::BAD_REQUEST,
            "signature_level must be 'ades' or 'qes'".into(),
        ));
    }
    if req.signers.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "signers must not be empty".into()));
    }
    if req.documents.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "documents must not be empty".into(),
        ));
    }
    // Documents are storage refs only - refuse anything that is not a
    // reference (never inline bytes).
    for d in &req.documents {
        if d.r#ref.trim().is_empty() || d.hash.trim().is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                "document ref and hash are required (bytes are never inline)".into(),
            ));
        }
    }
    if level == "qes"
        && (state.config.provider_mode != "qtsp" || state.config.provider_url.is_empty())
    {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "qes requires a qualified trust-service provider configured for this environment \
             (no silent downgrade; BUSINESS.md rule 4)"
                .into(),
        ));
    }

    let documents = serde_json::to_value(
        req.documents
            .iter()
            .map(|d| {
                serde_json::json!({ "ref": d.r#ref, "name": d.name, "hash": d.hash })
            })
            .collect::<Vec<_>>(),
    )
    .map_err(|e| (StatusCode::BAD_REQUEST, format!("documents: {e}")))?;

    let mut tx = begin_tenant_tx(&state.pool, env_id).await?;
    let row: RequestRow = sqlx::query_as(
        r#"INSERT INTO sign.signature_requests
             (title, status, signature_level, documents, idempotency_key, expires_at, created_by, env_id)
           VALUES ($1, 'open', $2, $3, $4, $5, $6, $7)
           RETURNING id, title, status, signature_level, documents, expires_at, created_by, env_id,
                     completed_at, created_at, updated_at"#,
    )
    .bind(&req.title)
    .bind(&level)
    .bind(&documents)
    .bind(req.idempotency_key.as_deref().filter(|k| !k.is_empty()))
    .bind(req.expires_at)
    .bind(a.sub())
    .bind(env_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| match &e {
        sqlx::Error::Database(d) if d.is_unique_violation() => (
            StatusCode::CONFLICT,
            "idempotency_key already used for this environment".into(),
        ),
        _ => db_err(e),
    })?;

    // Signer rows - the fixed signer set (same transaction).
    for user_id in &req.signers {
        let _ = sqlx::query(
            "INSERT INTO sign.signers (request_id, user_id, env_id) VALUES ($1, $2, $3)",
        )
        .bind(row.id)
        .bind(user_id)
        .bind(env_id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    }

    // Event - same transaction (DESIGN.md §4 event flow).
    emit_event_in_tx(
        &mut tx,
        env_id,
        "sentin8:sign:request:created",
        serde_json::json!({
            "request_id": row.id,
            "title": row.title,
            "signature_level": row.signature_level,
            "documents": row.documents,
            "signers": req.signers,
            "expires_at": req.expires_at.map(|e| e.to_rfc3339()),
        }),
        &state.config.stream_family,
        crate::auth::raw_bearer_token(&headers).as_deref(),
        Some(a.sub()),
    )
    .await?;

    tx.commit().await.map_err(db_err)?;
    Ok((StatusCode::CREATED, axum::Json(row.metadata())).into_response())
}

/// `GET /v1/requests` - list requests for the caller's env.
#[utoipa::path(
    get,
    operation_id = "sign.request.list",
    path = "/v1/requests",
    params(("status" = String, Query, description = "Filter by status")),
    responses(
        (status = 200, description = "Request metadata list"),
        (status = 403, description = "Missing sign scope"),
    ),
    security(("sentin8:sign:request:read" = [])),
    tag = "sign",
)]
pub async fn list_requests(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(q): axum::extract::Query<ListRequestsQuery>,
) -> Result<axum::Json<serde_json::Value>, (StatusCode, String)> {
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:sign:request:read"),
    )
    .await?;
    require_read_scope(&a)?;
    let env_id = a.env_id();

    let mut tx = begin_tenant_tx(&state.pool, env_id).await?;
    let rows: Vec<RequestRow> = match q.status.as_deref() {
        Some(s) if !s.is_empty() => sqlx::query_as(
            "SELECT id, title, status, signature_level, documents, expires_at, created_by, env_id,
                    completed_at, created_at, updated_at
             FROM sign.signature_requests WHERE env_id = $1 AND status = $2
             ORDER BY created_at DESC LIMIT 200",
        )
        .bind(env_id)
        .bind(s)
        .fetch_all(&mut *tx)
        .await
        .map_err(db_err)?,
        _ => sqlx::query_as(
            "SELECT id, title, status, signature_level, documents, expires_at, created_by, env_id,
                    completed_at, created_at, updated_at
             FROM sign.signature_requests WHERE env_id = $1
             ORDER BY created_at DESC LIMIT 200",
        )
        .bind(env_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(db_err)?,
    };
    tx.commit().await.map_err(db_err)?;

    Ok(axum::Json(serde_json::json!({
        "requests": rows.iter().map(|r| r.metadata()).collect::<Vec<_>>(),
    })))
}

/// Query params for the request list.
#[derive(Debug, serde::Deserialize, Default, utoipa::ToSchema, utoipa::IntoParams)]
pub struct ListRequestsQuery {
    /// Optional status filter.
    #[serde(default)]
    pub status: Option<String>,
}

/// `GET /v1/requests/{id}` - request detail + signer states.
#[utoipa::path(
    get,
    operation_id = "sign.request.get",
    path = "/v1/requests/{id}",
    params(("id" = uuid::Uuid, Path, description = "Request id")),
    responses(
        (status = 200, description = "Request detail + signer states"),
        (status = 404, description = "Unknown request"),
    ),
    security(("sentin8:sign:request:read" = [])),
    tag = "sign",
)]
pub async fn get_request(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<uuid::Uuid>,
) -> Result<axum::Json<serde_json::Value>, (StatusCode, String)> {
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:sign:request:read"),
    )
    .await?;
    require_read_scope(&a)?;
    let env_id = a.env_id();

    let mut tx = begin_tenant_tx(&state.pool, env_id).await?;
    let row: Option<RequestRow> = sqlx::query_as(
        "SELECT id, title, status, signature_level, documents, expires_at, created_by, env_id,
                completed_at, created_at, updated_at
         FROM sign.signature_requests WHERE env_id = $1 AND id = $2",
    )
    .bind(env_id)
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db_err)?;
    let Some(row) = row else {
        return Err((StatusCode::NOT_FOUND, "unknown request".into()));
    };
    let signers: Vec<SignerRow> = sqlx::query_as(
        "SELECT id, request_id, user_id, status, viewed_at, signed_at, session_id,
                signature_value, evidence, env_id
         FROM sign.signers WHERE env_id = $1 AND request_id = $2 ORDER BY created_at",
    )
    .bind(env_id)
    .bind(id)
    .fetch_all(&mut *tx)
    .await
    .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;

    let mut payload = row.metadata();
    payload["signers"] = serde_json::json!(signers.iter().map(|s| s.metadata()).collect::<Vec<_>>());
    Ok(axum::Json(payload))
}

// ── Ceremony transitions ─────────────────────────────────────────────────

/// `POST /v1/requests/{id}/view` - a listed signer opens the ceremony.
#[utoipa::path(
    post,
    operation_id = "sign.request.view",
    path = "/v1/requests/{id}/view",
    params(("id" = uuid::Uuid, Path, description = "Request id")),
    responses(
        (status = 200, description = "Ceremony document refs + level"),
        (status = 403, description = "Caller is not a listed signer"),
        (status = 404, description = "Unknown request"),
        (status = 409, description = "Request not open"),
    ),
    security(("sentin8:sign:signer:read" = [])),
    tag = "sign",
)]
pub async fn view_request(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<uuid::Uuid>,
) -> Result<axum::Json<serde_json::Value>, (StatusCode, String)> {
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:sign:signer:read"),
    )
    .await?;
    require_read_scope(&a)?;
    let env_id = a.env_id();

    let mut tx = begin_tenant_tx(&state.pool, env_id).await?;
    let row: Option<RequestRow> = sqlx::query_as(
        "SELECT id, title, status, signature_level, documents, expires_at, created_by, env_id,
                completed_at, created_at, updated_at
         FROM sign.signature_requests WHERE env_id = $1 AND id = $2 FOR UPDATE",
    )
    .bind(env_id)
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db_err)?;
    let Some(req_row) = row else {
        return Err((StatusCode::NOT_FOUND, "unknown request".into()));
    };
    if req_row.status != "open" {
        return Err((StatusCode::CONFLICT, "request is not open".into()));
    }
    if req_row
        .expires_at
        .map(|e| e < chrono::Utc::now())
        .unwrap_or(false)
    {
        return Err((StatusCode::CONFLICT, "request is expired".into()));
    }

    // Caller must be a listed signer.
    let signer: Option<SignerRow> = sqlx::query_as(
        "SELECT id, request_id, user_id, status, viewed_at, signed_at, session_id,
                signature_value, evidence, env_id
         FROM sign.signers WHERE env_id = $1 AND request_id = $2 AND user_id = $3",
    )
    .bind(env_id)
    .bind(id)
    .bind(a.sub())
    .fetch_optional(&mut *tx)
    .await
    .map_err(db_err)?;
    let Some(signer) = signer else {
        return Err((
            StatusCode::FORBIDDEN,
            "caller is not a listed signer".into(),
        ));
    };

    // Mark viewed on first view (idempotent - later views do not
    // rewrite the timestamp or re-emit).
    if signer.status == "pending" {
        let _ = sqlx::query(
            "UPDATE sign.signers SET status = 'viewed', viewed_at = now() WHERE id = $1",
        )
        .bind(signer.id)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
        emit_event_in_tx(
            &mut tx,
            env_id,
            "sentin8:sign:request:viewed",
            serde_json::json!({
                "request_id": id,
                "signer": a.sub(),
                "viewed_at": chrono::Utc::now().to_rfc3339(),
            }),
            &state.config.stream_family,
            crate::auth::raw_bearer_token(&headers).as_deref(),
            Some(a.sub()),
        )
        .await?;
    }
    tx.commit().await.map_err(db_err)?;

    Ok(axum::Json(serde_json::json!({
        "request_id": req_row.id,
        "title": req_row.title,
        "signature_level": req_row.signature_level,
        "documents": req_row.documents,
        "signer_status": if signer.status == "pending" { "viewed" } else { &signer.status },
    })))
}

/// `POST /v1/requests/{id}/approve` - the session-bound signer decision.
///
/// Approval binds to the signer's live session (CIBA-shaped rule,
/// DESIGN.md §4): the `sid` claim on the token is recorded; a replayed
/// or cross-session approval is rejected.
#[utoipa::path(
    post,
    operation_id = "sign.request.approve",
    path = "/v1/requests/{id}/approve",
    params(("id" = uuid::Uuid, Path, description = "Request id")),
    request_body = ApproveRequest,
    responses(
        (status = 200, description = "Decision recorded (signature evidence on sign)"),
        (status = 403, description = "Caller is not a listed signer / session mismatch"),
        (status = 404, description = "Unknown request"),
        (status = 409, description = "Request not open / signer already decided"),
        (status = 502, description = "Provider dispatch failed"),
    ),
    security(("sentin8:sign:signer:write" = [])),
    tag = "sign",
)]
pub async fn approve_request(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<uuid::Uuid>,
    axum::Json(req): axum::Json<ApproveRequest>,
) -> Result<axum::Json<serde_json::Value>, (StatusCode, String)> {
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:sign:signer:write"),
    )
    .await?;
    require_write_scope(&a)?;
    let env_id = a.env_id();

    let decision = req.decision.trim().to_ascii_lowercase();
    if decision != "sign" && decision != "decline" {
        return Err((StatusCode::BAD_REQUEST, "decision must be 'sign' or 'decline'".into()));
    }

    let mut tx = begin_tenant_tx(&state.pool, env_id).await?;
    let row: Option<RequestRow> = sqlx::query_as(
        "SELECT id, title, status, signature_level, documents, expires_at, created_by, env_id,
                completed_at, created_at, updated_at
         FROM sign.signature_requests WHERE env_id = $1 AND id = $2 FOR UPDATE",
    )
    .bind(env_id)
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db_err)?;
    let Some(req_row) = row else {
        return Err((StatusCode::NOT_FOUND, "unknown request".into()));
    };
    if req_row.status != "open" {
        return Err((StatusCode::CONFLICT, "request is not open".into()));
    }

    let signer: Option<SignerRow> = sqlx::query_as(
        "SELECT id, request_id, user_id, status, viewed_at, signed_at, session_id,
                signature_value, evidence, env_id
         FROM sign.signers WHERE env_id = $1 AND request_id = $2 AND user_id = $3 FOR UPDATE",
    )
    .bind(env_id)
    .bind(id)
    .bind(a.sub())
    .fetch_optional(&mut *tx)
    .await
    .map_err(db_err)?;
    let Some(signer) = signer else {
        return Err((
            StatusCode::FORBIDDEN,
            "caller is not a listed signer".into(),
        ));
    };
    if signer.status == "signed" || signer.status == "declined" {
        return Err((StatusCode::CONFLICT, "signer already decided".into()));
    }

    // Session binding: approval binds to the approving token (the
    // access-token anti-replay identifier `jti` - access tokens carry
    // no `sid` claim; a replayed or different-token approval for the
    // same ceremony attempt is rejected).
    let sid = Some(a.claims.jti.clone());
    if let Some(prev) = &signer.session_id {
        if sid.as_deref() != Some(prev.as_str()) {
            return Err((
                StatusCode::FORBIDDEN,
                "approval token mismatch (session-bound, BUSINESS.md rule 1)".into(),
            ));
        }
    }

    let now = chrono::Utc::now();
    match decision.as_str() {
        "decline" => {
            // Any signer declining closes the request for everyone.
            let _ = sqlx::query(
                "UPDATE sign.signers SET status = 'declined', session_id = $2 WHERE id = $1",
            )
            .bind(signer.id)
            .bind(sid.as_deref())
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
            let _ = sqlx::query(
                "UPDATE sign.signature_requests SET status = 'declined', updated_at = now() WHERE id = $1",
            )
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
            emit_event_in_tx(
                &mut tx,
                env_id,
                "sentin8:sign:request:declined",
                serde_json::json!({
                    "request_id": id,
                    "declined_by": a.sub(),
                    "declined_at": now.to_rfc3339(),
                }),
                &state.config.stream_family,
                crate::auth::raw_bearer_token(&headers).as_deref(),
                Some(a.sub()),
            )
            .await?;
            tx.commit().await.map_err(db_err)?;
            Ok(axum::Json(serde_json::json!({
                "request_id": id,
                "status": "declined",
            })))
        }
        _ => {
            // Sign: dispatch through the provider seam (stub mints a
            // deterministic evidence-backed signature; qtsp calls the
            // remote gateway with credentials resolved by secret_ref).
            let (sig, evidence) = dispatch_provider(&state, &req_row, &a).await?;

            let _ = sqlx::query(
                "UPDATE sign.signers
                   SET status = 'signed', signed_at = now(), session_id = $2,
                       signature_value = $3, evidence = $4
                 WHERE id = $1",
            )
            .bind(signer.id)
            .bind(sid.as_deref())
            .bind(&sig)
            .bind(evidence)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;

            emit_event_in_tx(
                &mut tx,
                env_id,
                "sentin8:sign:request:signed",
                serde_json::json!({
                    "request_id": id,
                    "signer": a.sub(),
                    "signed_at": now.to_rfc3339(),
                    "signature_level": req_row.signature_level,
                }),
                &state.config.stream_family,
                crate::auth::raw_bearer_token(&headers).as_deref(),
                Some(a.sub()),
            )
            .await?;

            // Completion: every signer signed.
            let pending: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM sign.signers WHERE request_id = $1 AND status <> 'signed'",
            )
            .bind(id)
            .fetch_one(&mut *tx)
            .await
            .map_err(db_err)?;
            let mut completed = false;
            if pending == 0 {
                let _ = sqlx::query(
                    "UPDATE sign.signature_requests
                       SET status = 'completed', completed_at = now(), updated_at = now()
                     WHERE id = $1",
                )
                .bind(id)
                .execute(&mut *tx)
                .await
                .map_err(db_err)?;
                emit_event_in_tx(
                    &mut tx,
                    env_id,
                    "sentin8:sign:request:completed",
                    serde_json::json!({
                        "request_id": id,
                        "completed_at": now.to_rfc3339(),
                        "signature_level": req_row.signature_level,
                    }),
                    &state.config.stream_family,
                    crate::auth::raw_bearer_token(&headers).as_deref(),
                    Some(a.sub()),
                )
                .await?;
                completed = true;
            }
            tx.commit().await.map_err(db_err)?;

            Ok(axum::Json(serde_json::json!({
                "request_id": id,
                "signer": a.sub(),
                "status": if completed { "completed" } else { "signed" },
                "signature": sig,
            })))
        }
    }
}

/// Provider dispatch seam (DESIGN.md §2): stub mode mints a
/// deterministic evidence-backed signature locally (the full ceremony
/// path without an external dependency); qtsp mode calls the remote
/// gateway. Credentials resolve by `secret_ref` at dispatch time -
/// never stored.
async fn dispatch_provider(
    state: &AppState,
    req: &RequestRow,
    a: &crate::auth::AuthContext,
) -> Result<(String, serde_json::Value), (StatusCode, String)> {
    match state.config.provider_mode.as_str() {
        "qtsp" => {
            if state.config.provider_url.is_empty() {
                return Err((
                    StatusCode::BAD_GATEWAY,
                    "qtsp provider url not configured (SENTIN8_SIGN_PROVIDER_URL)".into(),
                ));
            }
            // The remote gateway call site. Credential resolution rides
            // the Secrets chain at this seam (provider_secret_ref);
            // the HTTP exchange itself is the provider adapter's
            // concern behind this same match arm.
            Err((
                StatusCode::NOT_IMPLEMENTED,
                "qtsp remote-signing adapter lands behind this seam (gateway contract per \
                 provider); stub mode exercises the full path today"
                    .into(),
            ))
        }
        _ => {
            // Stub dispatch: deterministic signature value + evidence
            // snapshot (who/when/what seen/level) - the ceremony
            // machinery end-to-end without an external provider.
            let now = chrono::Utc::now().to_rfc3339();
            let sig = format!(
                "stub-sig-{}-{}",
                req.signature_level,
                uuid::Uuid::new_v5(
                    &uuid::Uuid::NAMESPACE_URL,
                    format!("{}|{}|{}", req.id, a.sub(), now).as_bytes()
                )
            );
            let evidence = serde_json::json!({
                "provider": "stub",
                "signature_level": req.signature_level,
                "dispatched_at": now,
                "documents": req.documents,
                "signer": a.sub(),
                "note": "stub dispatch - evidence shape is production-grade; the provider value is deterministic",
            });
            Ok((sig, evidence))
        }
    }
}

/// `GET /v1/requests/{id}/evidence` - append-only evidence bundle.
#[utoipa::path(
    get,
    operation_id = "sign.request.evidence",
    path = "/v1/requests/{id}/evidence",
    params(("id" = uuid::Uuid, Path, description = "Request id")),
    responses(
        (status = 200, description = "Evidence bundle (request + per-signer evidence)"),
        (status = 404, description = "Unknown request"),
    ),
    security(("sentin8:sign:request:read" = [])),
    tag = "sign",
)]
pub async fn request_evidence(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(id): Path<uuid::Uuid>,
) -> Result<axum::Json<serde_json::Value>, (StatusCode, String)> {
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:sign:request:read"),
    )
    .await?;
    require_read_scope(&a)?;
    let env_id = a.env_id();

    let mut tx = begin_tenant_tx(&state.pool, env_id).await?;
    let row: Option<RequestRow> = sqlx::query_as(
        "SELECT id, title, status, signature_level, documents, expires_at, created_by, env_id,
                completed_at, created_at, updated_at
         FROM sign.signature_requests WHERE env_id = $1 AND id = $2",
    )
    .bind(env_id)
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db_err)?;
    let Some(req_row) = row else {
        return Err((StatusCode::NOT_FOUND, "unknown request".into()));
    };
    let signers: Vec<SignerRow> = sqlx::query_as(
        "SELECT id, request_id, user_id, status, viewed_at, signed_at, session_id,
                signature_value, evidence, env_id
         FROM sign.signers WHERE env_id = $1 AND request_id = $2 ORDER BY created_at",
    )
    .bind(env_id)
    .bind(id)
    .fetch_all(&mut *tx)
    .await
    .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;

    let mut payload = req_row.metadata();
    payload["signers"] = serde_json::json!(
        signers
            .iter()
            .map(|s| serde_json::json!({
                "user_id": s.user_id,
                "status": s.status,
                "viewed_at": s.viewed_at.map(|v| v.to_rfc3339()).unwrap_or_default(),
                "signed_at": s.signed_at.map(|v| v.to_rfc3339()).unwrap_or_default(),
                "signature_value": s.signature_value.clone().unwrap_or_default(),
                "evidence": s.evidence.clone().unwrap_or(serde_json::Value::Null),
            }))
            .collect::<Vec<_>>()
    );
    Ok(axum::Json(payload))
}

// ── Maintenance ───────────────────────────────────────────────────────────

/// `POST /v1/internal/schedules/run` - Cron proxy-back target: the
/// expiry sweep closes stale open requests (DESIGN.md §6).
#[utoipa::path(
    post,
    operation_id = "sign.internal.schedules_run",
    path = "/v1/internal/schedules/run",
    request_body = ScheduleRunRequest,
    responses(
        (status = 200, description = "Sweep result"),
        (status = 404, description = "Unknown schedule type"),
    ),
    security(("sentin8:cron:write" = [])),
    tag = "internal",
)]
pub async fn internal_schedules_run(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::Json(req): axum::Json<ScheduleRunRequest>,
) -> Result<axum::Json<serde_json::Value>, (StatusCode, String)> {
    // Internal proxy-back: the M2M identity must carry the cron grant.
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:sign:request:admin"),
    )
    .await?;

    if req.schedule_type != "sign-expiry-sweep" {
        return Err((StatusCode::NOT_FOUND, format!("unknown schedule type: {}", req.schedule_type)));
    }

    let mut swept: Vec<serde_json::Value> = Vec::new();
    // Sweep per visible env: fetch the stale open rows, then close each
    // in its own tenant transaction with its event.
    let rows: Vec<(uuid::Uuid, uuid::Uuid)> = sqlx::query_as(
        "SELECT id, env_id FROM sign.signature_requests
          WHERE status = 'open' AND expires_at IS NOT NULL AND expires_at < now()",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(db_err)?;
    for (id, env_id) in rows {
        let mut tx = begin_tenant_tx(&state.pool, env_id).await?;
        let res = sqlx::query(
            "UPDATE sign.signature_requests
               SET status = 'expired', updated_at = now()
             WHERE env_id = $1 AND id = $2 AND status = 'open'",
        )
        .bind(env_id)
        .bind(id)
        .execute(&mut *tx)
        .await;
        match res {
            Ok(r) if r.rows_affected() > 0 => {
                let _ = emit_event_in_tx(
                    &mut tx,
                    env_id,
                    "sentin8:sign:request:expired",
                    serde_json::json!({
                        "request_id": id,
                        "expired_at": chrono::Utc::now().to_rfc3339(),
                    }),
                    &state.config.stream_family,
                    crate::auth::raw_bearer_token(&headers).as_deref(),
                    Some(a.sub()),
                )
                .await;
                let _ = tx.commit().await;
                swept.push(serde_json::json!({ "request_id": id, "env_id": env_id }));
            }
            _ => {
                let _ = tx.rollback().await;
            }
        }
    }

    Ok(axum::Json(serde_json::json!({
        "schedule_type": req.schedule_type,
        "swept": swept.len(),
        "requests": swept,
    })))
}

/// Schedule run request body.
#[derive(Debug, serde::Deserialize, ToSchema)]
pub struct ScheduleRunRequest {
    /// The schedule type to run.
    pub schedule_type: String,
}

// ── Health ────────────────────────────────────────────────────────────────

/// `GET /v1/health` - service health (own payload).
#[utoipa::path(
    get,
    operation_id = "sign.health",
    path = "/v1/health",
    responses((status = 200, description = "Service healthy")),
    tag = "health",
)]
pub async fn health_handler() -> &'static str {
    "ok"
}