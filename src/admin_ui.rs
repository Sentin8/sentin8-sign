// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Sign
// SPDX-License-Identifier: Apache-2.0

//! Sentin8:Sign Admin UI handlers - RFW definitions.
//! Served from `GET /v1/admin/ui/{page}`, rendered by Sentin8:Dash at runtime.

use crate::handlers::AppState;
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use sentin8::rfw::page::*;
use sentin8::rfw::response::AdminUiResponse;
use sentin8::rfw::widget::*;
use serde::Deserialize;

/// Resolve the effective env_id for admin operations.
/// Priority: target_env_id query param (BFF proxy) > x-sentin8-env-id
/// header (TLS) > token env_id. Cross-env access is validated at the
/// authorization layer.
#[derive(Deserialize, Default, utoipa::IntoParams, utoipa::ToSchema)]
pub struct TargetEnvQuery {
    #[serde(default)]
    target_env_id: Option<String>,
}

/// Resolve the effective env and authorize it: if the resolved env
/// differs from the token env, the caller must be a platform/env
/// admin. Otherwise 403.
fn resolve_env_id(
    headers: &HeaderMap,
    query: &TargetEnvQuery,
    a: &crate::auth::AuthContext,
) -> Result<String, (StatusCode, String)> {
    let requested = query
        .target_env_id
        .as_deref()
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .or_else(|| {
            headers
                .get("x-sentin8-env-id")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| uuid::Uuid::parse_str(s).ok())
        });
    let token_env = a.env_id();
    match requested {
        Some(env) if env != token_env => {
            if a.has_scope("sentin8:sys:admin")
                || a.has_scope("sentin8:sys:env:admin")
                || a.has_scope("sentin8:sys:org:admin")
            {
                Ok(env.to_string())
            } else {
                Err((
                    StatusCode::FORBIDDEN,
                    "caller has no role in the target environment".into(),
                ))
            }
        }
        _ => Ok(token_env.to_string()),
    }
}

const READ_SCOPES: &[&str] = &[
    "sentin8:sign:request:read",
    "sentin8:sign:request:write",
    "sentin8:sign:request:admin",
    "sentin8:sys:admin",
    "sentin8:sys:org:admin",
    "sentin8:sys:env:admin",
];
const WRITE_SCOPES: &[&str] = &[
    "sentin8:sign:request:admin",
    "sentin8:sys:admin",
    "sentin8:sys:org:admin",
    "sentin8:sys:env:admin",
];

/// `GET /v1/admin/ui/{page}` - RFW page definitions.
#[utoipa::path(
    get,
    path = "/v1/admin/ui/{page}",
    params(
        ("page" = String, Path, description = "RFW page name"),
        ("target_env_id" = String, Query, description = "Target env (RLS context)")
    ),
    responses(
        (status = 200, description = "RFW page definition (rendered by Sentin8:Dash)", body = sentin8::rfw::AdminUiResponse),
        (status = 403, description = "Caller lacks a sign read/admin scope"),
        (status = 404, description = "Unknown page"),
    ),
    security(("sentin8:sign:admin" = [])),
    tag = "admin-ui",
)]
pub async fn get_admin_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(page): Path<String>,
    Query(q): Query<TargetEnvQuery>,
) -> Result<Json<AdminUiResponse>, (StatusCode, String)> {
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    a.require_any_scope(READ_SCOPES)?;
    let _ = resolve_env_id(&headers, &q, &a)?;
    let def = match page.as_str() {
        "overview" => AdminPage::new("Sign Overview")
            .widget(card(
                "Electronic Signature Ceremonies",
                "Signature requests (AdES/QES) run through session-bound signer ceremonies; every transition is evented on the Bus and completed evidence is append-only. Provider dispatch runs behind a gateway seam (stub by default; a qualified trust-service provider per environment).",
            ))
            .build(),
        "requests" => AdminPage::new("Signature Requests")
            .action(link("New Request", "requests/new"))
            .widget(table_with_actions(
                vec![
                    col_s("title", "Title", true),
                    col_s("signature_level", "Level", true),
                    col_s("status", "Status", true),
                    col_s("updated_at", "Updated", true),
                ],
                "/requests",
                vec![
                    row_action("Evidence", "requests/{id}/evidence"),
                    row_action_post("Reopen (failed)", "admin/requests"),
                ],
            ))
            .build(),
        "requests/new" => AdminPage::new("New Signature Request")
            .widget(card(
                "API-created",
                "Requests are created by consuming services (M2M) or via the public API; the ceremony begins as soon as the signers are notified. Use the service's POST /v1/requests surface.",
            ))
            .build(),
        "settings" => AdminPage::new("Sign Settings")
            .widget(card(
                "Configuration",
                "Provider mode (stub/qtsp), provider URL, and the provider credential secret_ref are environment variables on the Sign service (SENTIN8_SIGN_*). QES refuses to mint without a qualified provider - no silent downgrade.",
            ))
            .build(),
        p if sentin8::rfw::policy_page("sentin8:sign", p).is_some() => sentin8::rfw::policy_page(
            "sentin8:sign", p,
        )
        .expect("policy_page checked in guard")
        .build(),
        _ => {
            return Err((StatusCode::NOT_FOUND, format!("Unknown admin UI page: {page}")));
        }
    };
    Ok(Json(AdminUiResponse::page(def)))
}

/// `GET /v1/admin/{resource}` - returns admin data rows for RFW tables.
#[utoipa::path(
    get,
    path = "/v1/admin/{resource}",
    params(
        ("resource" = String, Path, description = "Admin data resource"),
        ("target_env_id" = String, Query, description = "Target env (RLS context)")
    ),
    responses(
        (status = 200, description = "The resource's rows for the RFW table", body = sentin8::rfw::policy_pages::AdminDataRows),
        (status = 403, description = "Caller lacks a sign read/admin scope"),
        (status = 404, description = "Unknown resource"),
    ),
    security(("sentin8:sign:admin" = [])),
    tag = "admin-ui",
)]
pub async fn get_admin_data(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Path(resource): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    admin_data(state, headers, q, resource).await
}

/// GET alias for `/v1/admin/requests` - the POST-only literal on the
/// same path shadows the `/v1/admin/{resource}` catch-all for GET
/// requests (axum returns 405 instead of falling through), so the data
/// read must be registered explicitly, mirroring the secrets pattern.
#[utoipa::path(
    get,
    path = "/v1/admin/requests",
    params(("target_env_id" = String, Query, description = "Target env (RLS context)")),
    responses(
        (status = 200, description = "The requests rows for the RFW table", body = sentin8::rfw::policy_pages::AdminDataRows),
        (status = 403, description = "Caller lacks a sign read/admin scope"),
    ),
    security(("sentin8:sign:admin" = [])),
    tag = "admin-ui",
)]
pub async fn get_admin_data_requests(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    admin_data(state, headers, q, "requests".to_string()).await
}

async fn admin_data(
    state: AppState,
    headers: HeaderMap,
    q: TargetEnvQuery,
    resource: String,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    a.require_any_scope(READ_SCOPES)?;
    let env_id = resolve_env_id(&headers, &q, &a)?;
    let env_uuid = uuid::Uuid::parse_str(&env_id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid env id".into()))?;
    // Tenant RLS context is transaction-local; every query below runs
    // on the same explicit transaction.
    let mut tx = crate::handlers::begin_tenant_tx(&state.pool, env_uuid).await?;
    let rows: Vec<serde_json::Value> = match resource.as_str() {
        "requests" => {
            let recs: Vec<(
                uuid::Uuid,
                String,
                String,
                String,
                chrono::DateTime<chrono::Utc>,
            )> = sqlx::query_as(
                "SELECT id, title, signature_level, status, updated_at
                   FROM sign.signature_requests WHERE env_id = $1
                  ORDER BY updated_at DESC LIMIT 200",
            )
            .bind(env_uuid)
            .fetch_all(&mut *tx)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db error: {e}")))?;
            recs.iter()
                .map(|(id, title, level, status, updated_at)| {
                    serde_json::json!({
                        "id": id,
                        "title": title,
                        "signature_level": level,
                        "status": status,
                        "updated_at": updated_at.to_rfc3339(),
                    })
                })
                .collect()
        }
        r if r.starts_with("requests/") && r.ends_with("/evidence") => {
            let id = r
                .strip_prefix("requests/")
                .unwrap_or("")
                .strip_suffix("/evidence")
                .unwrap_or("");
            let Ok(id) = uuid::Uuid::parse_str(id) else {
                return Err((StatusCode::BAD_REQUEST, "invalid request id".into()));
            };
            let recs: Vec<(String, String, String)> = sqlx::query_as(
                "SELECT user_id, status, COALESCE(signature_value, '') FROM sign.signers
                  WHERE env_id = $1 AND request_id = $2 ORDER BY created_at",
            )
            .bind(env_uuid)
            .bind(id)
            .fetch_all(&mut *tx)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db error: {e}")))?;
            recs.iter()
                .map(|(user_id, status, sig)| {
                    serde_json::json!({
                        "user_id": user_id,
                        "status": status,
                        "signature_value": sig,
                    })
                })
                .collect()
        }
        _ => {
            return Err((
                StatusCode::NOT_FOUND,
                format!("Unknown admin resource: {resource}"),
            ));
        }
    };
    tx.commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db error: {e}")))?;
    Ok(Json(serde_json::Value::Array(rows)))
}

// ── Local RFW widget helpers (the per-service convention - every
// service defines these constructors at the bottom of its admin_ui;
// the dash renders the definitions, the SDK only carries the types).

fn col_s(key: &str, label: &str, sortable: bool) -> WidgetDataTableColumn {
    WidgetDataTableColumn {
        key: key.into(),
        label: label.into(),
        sortable,
        width: None,
        format: None,
    }
}
fn table_with_actions(
    columns: Vec<WidgetDataTableColumn>,
    endpoint: &str,
    row_actions: Vec<WidgetButton>,
) -> RemoteWidget {
    RemoteWidget::DataTable(WidgetDataTable {
        columns,
        data_endpoint: endpoint.into(),
        sortable: true,
        filterable: true,
        page_size: 20,
        empty_message: Some("No signature requests yet.".into()),
        row_link: None,
        row_actions,
    })
}
fn row_action(label: &str, route: &str) -> WidgetButton {
    WidgetButton {
        label: label.into(),
        button_type: ButtonType::Link,
        route: Some(route.into()),
        endpoint: None,
        icon: None,
    }
}
fn row_action_post(label: &str, endpoint: &str) -> WidgetButton {
    WidgetButton {
        label: label.into(),
        button_type: ButtonType::Primary,
        route: None,
        endpoint: Some(endpoint.into()),
        icon: None,
    }
}
fn card(title: &str, body: &str) -> RemoteWidget {
    RemoteWidget::Card(WidgetCard {
        title: Some(title.into()),
        subtitle: None,
        children: vec![RemoteWidget::Text(WidgetText {
            text: body.into(),
            text_type: WidgetTextType::Body,
            align: TextAlign::Left,
            max_lines: None,
        })],
        actions: vec![],
    })
}
fn link(label: &str, route: &str) -> AdminUiAction {
    AdminUiAction {
        label: label.into(),
        action_type: AdminUiActionType::Link,
        route: Some(route.into()),
        endpoint: None,
        icon: Some("0xe145".into()),
    }
}

/// Reopen-failed admin action body.
#[derive(Debug, serde::Deserialize, utoipa::ToSchema)]
pub struct AdminReopenRequest {
    /// The request id to reopen.
    pub id: String,
}

/// Reopen response - the reopened request's new state.
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct AdminReopenResponse {
    /// The reopened request id.
    pub id: uuid::Uuid,
    /// The request's resulting status (always `open`).
    pub status: String,
}

/// `POST /v1/admin/requests` - admin action surface: reopen a failed
/// request (the only post-completion mutation; DESIGN.md §6 replay).
#[utoipa::path(
    post,
    path = "/v1/admin/requests",
    request_body = AdminReopenRequest,
    responses(
        (status = 200, description = "Request reopened (open)", body = AdminReopenResponse),
        (status = 403, description = "Caller lacks a sign admin scope"),
        (status = 404, description = "Unknown request"),
        (status = 409, description = "Request is not in failed state"),
    ),
    security(("sentin8:sign:admin" = [])),
    tag = "admin-ui",
)]
pub async fn admin_reopen_failed(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(req): axum::Json<AdminReopenRequest>,
) -> Result<Json<AdminReopenResponse>, (StatusCode, String)> {
    let a = crate::auth::verify_token(&state.config, &headers).await?;
    a.require_any_scope(WRITE_SCOPES)?;
    let env_id = a.env_id();
    let id = uuid::Uuid::parse_str(&req.id)
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid request id".into()))?;

    let mut tx = crate::handlers::begin_tenant_tx(&state.pool, env_id).await?;
    let res = sqlx::query(
        "UPDATE sign.signature_requests
           SET status = 'open', updated_at = now()
         WHERE env_id = $1 AND id = $2 AND status = 'failed'",
    )
    .bind(env_id)
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db error: {e}")))?;
    if res.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "unknown or not-failed request".into()));
    }
    sentin8::bus::outbox::insert_outbox_row_with_publisher(
        &mut *tx,
        env_id,
        &state.config.stream_family,
        "sentin8:sign:request:reopened",
        &serde_json::json!({ "request_id": id, "reopened_by": a.sub() }),
        crate::auth::raw_bearer_token(&headers).as_deref(),
        Some(a.sub()),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db error: {e}")))?;
    tx.commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("db error: {e}")))?;
    Ok(Json(AdminReopenResponse { id, status: "open".into() }))
}