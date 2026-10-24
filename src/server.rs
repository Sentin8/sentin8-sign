// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Sign
// SPDX-License-Identifier: Apache-2.0

//! Axum server setup for Sentin8:Sign.

use std::sync::Arc;

use axum::routing::{get, post};

use crate::handlers::{self, AppState};

/// Build state.
pub async fn build_state(
    core: sentin8::shell::ServiceCore,
) -> anyhow::Result<crate::handlers::AppState> {
    let config = crate::config::SignConfig::from_env();
    // Shield (shell-owned boot): consume the engine the shell booted
    // in step 8 - no second engine, consumer, or DCR registration here.
    let policy_engine = core.admin.policy.clone();

    let state = AppState {
        config: Arc::new(config.clone()),
        pool: core.pool.clone(),
        policy: policy_engine.clone(),
        admin: sentin8::shield::admin::SharedAdminState {
            service: "sentin8:sign".to_string(),
            pool: core.pool.clone(),
            policy: policy_engine.clone(),
            auth_client: Arc::new(config.auth_client.clone()),
        },
    };

    Ok(state)
}

/// Add this service's routes onto the shell-provided router. The shell
/// owns the boot sequence, state binding, OpenAPI merge and the
/// standard middleware stack; this adds ONLY routes (including the
/// service's own `/v1/health` - custom payload).
pub fn routes(
    router: axum::Router<crate::handlers::AppState>,
) -> axum::Router<crate::handlers::AppState> {
    router
        .route("/v1/health", get(handlers::health_handler))
        // ── Request CRUD + ceremonies (env-scoped; env from token) ─────
        .route("/v1/requests", post(handlers::create_request).get(handlers::list_requests))
        .route(
            "/v1/requests/{id}",
            get(handlers::get_request),
        )
        .route("/v1/requests/{id}/view", post(handlers::view_request))
        .route(
            "/v1/requests/{id}/approve",
            post(handlers::approve_request),
        )
        .route(
            "/v1/requests/{id}/evidence",
            get(handlers::request_evidence),
        )
        // Cron proxy-back target (expiry sweep, DESIGN.md §4).
        .route(
            "/v1/internal/schedules/run",
            post(handlers::internal_schedules_run),
        )
        // ── Admin UI (RFW) ─────────────────────────────────────────────
        .route("/v1/admin/ui/{*page}", get(crate::admin_ui::get_admin_ui))
        .route("/v1/admin/{resource}", get(crate::admin_ui::get_admin_data))
        .route(
            "/v1/admin/requests",
            post(crate::admin_ui::admin_reopen_failed).get(crate::admin_ui::get_admin_data_requests),
        )
        // ── Shield policy admin API (shared implementation, one surface
        // per service; handlers are generic over this AppState).
        .route(
            "/v1/admin/policy-sets",
            get(sentin8::shield::admin::list_policy_sets::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/{name}",
            get(sentin8::shield::admin::get_policy_set::<handlers::AppState>)
                .put(sentin8::shield::admin::put_policy_set::<handlers::AppState>)
                .delete(sentin8::shield::admin::delete_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/{name}/test",
            post(sentin8::shield::admin::test_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/enforce",
            post(sentin8::shield::admin::admin_enforce_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/shadow",
            post(sentin8::shield::admin::admin_shadow_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/disable",
            post(sentin8::shield::admin::admin_disable_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/relations",
            get(sentin8::shield::admin::list_relations::<handlers::AppState>)
                .put(sentin8::shield::admin::put_relation::<handlers::AppState>)
                .delete(sentin8::shield::admin::delete_relation::<handlers::AppState>),
        )
        .route(
            "/v1/admin/relations/check",
            get(sentin8::shield::admin::check_relation::<handlers::AppState>),
        )
        .route(
            "/v1/admin/attributes",
            get(sentin8::shield::admin::list_attributes::<handlers::AppState>)
                .put(sentin8::shield::admin::put_attribute::<handlers::AppState>)
                .delete(sentin8::shield::admin::delete_attribute::<handlers::AppState>),
        )
}

/// Shared policy-admin surface accessor - the shared handlers extract
/// this service's admin state via [`HasPolicyAdmin`].
impl sentin8::shield::admin::HasPolicyAdmin for AppState {
    fn policy_admin(&self) -> &sentin8::shield::admin::SharedAdminState {
        &self.admin
    }
}