// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Sign
// SPDX-License-Identifier: Apache-2.0

//! Service self-registration data for Sentin8:Sign.
//!
//! Output via `--print-registration` flag. The CLI runs the binary with
//! this flag and consumes the JSON to register the service in the
//! platform DB (enroll provisions platform rows; scopes, roles, SQL,
//! policies, schedules and M2M grants declared here).

use sentin8::registration::{
    AdminScope, AdminUi, AdminUiPage, PgRole, PolicySetDecl, Registration, ScheduleDecl,
    SqlMigration,
};
use utoipa::OpenApi;

const PG_ROLES: &[PgRole] = &[PgRole {
    scope: "sentin8:sign:request:read,sentin8:sign:request:write",
    role: "sentin8_sign_service",
    bypass_rls: false,
    database: "sentin8",
    cross_schema_grants: &[],
}];

// Admin role scopes - the signature-ceremony vocabulary (the
// registration declares the authoritative scope vocabulary for the
// `sentin8:sign:admin` role; the policy-admin pair follows the
// per-service convention).
const ADMIN_SCOPES: &[AdminScope] = &[
    AdminScope::Tuple("sentin8:sign:admin", "sentin8:sign:admin"),
    AdminScope::Tuple("sentin8:sign:admin", "sentin8:sign:request:read"),
    AdminScope::Tuple("sentin8:sign:admin", "sentin8:sign:request:write"),
    AdminScope::Tuple("sentin8:sign:admin", "sentin8:sign:signer:read"),
    AdminScope::Tuple("sentin8:sign:admin", "sentin8:sign:signer:write"),
    AdminScope::Tuple("sentin8:sign:admin", "sentin8:sign:request:admin"),
    // Policy-admin surface (per-service scope).
    AdminScope::Tuple("sentin8:sign:admin", "sentin8:sign:policy:read"),
    AdminScope::Tuple("sentin8:sign:admin", "sentin8:sign:policy:write"),
];

const ADMIN_UI_PAGES: &[AdminUiPage] = &[
    AdminUiPage {
        route: "overview",
        label: "Overview",
        ui_endpoint: "/v1/admin/ui/overview",
        data_endpoint: "/v1/admin/overview",
        icon: "0xe899",
    },
    AdminUiPage {
        route: "requests",
        label: "Signature Requests",
        ui_endpoint: "/v1/admin/ui/requests",
        data_endpoint: "/v1/admin/requests",
        icon: "0xe8b8",
    },
    AdminUiPage {
        route: "settings",
        label: "Settings",
        ui_endpoint: "/v1/admin/ui/settings",
        data_endpoint: "/v1/admin/settings",
        icon: "0xe57f",
    },
    AdminUiPage {
        route: "policy-sets",
        label: "Policy Sets",
        ui_endpoint: "/v1/admin/ui/policy-sets",
        data_endpoint: "/v1/admin/policy-sets",
        icon: "0xe8b8",
    },
    AdminUiPage {
        route: "policy-decisions",
        label: "Policy Decisions",
        ui_endpoint: "/v1/admin/ui/policy-decisions",
        data_endpoint: "/v1/admin/policy-decisions",
        icon: "0xf070",
    },
];

const SQL_1_INIT: &str = include_str!("../sql/init.sql");

/// Serialize the utoipa OpenAPI spec (used for the `all` and `openapi`
/// sections).
fn openapi_spec() -> serde_json::Value {
    serde_json::to_value(crate::openapi::SignOpenApi::openapi()).unwrap_or(serde_json::Value::Null)
}

/// Default declarative policy sets: action-granular scope permits over
/// the LIVE effective scope set. Seeded `origin='platform'`,
/// `mode='enforced'` - step 5 is the only gate; shadow is the emergency
/// one-UPDATE rollback lever only.
const POLICIES: &[PolicySetDecl] = &[
    PolicySetDecl {
        policy_set_name: "scope-mirror",
        description: "Action-granular scope permits for sentin8:sign over the LIVE effective scope set. Enforced - the Shield gate is the only access gate.",
        policies: "permit(principal, action == Action::\"sentin8:sign:request:read\", resource) when { principal.scopes.contains(\"sentin8:sign:request:read\") };\npermit(principal, action == Action::\"sentin8:sign:request:read\", resource) when { principal.scopes.contains(\"sentin8:sign:admin\") };\npermit(principal, action == Action::\"sentin8:sign:request:write\", resource) when { principal.scopes.contains(\"sentin8:sign:request:write\") };\npermit(principal, action == Action::\"sentin8:sign:request:write\", resource) when { principal.scopes.contains(\"sentin8:sign:admin\") };\npermit(principal, action == Action::\"sentin8:sign:signer:read\", resource) when { principal.scopes.contains(\"sentin8:sign:signer:read\") };\npermit(principal, action == Action::\"sentin8:sign:signer:read\", resource) when { principal.scopes.contains(\"sentin8:sign:admin\") };\npermit(principal, action == Action::\"sentin8:sign:signer:write\", resource) when { principal.scopes.contains(\"sentin8:sign:signer:write\") };\npermit(principal, action == Action::\"sentin8:sign:signer:write\", resource) when { principal.scopes.contains(\"sentin8:sign:signer:admin\") };\npermit(principal, action == Action::\"sentin8:sign:signer:write\", resource) when { principal.scopes.contains(\"sentin8:sign:admin\") };\npermit(principal, action == Action::\"sentin8:sign:request:admin\", resource) when { principal.scopes.contains(\"sentin8:sign:request:admin\") };\npermit(principal, action == Action::\"sentin8:sign:request:admin\", resource) when { principal.scopes.contains(\"sentin8:sign:admin\") };",
        schema: None,
        mode: "enforced",
        default_enabled: true,
    },
];

/// Default ReBAC relation tuples - none declared by this service today;
/// env admins author their own graph via the admin API.
const RELATIONS: &[sentin8::registration::RelationDecl] = &[];

/// M2M DCR workload grants: this service's own `certless:<workload>`
/// rows, upserted by `vertical enroll` (self-registration - the static
/// auth seed is retired; this declaration is the ONLY provisioning
/// path).
const M2M_GRANTS: &[sentin8::registration::M2mGrant] = &[
    sentin8::registration::M2mGrant {
        workload: "sign-audit",
        scopes: &["sentin8:sys:audit:write"],
    },
    sentin8::registration::M2mGrant {
        workload: "sentin8:sign",
        scopes: &["sentin8:bus:produce"],
    },
    sentin8::registration::M2mGrant {
        workload: "sentin8:sign-policy",
        scopes: &["sentin8:bus:consume", "sentin8:stat:measure"],
    },
    // Cron schedule proxy-back (DESIGN.md §4): the daily expiry sweep
    // calls `/v1/internal/schedules/run` with M2M.
    sentin8::registration::M2mGrant {
        workload: "sign-cron",
        scopes: &["sentin8:cron:write"],
    },
    // the database-free HostContextResolver's resolve
    // workload - cache miss calls Sys `GET /v1/resolve/hostname`.
    sentin8::registration::M2mGrant {
        workload: "sentin8-sign-tls",
        scopes: &["sentin8:sys:instances:read"],
    },
];

/// Print the registration JSON to stdout.
///
/// With no `--section` argument, outputs the full registration object.
/// With `--section=<name>`, outputs only that section as a standalone
/// JSON value.
pub fn print(section: Option<String>) -> anyhow::Result<()> {
    let reg = Registration {
        service_type: "sentin8:sign",
        subdomain: "sign",
        health_path: "/v1/health",
        admin_scopes: ADMIN_SCOPES,
        error_codes: &[],
        consent_providers: &[],
        consent_flows: &[],
        admin_ui: Some(AdminUi {
            label: "Sign",
            icon: "0xe8b8",
            service_flag: "sign",
            pages: ADMIN_UI_PAGES,
        }),
        sql_migrations: vec![SqlMigration {
            version: 1,
            name: "init",
            sql: SQL_1_INIT,
        }],
        pg_roles: PG_ROLES,
        policies: POLICIES,
        relations: RELATIONS,
        event_triggers: &[],
        // Declarative schedules (SDD §2.4): recurring internal
        // maintenance owned by Cron, declared here, provisioned by
        // `vertical enroll`. The expiry sweep closes stale open
        // requests (DESIGN.md §6) via the internal proxy-back route.
        schedules: &[ScheduleDecl {
            schedule_type: "sign-expiry-sweep",
            cron_expression: "0 4 * * *",
            timezone: "UTC",
            target_config: r#"{"internalPath": "/v1/internal/schedules/run", "scheduleType": "sign-expiry-sweep"}"#,
            max_retries: 3,
        }],
        audit_findings: None,
        service_actions: None,
        m2m_grants: Some(M2M_GRANTS),
        openapi_url: "/openapi.json",
        openapi: openapi_spec,
    };
    sentin8::registration::print_registration(section, &reg, openapi_spec)
}