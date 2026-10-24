// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Sign
// SPDX-License-Identifier: Apache-2.0

//! Sentin8:Sign - electronic signature ceremony service.
//!
//! Owns the signature-request lifecycle (create → view → approve →
//! complete/decline/expired), the signer ceremonies (session-bound
//! approval), provider dispatch behind a gateway seam (AdES/QES), and
//! append-only evidence retention. Design: DESIGN.md.
//!
//! Boot runs on the platform `sentin8-shell` crate: registration flag,
//! PQ provider, config, capped pool, PG18 check, state binding, OpenAPI
//! merge, middleware stack and PQ-TLS listener are owned by the shell.
//! This binary supplies only its registration data, state and routes.

use utoipa::OpenApi;

mod admin_ui;
mod auth;
mod config;
mod handlers;
mod openapi;
mod policy;
mod registration;
mod server;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    sentin8::shell::serve(
        sentin8::shell::Sentin8Shell::new("sentin8:sign", "SENTIN8_SIGN")
            .with_registration(registration::print)
            .with_state(server::build_state)
            .with_own_health()
            .with_router(|router, _state| server::routes(router))
            .with_openapi(openapi::SignOpenApi::openapi()),
    )
    .await
}