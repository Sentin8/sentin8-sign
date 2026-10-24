// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Sign
// SPDX-License-Identifier: Apache-2.0

//! Sign service configuration loaded from environment variables.

use std::env;

use sentin8::auth::client::{Client as AuthClient, ClientOptions};

/// Configuration for Sign.
pub struct SignConfig {
    /// The port.
    pub port: u16,
    /// Auth JWKS URL for token verification.
    pub sentin8_auth_jwks_url: String,
    /// Auth issuer for token verification.
    pub sentin8_auth_issuer: String,
    /// Shared Auth client - constructed once so the discovery and JWKS
    /// caches are reused across every request (5-minute TTL each).
    pub auth_client: AuthClient,
    /// Database URL.
    pub database_url: String,
    /// Bus base URL for event publication (outbox relay pushes here).
    pub sentin8_bus_url: String,
    /// Bus stream family for Sign events (default `"sign"`).
    pub stream_family: String,
    /// Provider dispatch mode: `"stub"` (default - dev/test dispatch that
    /// exercises the full ceremony path) or `"qtsp"` (remote signing
    /// through the configured provider gateway, DESIGN.md §4).
    pub provider_mode: String,
    /// QTSP gateway base URL (provider mode `qtsp` only). Credentials
    /// resolve by `secret_ref` at dispatch time - never stored here.
    pub provider_url: String,
    /// Secret reference for the QTSP gateway credentials (provider mode
    /// `qtsp` only). Resolved through the Secrets chain at dispatch time.
    pub provider_secret_ref: String,
}

impl std::fmt::Debug for SignConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // No secret material is held in this config (references only) -
        // the debug shape reports the mode and endpoints, never values.
        f.debug_struct("SignConfig")
            .field("port", &self.port)
            .field("stream_family", &self.stream_family)
            .field("provider_mode", &self.provider_mode)
            .field("provider_url", &self.provider_url)
            .field("provider_secret_ref", &self.provider_secret_ref)
            .finish()
    }
}

impl Clone for SignConfig {
    fn clone(&self) -> Self {
        Self {
            port: self.port,
            sentin8_auth_jwks_url: self.sentin8_auth_jwks_url.clone(),
            sentin8_auth_issuer: self.sentin8_auth_issuer.clone(),
            auth_client: self.auth_client.clone(),
            database_url: self.database_url.clone(),
            sentin8_bus_url: self.sentin8_bus_url.clone(),
            stream_family: self.stream_family.clone(),
            provider_mode: self.provider_mode.clone(),
            provider_url: self.provider_url.clone(),
            provider_secret_ref: self.provider_secret_ref.clone(),
        }
    }
}

impl SignConfig {
    /// Load the configuration from environment variables.
    pub fn from_env() -> Self {
        let cfg = sentin8::config::Sentin8Config::from_env();
        let sentin8_auth_issuer =
            env::var("SENTIN8_AUTH_ISSUER").unwrap_or_else(|_| cfg.sentin8_auth_issuer());

        Self {
            port: env::var("SENTIN8_SIGN_PORT")
                .expect("SENTIN8_SIGN_PORT must be set by captain")
                .parse()
                .expect("SENTIN8_SIGN_PORT must be a valid u16"),
            sentin8_auth_jwks_url: env::var("SENTIN8_AUTH_JWKS_URL")
                .unwrap_or_else(|_| cfg.sentin8_auth_jwks_url()),
            sentin8_auth_issuer: sentin8_auth_issuer.clone(),
            auth_client: AuthClient::new(ClientOptions {
                base_url: sentin8_auth_issuer,
                ..Default::default()
            }),
            database_url: env::var("SENTIN8_SIGN_DATABASE_URL").unwrap_or_else(|_| {
                env::var("DATABASE_URL").unwrap_or_else(|_| {
                    sentin8::config::Sentin8Config::default_database_url().to_string()
                })
            }),
            sentin8_bus_url: env::var("SENTIN8_BUS_URL")
                .unwrap_or_else(|_| cfg.sentin8_bus_url()),
            stream_family: env::var("SENTIN8_SIGN_STREAM_FAMILY")
                .unwrap_or_else(|_| "sign".into()),
            provider_mode: env::var("SENTIN8_SIGN_PROVIDER_MODE")
                .unwrap_or_else(|_| "stub".into()),
            provider_url: env::var("SENTIN8_SIGN_PROVIDER_URL").unwrap_or_default(),
            provider_secret_ref: env::var("SENTIN8_SIGN_PROVIDER_SECRET_REF").unwrap_or_default(),
        }
    }
}