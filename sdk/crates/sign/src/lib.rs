// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Sign
// SPDX-License-Identifier: Apache-2.0

//! # sentin8-sign
//!
//! Contract types for Sentin8:Sign - the platform's electronic
//! signature ceremony service.
//!
//! Consuming services (vertical or platform) create signature requests
//! (`POST /v1/requests`), drive their signers through the ceremony, and
//! consume the payload-complete `sentin8:sign:request:*` events. The
//! event contract is the integration surface - consumers never call
//! back for state.

use serde::{Deserialize, Serialize};

/// The signature level of a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureLevel {
    /// Advanced electronic signature (works with the stub dispatch).
    Ades,
    /// Qualified electronic signature (requires a qualified
    /// trust-service provider configured for the environment).
    Qes,
}

impl SignatureLevel {
    /// The wire string (`ades` | `qes`).
    pub fn as_str(&self) -> &'static str {
        match self {
            SignatureLevel::Ades => "ades",
            SignatureLevel::Qes => "qes",
        }
    }
}

/// A document reference inside a signature request - a storage
/// reference only; document bytes are never inline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocumentRef {
    /// Storage object reference.
    pub r#ref: String,
    /// Display name.
    pub name: String,
    /// Content hash (what the signature covers).
    pub hash: String,
}

/// The terminal status of a signature request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RequestStatus {
    /// Open ceremony.
    Open,
    /// All signers signed.
    Completed,
    /// A signer declined.
    Declined,
    /// The expiry sweep closed it.
    Expired,
    /// Provider dispatch failed terminally (admin-replayable).
    Failed,
}

/// A `sentin8:sign:request:*` event payload (the consumer contract).
///
/// Payload-complete by design: every event carries the request id, the
/// acting signer, the level, and the timestamps - a consumer reacts
/// without calling back.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignEvent {
    /// The request the event refers to.
    pub request_id: uuid::Uuid,
    /// The acting signer (absent on created/expired).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
    /// The request's signature level.
    pub signature_level: String,
    /// RFC 3339 timestamp of the transition.
    pub at: String,
    /// The document set (storage refs + hashes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub documents: Option<Vec<DocumentRef>>,
    /// The signer set (created event only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signers: Option<Vec<String>>,
}