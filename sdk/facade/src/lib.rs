// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Sign
// SPDX-License-Identifier: Apache-2.0

//! sentin8-sign-sdk - per-service SDK mini-facade (SDD §3.1).
//!
//! Re-exports the Sentin8:Sign contracts crate. No logic, no features
//! (SDD-4b). Consumers import as `use sentin8_sign_sdk::sign::…`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// The sign crate - `SignatureLevel`, `DocumentRef`, `RequestStatus`,
/// and the `SignEvent` consumer contract (re-export).
pub mod sign {
    pub use sentin8_sign::*;
}