// SPDX-License-Identifier: MIT OR Apache-2.0

//! Portable Utreexo accumulator snapshots.
//!
//! A [`UtreexoSnapshot`] captures exactly the data needed to seed a fresh node's
//! `assumeutreexo_value`: the best-block hash and height at the moment of dump,
//! plus the Utreexo forest (leaf count + root hashes). It serialises to a small
//! JSON blob that is safe to move between devices (clipboard, QR, share sheet).
//!
//! ## Security — no wallet / descriptor data in the payload
//!
//! The snapshot contains only consensus-public data. The list of top-level JSON
//! keys is fixed (`version`, `network`, `block_hash`, `height`, `leaves`, `roots`)
//! and enforced by a schema-lock unit test. Import parsing sets
//! `#[serde(deny_unknown_fields)]` so a crafted payload can never smuggle extra
//! fields.
//!
//! Any future addition to the on-the-wire shape must also update the schema-lock
//! test — it is a deliberate tripwire so reviewers notice payload widening.

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::error::Error;
use core::fmt;
use core::str::FromStr;

use bitcoin::BlockHash;
use bitcoin::Network;
use rustreexo::node_hash::BitcoinNodeHash;
use serde::Deserialize;
use serde::Serialize;

use crate::pruned_utreexo::chainparams::AssumeUtreexoValue;

/// Current wire-format version. Bump whenever the on-disk shape changes
/// incompatibly. `from_json` rejects any other value.
pub const SNAPSHOT_VERSION: u32 = 1;

/// A portable dump of a node's Utreexo accumulator at a specific tip.
///
/// This is the complement of [`AssumeUtreexoValue`]: a `UtreexoSnapshot` is what
/// a synced node exports so that another node can skip IBD by loading it into
/// `Config::assumeutreexo_value`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UtreexoSnapshot {
    pub block_hash: BlockHash,
    pub height: u32,
    pub leaves: u64,
    pub roots: Vec<BitcoinNodeHash>,
}

impl UtreexoSnapshot {
    /// Serialise to JSON. The `network` is recorded in the payload so that
    /// [`from_json`](Self::from_json) can refuse mismatched imports.
    pub fn to_json(&self, network: Network) -> String {
        let wire = SnapshotJson {
            version: SNAPSHOT_VERSION,
            network: network_tag(network).to_string(),
            block_hash: self.block_hash.to_string(),
            height: self.height,
            leaves: self.leaves,
            roots: self.roots.iter().map(|r| r.to_string()).collect(),
        };
        // `serde_json::to_string` on a struct with only primitive / hex-string
        // fields cannot fail — but we never unwrap at a user boundary: fall
        // back to the raw Debug form so a programming bug is visible rather
        // than a panic at runtime.
        serde_json::to_string(&wire)
            .unwrap_or_else(|_| format!("{{\"error\":\"snapshot serialisation bug: {wire:?}\"}}"))
    }

    /// Parse a payload produced by [`to_json`](Self::to_json). Returns both the
    /// snapshot and the network it was taken on, so callers can refuse to load
    /// a cross-network dump.
    pub fn from_json(s: &str) -> Result<(Self, Network), SnapshotError> {
        let wire: SnapshotJson = serde_json::from_str(s).map_err(SnapshotError::InvalidJson)?;

        if wire.version != SNAPSHOT_VERSION {
            return Err(SnapshotError::UnsupportedVersion(wire.version));
        }

        let network = network_from_tag(&wire.network)
            .ok_or_else(|| SnapshotError::UnknownNetwork(wire.network.clone()))?;

        let block_hash = BlockHash::from_str(&wire.block_hash)
            .map_err(|_| SnapshotError::InvalidHex("block_hash"))?;

        let mut roots = Vec::with_capacity(wire.roots.len());
        for r in &wire.roots {
            let h = BitcoinNodeHash::from_str(r).map_err(|_| SnapshotError::InvalidHex("roots"))?;
            roots.push(h);
        }

        Ok((
            UtreexoSnapshot {
                block_hash,
                height: wire.height,
                leaves: wire.leaves,
                roots,
            },
            network,
        ))
    }

    /// Convert into an `AssumeUtreexoValue` suitable for `Config::assumeutreexo_value`.
    pub fn into_assume_value(self) -> AssumeUtreexoValue {
        AssumeUtreexoValue {
            block_hash: self.block_hash,
            height: self.height,
            roots: self.roots,
            leaves: self.leaves,
        }
    }

    /// Build a snapshot from the same fields an `AssumeUtreexoValue` holds.
    pub fn from_assume_value(v: AssumeUtreexoValue) -> Self {
        Self {
            block_hash: v.block_hash,
            height: v.height,
            leaves: v.leaves,
            roots: v.roots,
        }
    }
}

/// On-the-wire JSON shape. The field set here is load-bearing — see the
/// schema-lock test in this module.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotJson {
    version: u32,
    network: String,
    block_hash: String,
    height: u32,
    leaves: u64,
    roots: Vec<String>,
}

fn network_tag(network: Network) -> &'static str {
    // Exhaustive match is intentional: if a future `bitcoin` upgrade adds a
    // new `Network` variant, this fails to compile and forces a conscious
    // decision about the wire tag.
    match network {
        Network::Bitcoin => "bitcoin",
        Network::Testnet => "testnet",
        Network::Testnet4 => "testnet4",
        Network::Signet => "signet",
        Network::Regtest => "regtest",
    }
}

fn network_from_tag(s: &str) -> Option<Network> {
    match s {
        "bitcoin" => Some(Network::Bitcoin),
        "testnet" => Some(Network::Testnet),
        "testnet4" => Some(Network::Testnet4),
        "signet" => Some(Network::Signet),
        "regtest" => Some(Network::Regtest),
        _ => None,
    }
}

#[derive(Debug)]
pub enum SnapshotError {
    InvalidJson(serde_json::Error),
    UnsupportedVersion(u32),
    UnknownNetwork(String),
    /// Which hex-bearing field failed to parse (`"block_hash"` or `"roots"`).
    InvalidHex(&'static str),
    /// Payload was taken on a different network than the caller's expected one.
    NetworkMismatch {
        expected: Network,
        got: Network,
    },
}

impl fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SnapshotError::InvalidJson(e) => write!(f, "invalid snapshot JSON: {e}"),
            SnapshotError::UnsupportedVersion(v) => write!(
                f,
                "unsupported snapshot version {v} (this build expects {SNAPSHOT_VERSION})"
            ),
            SnapshotError::UnknownNetwork(s) => write!(f, "unknown network tag {s:?}"),
            SnapshotError::InvalidHex(field) => write!(f, "invalid hex in field {field:?}"),
            SnapshotError::NetworkMismatch { expected, got } => write!(
                f,
                "snapshot is for {} but node is configured for {}",
                network_tag(*got),
                network_tag(*expected)
            ),
        }
    }
}

impl Error for SnapshotError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            SnapshotError::InvalidJson(e) => Some(e),
            _ => None,
        }
    }
}

/// Convenience: validate a payload against an expected network in one call.
/// Used by the FFI as a pre-check before triggering a restart-to-import on the
/// Android side.
pub fn validate_for_network(payload: &str, expected: Network) -> Result<UtreexoSnapshot, SnapshotError> {
    let (snap, got) = UtreexoSnapshot::from_json(payload)?;
    if got != expected {
        return Err(SnapshotError::NetworkMismatch { expected, got });
    }
    Ok(snap)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use bitcoin::BlockHash;
    use rustreexo::node_hash::BitcoinNodeHash;
    use serde_json::Value;

    use super::*;

    fn sample() -> UtreexoSnapshot {
        UtreexoSnapshot {
            block_hash: BlockHash::from_str(
                "000000000000000000009d36aae180d04aeac872adb14e22f65c8b6647a8bf79",
            )
            .unwrap(),
            height: 939_969,
            leaves: 12_345_678,
            roots: vec![
                BitcoinNodeHash::from_str(
                    "08daaf0c6bc41531885cfcfdeb89c34bd4d06ab4b105cf0e81bd74ab082693f5",
                )
                .unwrap(),
                BitcoinNodeHash::from_str(
                    "8d4166d0303d41f7023cd35b95b24455b99b2f4a2728083bba3d172727900bed",
                )
                .unwrap(),
            ],
        }
    }

    #[test]
    fn round_trip() {
        let snap = sample();
        let json = snap.to_json(Network::Bitcoin);
        let (back, net) = UtreexoSnapshot::from_json(&json).unwrap();
        assert_eq!(back, snap);
        assert_eq!(net, Network::Bitcoin);
    }

    /// Schema lock — the set of top-level JSON keys is load-bearing. If a
    /// reviewer widens the payload shape, this test must be updated and the
    /// change justified (see module docs).
    #[test]
    fn schema_lock_top_level_keys() {
        let json = sample().to_json(Network::Bitcoin);
        let parsed: Value = serde_json::from_str(&json).unwrap();
        let keys: BTreeSet<&str> = parsed
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        let expected: BTreeSet<&str> = ["version", "network", "block_hash", "height", "leaves", "roots"]
            .into_iter()
            .collect();
        assert_eq!(keys, expected);
    }

    /// Belt-and-braces: if a contributor accidentally wires wallet data into the
    /// dump path, this catches it by substring search. Keep the list in sync
    /// with the non-leak guarantees documented in the plan.
    #[test]
    fn no_descriptor_or_xpub_in_payload() {
        let secret_descriptor = "wpkh([1234abcd/84'/0'/0']xpub6C...MUSTNOTLEAK...)";
        let secret_xpub = "xpub6C...ALSOMUSTNOTLEAK...";
        let mut snap = sample();
        // Attempt to sneak the strings through by using them as hash parse
        // inputs elsewhere — these are constants used only inside this test;
        // the snapshot itself never touches them, but the assertion below
        // protects against a future drift.
        snap.height = 1;
        let json = snap.to_json(Network::Bitcoin);
        assert!(!json.contains(secret_descriptor));
        assert!(!json.contains(secret_xpub));
        assert!(!json.contains("xpub"));
        assert!(!json.contains("descriptor"));
        assert!(!json.contains("wallet"));
    }

    #[test]
    fn rejects_unknown_fields() {
        // Add an extra top-level field — strict parsing must refuse.
        let good = sample().to_json(Network::Bitcoin);
        let mut v: Value = serde_json::from_str(&good).unwrap();
        v.as_object_mut()
            .unwrap()
            .insert("extra".into(), Value::String("smuggled".into()));
        let tampered = v.to_string();
        match UtreexoSnapshot::from_json(&tampered) {
            Err(SnapshotError::InvalidJson(_)) => {}
            other => panic!("expected InvalidJson from deny_unknown_fields, got {other:?}"),
        }
    }

    #[test]
    fn rejects_wrong_version() {
        let good = sample().to_json(Network::Bitcoin);
        let mut v: Value = serde_json::from_str(&good).unwrap();
        v["version"] = Value::from(99_u32);
        match UtreexoSnapshot::from_json(&v.to_string()) {
            Err(SnapshotError::UnsupportedVersion(99)) => {}
            other => panic!("expected UnsupportedVersion(99), got {other:?}"),
        }
    }

    #[test]
    fn rejects_unknown_network() {
        let good = sample().to_json(Network::Bitcoin);
        let mut v: Value = serde_json::from_str(&good).unwrap();
        v["network"] = Value::String("mainnet-v2".into());
        match UtreexoSnapshot::from_json(&v.to_string()) {
            Err(SnapshotError::UnknownNetwork(s)) if s == "mainnet-v2" => {}
            other => panic!("expected UnknownNetwork, got {other:?}"),
        }
    }

    #[test]
    fn rejects_malformed_block_hash() {
        let good = sample().to_json(Network::Bitcoin);
        let mut v: Value = serde_json::from_str(&good).unwrap();
        v["block_hash"] = Value::String("not a real hash".into());
        match UtreexoSnapshot::from_json(&v.to_string()) {
            Err(SnapshotError::InvalidHex("block_hash")) => {}
            other => panic!("expected InvalidHex(\"block_hash\"), got {other:?}"),
        }
    }

    #[test]
    fn rejects_malformed_root() {
        let good = sample().to_json(Network::Bitcoin);
        let mut v: Value = serde_json::from_str(&good).unwrap();
        v["roots"].as_array_mut().unwrap()[0] = Value::String("zz".into());
        match UtreexoSnapshot::from_json(&v.to_string()) {
            Err(SnapshotError::InvalidHex("roots")) => {}
            other => panic!("expected InvalidHex(\"roots\"), got {other:?}"),
        }
    }

    #[test]
    fn validate_for_network_refuses_cross_network() {
        let json = sample().to_json(Network::Bitcoin);
        match validate_for_network(&json, Network::Signet) {
            Err(SnapshotError::NetworkMismatch { expected, got }) => {
                assert_eq!(expected, Network::Signet);
                assert_eq!(got, Network::Bitcoin);
            }
            other => panic!("expected NetworkMismatch, got {other:?}"),
        }
    }

    #[test]
    fn assume_value_round_trip() {
        let snap = sample();
        let av = snap.clone().into_assume_value();
        let back = UtreexoSnapshot::from_assume_value(av);
        assert_eq!(back, snap);
    }
}
