// SPDX-License-Identifier: MIT OR Apache-2.0

//! Verbose serialization for `blockchain.transaction.get`.
//!
//! Some Electrum clients (notably Blue Wallet) call
//! `blockchain.transaction.get(txid, true)` and expect a decoded JSON object
//! rather than the raw transaction hex. This module builds that object in the
//! shape those clients read: `scriptPubKey.addresses` is an **array**, keys are
//! camelCase (`scriptPubKey`, `scriptSig`, `reqSigs`), and `value` is in BTC —
//! matching what ElectrumX/Fulcrum return when proxying bitcoind's
//! `getrawtransaction <txid> true`.
//!
//! It is intentionally self-contained (rather than reusing
//! `floresta-node`'s `RawTxJson`): `floresta-node` depends on this crate, and
//! its serializer emits a bitcoind-RPC shape (snake_case, singular `address`,
//! sats) that those clients do not accept.

use bitcoin::Network;
use bitcoin::ScriptBuf;
use bitcoin::Transaction;
use bitcoin::TxIn;
use bitcoin::TxOut;
use bitcoin::address::Address;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hex::DisplayHex;
use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerboseTxJson {
    pub txid: String,
    /// wtxid (segwit transaction hash).
    pub hash: String,
    pub version: i32,
    pub size: u64,
    pub vsize: u64,
    pub weight: u64,
    pub locktime: u32,
    pub vin: Vec<VinJson>,
    pub vout: Vec<VoutJson>,
    pub hex: String,
    pub confirmations: u32,
    #[serde(rename = "blockhash", skip_serializing_if = "Option::is_none")]
    pub blockhash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocktime: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<u32>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VinJson {
    pub txid: String,
    pub vout: u32,
    pub script_sig: ScriptSigJson,
    pub sequence: u32,
    pub txinwitness: Vec<String>,
}

#[derive(Serialize)]
pub struct ScriptSigJson {
    pub asm: String,
    pub hex: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VoutJson {
    /// Amount in BTC (bitcoind/Electrum verbose convention).
    pub value: f64,
    pub n: u32,
    pub script_pub_key: ScriptPubKeyJson,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScriptPubKeyJson {
    pub asm: String,
    pub hex: String,
    pub req_sigs: u32,
    #[serde(rename = "type")]
    pub type_: String,
    pub addresses: Vec<String>,
}

fn get_script_type(script: &ScriptBuf) -> &'static str {
    if script.is_p2pkh() {
        "pubkeyhash"
    } else if script.is_p2sh() {
        "scripthash"
    } else if script.is_p2wpkh() {
        "witness_v0_keyhash"
    } else if script.is_p2wsh() {
        "witness_v0_scripthash"
    } else if script.is_p2tr() {
        "witness_v1_taproot"
    } else {
        "nonstandard"
    }
}

fn make_vin(input: &TxIn) -> VinJson {
    VinJson {
        // Display form (big-endian) — clients use this to fetch the prevout tx.
        txid: input.previous_output.txid.to_string(),
        vout: input.previous_output.vout,
        script_sig: ScriptSigJson {
            asm: input.script_sig.to_asm_string(),
            hex: input.script_sig.to_hex_string(),
        },
        sequence: input.sequence.0,
        txinwitness: input
            .witness
            .iter()
            .map(|w| w.to_lower_hex_string())
            .collect(),
    }
}

fn make_vout(output: &TxOut, n: u32, network: Network) -> VoutJson {
    let spk = &output.script_pubkey;
    // Non-standard outputs (OP_RETURN, bare multisig) have no address — emit an
    // empty array instead of panicking like an `unwrap()` would.
    let addresses = Address::from_script(spk, network)
        .map(|a| vec![a.to_string()])
        .unwrap_or_default();
    VoutJson {
        value: output.value.to_btc(),
        n,
        script_pub_key: ScriptPubKeyJson {
            asm: spk.to_asm_string(),
            hex: spk.to_hex_string(),
            req_sigs: 1,
            type_: get_script_type(spk).to_string(),
            addresses,
        },
    }
}

/// Build the verbose JSON for a transaction. `confirmations`/`blockhash`/
/// `blocktime` describe the confirming block; pass `0`/`None` for an
/// unconfirmed (or unknown-height) transaction.
pub fn make_verbose_transaction(
    tx: &Transaction,
    network: Network,
    confirmations: u32,
    blockhash: Option<String>,
    blocktime: Option<u32>,
) -> VerboseTxJson {
    let vout = tx
        .output
        .iter()
        .enumerate()
        .map(|(n, o)| make_vout(o, u32::try_from(n).unwrap_or(u32::MAX), network))
        .collect();
    VerboseTxJson {
        txid: tx.compute_txid().to_string(),
        hash: tx.compute_wtxid().to_string(),
        version: tx.version.0,
        size: u64::try_from(tx.total_size()).unwrap_or(u64::MAX),
        vsize: u64::try_from(tx.vsize()).unwrap_or(u64::MAX),
        weight: tx.weight().to_wu(),
        locktime: tx.lock_time.to_consensus_u32(),
        vin: tx.input.iter().map(make_vin).collect(),
        vout,
        hex: serialize_hex(tx),
        confirmations,
        blockhash,
        // bitcoind sets `time == blocktime` for confirmed transactions.
        blocktime,
        time: blocktime,
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::Network;
    use bitcoin::Transaction;
    use bitcoin::consensus::encode::deserialize_hex;

    use super::make_verbose_transaction;

    // A real signet tx with one p2wpkh output (999890 sats) and one witness input.
    const TX_HEX: &str = "020000000001017ca523c5e6df0c014e837279ab49be1676a9fe7571c3989aeba1e5d534f4054a0000000000fdffffff01d2410f00000000001600142b6a2924aa9b1b115d1ac3098b0ba0e6ed510f2a02473044022071b8583ba1f10531b68cb5bd269fb0e75714c20c5a8bce49d8a2307d27a082df022069a978dac00dd9d5761aa48c7acc881617fa4d2573476b11685596b17d437595012103b193d06bd0533d053f959b50e3132861527e5a7a49ad59c5e80a265ff6a77605eece0100";

    #[test]
    fn verbose_shape_matches_blue_wallet_expectations() {
        let tx: Transaction = deserialize_hex(TX_HEX).unwrap();
        let vtx = make_verbose_transaction(
            &tx,
            Network::Signet,
            6,
            Some("000000000000000000000000000000000000000000000000000000000000dead".to_string()),
            Some(1_700_000_000),
        );

        // Typed assertions.
        assert_eq!(vtx.txid, tx.compute_txid().to_string());
        assert_eq!(vtx.confirmations, 6);
        assert_eq!(vtx.vin.len(), 1);
        assert_eq!(vtx.vout.len(), 1);
        assert!(
            (vtx.vout[0].value - 0.009_998_9).abs() < 1e-9,
            "value must be BTC"
        );
        assert_eq!(vtx.vout[0].script_pub_key.type_, "witness_v0_keyhash");
        assert_eq!(vtx.vout[0].script_pub_key.addresses.len(), 1);
        assert!(vtx.vout[0].script_pub_key.addresses[0].starts_with("tb1"));

        // JSON shape: Blue Wallet reads these exact (camelCase) keys.
        let json = serde_json::to_value(&vtx).unwrap();
        assert!(json["vin"].is_array());
        let vout0 = &json["vout"][0];
        assert!(vout0["scriptPubKey"]["addresses"].is_array());
        assert!(vout0["scriptPubKey"]["reqSigs"].is_number());
        assert!(vout0["scriptPubKey"]["type"].is_string());
        assert!(json["vin"][0]["scriptSig"]["hex"].is_string());
        assert!(json["vin"][0]["txinwitness"].is_array());
        assert_eq!(json["blockhash"].as_str().unwrap().len(), 64);
    }

    #[test]
    fn unconfirmed_omits_block_fields() {
        let tx: Transaction = deserialize_hex(TX_HEX).unwrap();
        let vtx = make_verbose_transaction(&tx, Network::Signet, 0, None, None);
        let json = serde_json::to_value(&vtx).unwrap();
        assert_eq!(vtx.confirmations, 0);
        assert!(json.get("blockhash").is_none());
        assert!(json.get("blocktime").is_none());
        assert!(json.get("time").is_none());
    }
}
