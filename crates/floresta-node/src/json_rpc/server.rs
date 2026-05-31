// SPDX-License-Identifier: MIT OR Apache-2.0

use core::net::SocketAddr;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use axum::Json;
use axum::Router;
use axum::body::Body;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::Method;
use axum::http::Response;
use axum::http::StatusCode;
use axum::routing::post;
use bitcoin::Address;
use bitcoin::BlockHash;
use bitcoin::Network;
use bitcoin::ScriptBuf;
use bitcoin::Transaction;
use bitcoin::TxIn;
use bitcoin::TxOut;
use bitcoin::Txid;
use bitcoin::consensus::deserialize;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hashes::Hash;
use bitcoin::hashes::hex::FromHex;
use bitcoin::hex::DisplayHex;
use floresta_chain::ThreadSafeChain;
use floresta_compact_filters::flat_filters_store::FlatFiltersStore;
use floresta_compact_filters::network_filters::NetworkFilters;
use floresta_watch_only::AddressCache;
use floresta_watch_only::CachedTransaction;
use floresta_watch_only::kv_database::KvDatabase;
use floresta_wire::node_interface::NodeInterface;
use serde_json::Value;
use serde_json::json;
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::warn;

use super::res::JsonRpcError;
use super::res::RawTxJson;
use super::res::RpcError;
use super::res::ScriptPubKeyJson;
use super::res::ScriptSigJson;
use super::res::TxInJson;
use super::res::TxOutJson;
use crate::json_rpc::request::RpcRequest;
use crate::json_rpc::request::arg_parser::get_bool;
use crate::json_rpc::request::arg_parser::get_hash;
use crate::json_rpc::request::arg_parser::get_hashes_array;
use crate::json_rpc::request::arg_parser::get_numeric;
use crate::json_rpc::request::arg_parser::get_optional_field;
use crate::json_rpc::request::arg_parser::get_string;
use crate::json_rpc::res::RescanConfidence;

pub(super) struct InflightRpc {
    pub method: String,
    pub when: Instant,
}

/// Utility trait to ensure that the chain implements all the necessary traits
///
/// Instead of using this very complex trait bound declaration on every impl block
/// and function, this trait makes sure everything we need is implemented.
pub trait RpcChain: ThreadSafeChain + Clone {}

impl<T> RpcChain for T where T: ThreadSafeChain + Clone {}

pub struct RpcImpl<Blockchain: RpcChain> {
    pub(super) block_filter_storage: Option<Arc<NetworkFilters<FlatFiltersStore>>>,
    /// Resolved absolute height at which compact filter download started for
    /// the on-disk store. Surfaced via `getblockchaininfo.filters_start` so
    /// clients can compute filter sync progress against the actual download
    /// window rather than the chain tip.
    pub(super) block_filter_start: Option<u32>,
    pub(super) network: Network,
    pub(super) chain: Blockchain,
    pub(super) wallet: Arc<AddressCache<KvDatabase>>,
    pub(super) node: NodeInterface,
    pub(super) kill_signal: Arc<RwLock<bool>>,
    pub(super) inflight: Arc<RwLock<HashMap<Value, InflightRpc>>>,
    pub(super) log_path: PathBuf,
    pub(super) start_time: Instant,
    /// Whether a wallet rescan (`rescanblockchain` or the rescan kicked off by
    /// `loaddescriptor`) is currently running. Used to dedup concurrent rescans
    /// and to let clients tell, via `getblockchaininfo`, that the wallet is
    /// still being scanned even though filter download already reached the tip.
    pub(super) rescan_in_progress: Arc<AtomicBool>,
    /// Matched blocks processed so far by the in-progress rescan.
    pub(super) rescan_blocks_processed: Arc<AtomicU32>,
    /// Total matched blocks the in-progress rescan has to process.
    pub(super) rescan_blocks_total: Arc<AtomicU32>,
    pub(super) user_agent: String,
    pub(super) proxy: Option<SocketAddr>,
}

type Result<T> = std::result::Result<T, JsonRpcError>;

impl<Blockchain: RpcChain> RpcImpl<Blockchain> {
    fn get_transaction(&self, tx_id: Txid, verbosity: Option<bool>) -> Result<Value> {
        if verbosity == Some(true) {
            let tx = self
                .wallet
                .get_transaction(&tx_id)
                .ok_or(JsonRpcError::TxNotFound);
            return tx.map(|tx| serde_json::to_value(self.make_raw_transaction(tx)).unwrap());
        }

        self.wallet
            .get_transaction(&tx_id)
            .and_then(|tx| serde_json::to_value(self.make_raw_transaction(tx)).ok())
            .ok_or(JsonRpcError::TxNotFound)
    }

    fn load_descriptor(&self, descriptor: String) -> Result<bool> {
        let addresses = self.wallet.push_descriptor(&descriptor)?;
        info!("Descriptor pushed: {descriptor}");
        debug!("Rescanning with block filters for addresses: {addresses:?}");

        let addresses = self.wallet.get_cached_addresses();
        let wallet = self.wallet.clone();
        if self.block_filter_storage.is_none() {
            return Err(JsonRpcError::InInitialBlockDownload);
        };

        let cfilters = self.block_filter_storage.as_ref().unwrap().clone();
        let node = self.node.clone();
        let chain = self.chain.clone();

        // Always persist the descriptor; only kick off a rescan if one isn't
        // already running. If a rescan is in progress we skip spawning a
        // duplicate — the freshly cached addresses are picked up by the next
        // rescan (the client triggers one once filters reach the tip).
        if self
            .rescan_in_progress
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            self.rescan_blocks_processed.store(0, Ordering::SeqCst);
            self.rescan_blocks_total.store(0, Ordering::SeqCst);
            tokio::task::spawn(Self::rescan_with_block_filters(
                addresses,
                chain,
                wallet,
                cfilters,
                node,
                None,
                None,
                self.rescan_in_progress.clone(),
                self.rescan_blocks_processed.clone(),
                self.rescan_blocks_total.clone(),
            ));
        } else {
            debug!(
                "rescan already in progress; descriptor cached, will be covered by the next rescan"
            );
        }

        Ok(true)
    }

    fn rescan_blockchain(
        &self,
        start: Option<u32>,
        stop: Option<u32>,
        use_timestamp: bool,
        confidence: Option<RescanConfidence>,
    ) -> Result<bool> {
        let (start_height, stop_height) =
            self.get_rescan_interval(use_timestamp, start, stop, confidence)?;

        if stop_height != 0 && start_height >= stop_height {
            // When stop height is a non zero value it needs atleast to be greater than start_height.
            return Err(JsonRpcError::InvalidRescanVal);
        }

        // if we are on ibd, we don't have any filters to rescan
        if self.chain.is_in_ibd() {
            return Err(JsonRpcError::InInitialBlockDownload);
        }

        let addresses = self.wallet.get_cached_addresses();

        if addresses.is_empty() {
            return Err(JsonRpcError::NoAddressesToRescan);
        }

        let wallet = self.wallet.clone();

        if self.block_filter_storage.is_none() {
            return Err(JsonRpcError::NoBlockFilters);
        };

        let cfilters = self.block_filter_storage.as_ref().unwrap().clone();

        let node = self.node.clone();

        let chain = self.chain.clone();

        // Refuse to spawn a duplicate rescan if one is already running. This
        // backstops the UI: rapid taps on the Rescan button no longer launch
        // overlapping tasks that re-fetch the same blocks.
        if self
            .rescan_in_progress
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(JsonRpcError::RescanInProgress);
        }

        self.rescan_blocks_processed.store(0, Ordering::SeqCst);
        self.rescan_blocks_total.store(0, Ordering::SeqCst);

        tokio::task::spawn(Self::rescan_with_block_filters(
            addresses,
            chain,
            wallet,
            cfilters,
            node,
            (start_height != 0).then_some(start_height), // Its ugly but to maintain the API here its necessary to recast to a Option.
            (stop_height != 0).then_some(stop_height),
            self.rescan_in_progress.clone(),
            self.rescan_blocks_processed.clone(),
            self.rescan_blocks_total.clone(),
        ));
        Ok(true)
    }

    async fn send_raw_transaction(&self, tx: String) -> Result<Txid> {
        let tx_hex = Vec::from_hex(&tx).map_err(|_| JsonRpcError::InvalidHex)?;
        let tx: Transaction =
            deserialize(&tx_hex).map_err(|e| JsonRpcError::Decode(e.to_string()))?;

        Ok(self
            .node
            .broadcast_transaction(tx)
            .await
            .map_err(|e| JsonRpcError::Node(e.to_string()))??)
    }
}

async fn handle_json_rpc_request(
    req: RpcRequest,
    state: Arc<RpcImpl<impl RpcChain>>,
) -> Result<serde_json::Value> {
    let RpcRequest {
        jsonrpc,
        method,
        params,
        id,
    } = req;

    if let Some(version) = jsonrpc {
        if !["1.0", "2.0"].contains(&version.as_str()) {
            return Err(JsonRpcError::InvalidRequest);
        }
    }

    state.inflight.write().await.insert(
        id.clone(),
        InflightRpc {
            method: method.clone(),
            when: Instant::now(),
        },
    );

    match method.as_str() {
        // blockchain
        "getbestblockhash" => {
            let hash = state.get_best_block_hash()?;
            Ok(serde_json::to_value(hash).unwrap())
        }

        "getblock" => {
            let hash = get_hash(&params, 0, "block_hash")?;
            // Default value in case of missing parameter is 1
            let verbosity: u8 =
                get_optional_field(&params, 1, "verbosity", get_numeric)?.unwrap_or(1);

            state
                .get_block(hash, verbosity)
                .await
                .map(|v| serde_json::to_value(v).expect("GetBlockRes implements serde"))
        }

        "getblockchaininfo" => state
            .get_blockchain_info()
            .map(|v| serde_json::to_value(v).unwrap()),

        "getblockcount" => state
            .get_block_count()
            .map(|v| serde_json::to_value(v).unwrap()),

        "getblockfrompeer" => {
            let hash = get_hash(&params, 0, "block_hash")?;

            state.get_block(hash, 0).await?;

            Ok(Value::Null)
        }

        "getblockhash" => {
            let height = get_numeric(&params, 0, "block_height")?;
            state
                .get_block_hash(height)
                .map(|h| serde_json::to_value(h).unwrap())
        }

        "getblockheader" => {
            let hash = get_hash(&params, 0, "block_hash")?;
            let verbosity = get_optional_field(&params, 1, "verbosity", get_bool)?.unwrap_or(true);

            state
                .get_block_header(hash, verbosity)
                .await
                .map(|h| serde_json::to_value(h).unwrap())
        }

        "getdeploymentinfo" => {
            let blockhash = get_optional_field(&params, 0, "blockhash", get_hash)?;
            state
                .get_deployment_info(blockhash)
                .map(|info| serde_json::to_value(info).unwrap())
        }

        "getdifficulty" => state
            .get_difficulty()
            .map(|v| serde_json::to_value(v).unwrap()),

        "gettxout" => {
            let txid = get_hash(&params, 0, "txid")?;
            let vout = get_numeric(&params, 1, "vout")?;
            let include_mempool =
                get_optional_field(&params, 2, "include_mempool", get_bool)?.unwrap_or(false);

            state
                .get_tx_out(txid, vout, include_mempool)
                .map(|v| serde_json::to_value(v).unwrap())
        }

        "gettxoutproof" => {
            let txids = get_hashes_array(&params, 0, "txids")?;
            let block_hash = get_optional_field(&params, 1, "block_hash", get_hash)?;

            Ok(serde_json::to_value(
                state
                    .get_txout_proof(&txids, block_hash)
                    .await?
                    .0
                    .to_lower_hex_string(),
            )
            .expect("GetTxOutProof implements serde"))
        }

        "getrawtransaction" => {
            let txid = get_hash(&params, 0, "txid")?;
            let verbosity = get_optional_field(&params, 1, "verbosity", get_bool)?;

            state
                .get_transaction(txid, verbosity)
                .map(|v| serde_json::to_value(v).unwrap())
        }

        "getroots" => state.get_roots().map(|v| serde_json::to_value(v).unwrap()),

        "findtxout" => {
            let txid = get_hash(&params, 0, "txid")?;
            let vout = get_numeric(&params, 1, "vout")?;
            let script = get_string(&params, 2, "script")?;
            let script = ScriptBuf::from_hex(&script).map_err(|_| JsonRpcError::InvalidScript)?;
            let height = get_numeric(&params, 3, "height")?;

            let state = state.clone();
            state.find_tx_out(txid, vout, script, height).await
        }

        // control
        "getmemoryinfo" => {
            let mode =
                get_optional_field(&params, 0, "mode", get_string)?.unwrap_or("stats".into());

            state
                .get_memory_info(&mode)
                .map(|v| serde_json::to_value(v).unwrap())
        }

        "getrpcinfo" => state
            .get_rpc_info()
            .await
            .map(|v| serde_json::to_value(v).unwrap()),

        // help
        // logging
        "stop" => state.stop().await.map(|v| serde_json::to_value(v).unwrap()),

        "uptime" => {
            let uptime = state.uptime();
            Ok(serde_json::to_value(uptime).unwrap())
        }

        // network
        "getpeerinfo" => state
            .get_peer_info()
            .await
            .map(|v| serde_json::to_value(v).unwrap()),

        "getconnectioncount" => state
            .get_connection_count()
            .await
            .map(|v| serde_json::to_value(v).unwrap()),

        "getnetworkinfo" => state
            .get_network_info()
            .await
            .map(|v| serde_json::to_value(v).unwrap()),

        "addnode" => {
            let node = get_string(&params, 0, "node")?;
            let command = get_string(&params, 1, "command")?;
            let v2transport =
                get_optional_field(&params, 2, "V2transport", get_bool)?.unwrap_or(false);

            state
                .add_node(node, command, v2transport)
                .await
                .map(|v| serde_json::to_value(v).unwrap())
        }

        "disconnectnode" => {
            let node_address = get_string(&params, 0, "node_address")?;
            let node_id = get_optional_field(&params, 1, "node_id", get_numeric)?;

            state
                .disconnect_node(node_address, node_id)
                .await
                .map(|v| serde_json::to_value(v).unwrap())
        }

        "ping" => {
            state.ping().await?;

            Ok(serde_json::json!(null))
        }

        // wallet
        "loaddescriptor" => {
            let descriptor = get_string(&params, 0, "descriptor")?;

            state
                .load_descriptor(descriptor)
                .map(|v| serde_json::to_value(v).unwrap())
        }

        "rescanblockchain" => {
            let start_height = get_optional_field(&params, 0, "start_height", get_numeric)?;
            let stop_height = get_optional_field(&params, 1, "stop_height", get_numeric)?;
            let use_timestamp =
                get_optional_field(&params, 2, "use_timestamp", get_bool)?.unwrap_or(false);
            let confidence_str = get_optional_field(&params, 3, "confidence", get_string)?
                .unwrap_or("medium".into());

            let confidence = match confidence_str.as_str() {
                "low" => RescanConfidence::Low,
                "medium" => RescanConfidence::Medium,
                "high" => RescanConfidence::High,
                "exact" => RescanConfidence::Exact,
                _ => return Err(JsonRpcError::InvalidRescanVal),
            };

            state
                .rescan_blockchain(start_height, stop_height, use_timestamp, Some(confidence))
                .map(|v| serde_json::to_value(v).unwrap())
        }

        "sendrawtransaction" => {
            let tx = get_string(&params, 0, "hex")?;
            state
                .send_raw_transaction(tx)
                .await
                .map(|v| serde_json::to_value(v).unwrap())
        }

        "listdescriptors" => state
            .list_descriptors()
            .map(|v| serde_json::to_value(v).unwrap()),

        _ => {
            let error = JsonRpcError::MethodNotFound;
            Err(error)
        }
    }
}

fn get_http_error_code(err: &JsonRpcError) -> u16 {
    match err {
        // you messed up
        JsonRpcError::InvalidHex
        | JsonRpcError::InvalidAddress
        | JsonRpcError::InvalidScript
        | JsonRpcError::InvalidRequest
        | JsonRpcError::InvalidDescriptor(_)
        | JsonRpcError::InvalidVerbosityLevel
        | JsonRpcError::Decode(_)
        | JsonRpcError::NoBlockFilters
        | JsonRpcError::InvalidMemInfoMode
        | JsonRpcError::InvalidAddnodeCommand
        | JsonRpcError::InvalidDisconnectNodeCommand
        | JsonRpcError::PeerNotFound
        | JsonRpcError::InvalidTimestamp
        | JsonRpcError::InvalidRescanVal
        | JsonRpcError::NoAddressesToRescan
        | JsonRpcError::InvalidParameterType(_)
        | JsonRpcError::MissingParameter(_)
        | JsonRpcError::ChainWorkOverflow
        | JsonRpcError::ConversionOverflow(_)
        | JsonRpcError::MempoolAccept(_)
        | JsonRpcError::Wallet(_) => 400,

        // idunnolol
        JsonRpcError::MethodNotFound | JsonRpcError::BlockNotFound | JsonRpcError::TxNotFound => {
            404
        }

        // we messed up, sowwy
        JsonRpcError::InInitialBlockDownload
        | JsonRpcError::RescanInProgress
        | JsonRpcError::Node(_)
        | JsonRpcError::Chain
        | JsonRpcError::Filters(_) => 503,
    }
}

fn get_json_rpc_error_code(err: &JsonRpcError) -> i32 {
    match err {
        // Parse Error
        JsonRpcError::Decode(_) | JsonRpcError::InvalidParameterType(_) => -32700,

        // Invalid Request
        JsonRpcError::InvalidHex
        | JsonRpcError::MissingParameter(_)
        | JsonRpcError::InvalidAddress
        | JsonRpcError::InvalidScript
        | JsonRpcError::MethodNotFound
        | JsonRpcError::InvalidRequest
        | JsonRpcError::InvalidDescriptor(_)
        | JsonRpcError::InvalidVerbosityLevel
        | JsonRpcError::TxNotFound
        | JsonRpcError::BlockNotFound
        | JsonRpcError::InvalidTimestamp
        | JsonRpcError::InvalidMemInfoMode
        | JsonRpcError::InvalidAddnodeCommand
        | JsonRpcError::InvalidDisconnectNodeCommand
        | JsonRpcError::PeerNotFound
        | JsonRpcError::InvalidRescanVal
        | JsonRpcError::NoAddressesToRescan
        | JsonRpcError::ChainWorkOverflow
        | JsonRpcError::ConversionOverflow(_)
        | JsonRpcError::Wallet(_)
        | JsonRpcError::MempoolAccept(_) => -32600,

        // server error
        JsonRpcError::InInitialBlockDownload
        | JsonRpcError::RescanInProgress
        | JsonRpcError::Node(_)
        | JsonRpcError::Chain
        | JsonRpcError::NoBlockFilters
        | JsonRpcError::Filters(_) => -32603,
    }
}

async fn json_rpc_request(
    State(state): State<Arc<RpcImpl<impl RpcChain>>>,
    body: Bytes,
) -> Response<Body> {
    let req: RpcRequest = match serde_json::from_slice(&body) {
        Ok(req) => req,
        Err(e) => {
            let error = RpcError {
                code: -32700,
                message: format!("Parse error: {e}"),
                data: None,
            };
            let body = json!({
                "error": error,
                "id": Value::Null,
            });
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap();
        }
    };

    debug!("Received JSON-RPC request: {req:?}");

    let id = req.id.clone();
    let res = handle_json_rpc_request(req, state.clone()).await;

    state.inflight.write().await.remove(&id);

    match res {
        Ok(res) => {
            let body = serde_json::json!({
                "result": res,
                "id": id,
            });

            axum::http::Response::builder()
                .status(axum::http::StatusCode::OK)
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap()
        }

        Err(e) => {
            let http_error_code = get_http_error_code(&e);
            let json_rpc_error_code = get_json_rpc_error_code(&e);
            let error = RpcError {
                code: json_rpc_error_code,
                message: e.to_string(),
                data: None,
            };

            let body = serde_json::json!({
                "error": error,
                "id": id,
            });

            axum::http::Response::builder()
                .status(axum::http::StatusCode::from_u16(http_error_code).unwrap())
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap()
        }
    }
}

async fn cannot_get(_state: State<Arc<RpcImpl<impl RpcChain>>>) -> Json<serde_json::Value> {
    Json(json!({
        "error": "Cannot get on this route",
    }))
}

/// Resets the rescan-in-progress flag on drop, so the flag is cleared on every
/// exit path of the spawned rescan task — normal completion, early return, or
/// panic — and a future rescan is never permanently blocked.
struct RescanInProgressGuard(Arc<AtomicBool>);

impl Drop for RescanInProgressGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

impl<Blockchain: RpcChain> RpcImpl<Blockchain> {
    /// How many times to retry fetching a single matched block before giving up
    /// on it for this rescan pass. Bounds the work-queue so an unreachable block
    /// (no peer has it) can't loop forever.
    const MAX_BLOCK_FETCH_ATTEMPTS: u8 = 5;

    /// Per-attempt cap on a single block download. `get_block` can otherwise hang
    /// forever: a peer that accepts the request but never replies leaves the
    /// node-side responder uncompleted (user requests are not timed out), so the
    /// await never resolves. Bounding it turns a silent stall into the retry path.
    const BLOCK_FETCH_TIMEOUT: Duration = Duration::from_secs(30);

    #[allow(clippy::too_many_arguments)]
    async fn rescan_with_block_filters(
        addresses: Vec<ScriptBuf>,
        chain: Blockchain,
        wallet: Arc<AddressCache<KvDatabase>>,
        cfilters: Arc<NetworkFilters<FlatFiltersStore>>,
        node: NodeInterface,
        start_height: Option<u32>,
        stop_height: Option<u32>,
        in_progress: Arc<AtomicBool>,
        blocks_processed: Arc<AtomicU32>,
        blocks_total: Arc<AtomicU32>,
    ) -> Result<()> {
        // Clears `in_progress` on every exit path (including panic / early
        // return) so a stuck flag can never permanently block future rescans.
        let _guard = RescanInProgressGuard(in_progress);

        let blocks = match cfilters.match_any(
            addresses.iter().map(|a| a.as_bytes()).collect(),
            start_height,
            stop_height,
            chain.clone(),
        ) {
            Ok(blocks) => blocks,
            Err(e) => {
                // A filter-store read error (e.g. I/O on the on-disk store) can't
                // be recovered here; log and abort the rescan instead of panicking
                // the spawned task. The in-progress guard still clears on return.
                warn!("rescan aborted: could not read compact filters: {e:?}");
                return Ok(());
            }
        };

        info!("rescan filter hits: {blocks:?}");

        blocks_total.store(blocks.len() as u32, Ordering::SeqCst);
        blocks_processed.store(0, Ordering::SeqCst);

        // A matched block whose download fails must be retried, not dropped.
        // `get_block` yields `Ok(None)` on a peer NOTFOUND, `Err` when the
        // responder is dropped (inflight cap / peer disconnect), or our `timeout`
        // elapses when a peer accepts the request but never replies — all
        // transient on a phone with few, flaky peers. The old code's
        // `if let Ok(Some(block))` swallowed the first two and could hang forever
        // on the third, silently losing the wallet transactions those blocks
        // carried, which is why a single rescan was never enough.
        let mut queue: VecDeque<BlockHash> = blocks.into_iter().collect();
        let mut attempts: HashMap<BlockHash, u8> = HashMap::new();
        let mut processed: u32 = 0;
        let mut failed: u32 = 0;

        while let Some(hash) = queue.pop_front() {
            // `timeout` guards against a peer that never replies (see
            // BLOCK_FETCH_TIMEOUT): on elapse we drop the request and fall into
            // the retry path below, which re-requests (likely from another peer).
            match tokio::time::timeout(Self::BLOCK_FETCH_TIMEOUT, node.get_block(hash)).await {
                Ok(Ok(Some(block))) => {
                    match chain.get_block_height(&block.block_hash()) {
                        Ok(Some(height)) => {
                            wallet.block_process(&block, height);
                            processed += 1;
                            blocks_processed.fetch_add(1, Ordering::SeqCst);
                        }
                        // The block matched our request, so the chain should know
                        // its height; a miss means a chain-store error or a deep
                        // reorg evicted it. Retrying the fetch won't help, so count
                        // it and move on instead of panicking.
                        Ok(None) => {
                            warn!("rescan: fetched block {hash} has no height (reorged out?); skipping");
                            failed += 1;
                        }
                        Err(e) => {
                            warn!("rescan: height lookup failed for block {hash}: {e:?}; skipping");
                            failed += 1;
                        }
                    }
                }
                _ => {
                    let attempt = attempts.entry(hash).or_insert(0);
                    *attempt += 1;
                    if *attempt >= Self::MAX_BLOCK_FETCH_ATTEMPTS {
                        warn!("rescan: giving up on block {hash} after {attempt} attempts");
                        failed += 1;
                        continue;
                    }
                    let backoff = Duration::from_millis(500 * u64::from(*attempt))
                        .min(Duration::from_secs(5));
                    tokio::time::sleep(backoff).await;
                    queue.push_back(hash);
                }
            }
        }

        if failed > 0 {
            warn!("rescan complete: processed {processed} block(s), {failed} unreachable");
        } else {
            info!("rescan complete: processed {processed} block(s)");
        }

        Ok(())
    }

    fn make_vin(&self, input: TxIn) -> TxInJson {
        let txid = serialize_hex(&input.previous_output.txid);
        let vout = input.previous_output.vout;
        let sequence = input.sequence.0;
        TxInJson {
            txid,
            vout,
            script_sig: ScriptSigJson {
                asm: input.script_sig.to_asm_string(),
                hex: input.script_sig.to_hex_string(),
            },
            witness: input
                .witness
                .iter()
                .map(|w| w.to_hex_string(bitcoin::hex::Case::Upper))
                .collect(),
            sequence,
        }
    }

    fn get_script_type(script: ScriptBuf) -> Option<&'static str> {
        if script.is_p2pkh() {
            return Some("p2pkh");
        }
        if script.is_p2sh() {
            return Some("p2sh");
        }
        if script.is_p2wpkh() {
            return Some("v0_p2wpkh");
        }
        if script.is_p2wsh() {
            return Some("v0_p2wsh");
        }
        None
    }

    fn make_vout(&self, output: TxOut, n: u32) -> TxOutJson {
        let value = output.value;
        TxOutJson {
            value: value.to_sat(),
            n,
            script_pub_key: ScriptPubKeyJson {
                asm: output.script_pubkey.to_asm_string(),
                hex: output.script_pubkey.to_hex_string(),
                req_sigs: 0, // This field is deprecated
                address: Address::from_script(&output.script_pubkey, self.network)
                    .map(|a| a.to_string())
                    .unwrap(),
                type_: Self::get_script_type(output.script_pubkey)
                    .unwrap_or("nonstandard")
                    .to_string(),
            },
        }
    }

    fn make_raw_transaction(&self, tx: CachedTransaction) -> RawTxJson {
        let raw_tx = tx.tx;
        let in_active_chain = tx.height != 0;
        let hex = serialize_hex(&raw_tx);
        let txid = serialize_hex(&raw_tx.compute_txid());
        let block_hash = self
            .chain
            .get_block_hash(tx.height)
            .unwrap_or(BlockHash::all_zeros());
        let tip = self.chain.get_height().unwrap();
        let confirmations = if in_active_chain {
            tip - tx.height + 1
        } else {
            0
        };

        RawTxJson {
            in_active_chain,
            hex,
            txid,
            hash: serialize_hex(&raw_tx.compute_wtxid()),
            size: raw_tx.total_size() as u32,
            vsize: raw_tx.vsize() as u32,
            weight: raw_tx.weight().to_wu() as u32,
            version: raw_tx.version.0 as u32,
            locktime: raw_tx.lock_time.to_consensus_u32(),
            vin: raw_tx
                .input
                .iter()
                .map(|input| self.make_vin(input.clone()))
                .collect(),
            vout: raw_tx
                .output
                .into_iter()
                .enumerate()
                .map(|(i, output)| self.make_vout(output, i as u32))
                .collect(),
            blockhash: serialize_hex(&block_hash),
            confirmations,
            blocktime: self
                .chain
                .get_block_header(&block_hash)
                .map(|h| h.time)
                .unwrap_or(0),
            time: self
                .chain
                .get_block_header(&block_hash)
                .map(|h| h.time)
                .unwrap_or(0),
        }
    }

    // TODO(@luisschwab): get rid of this once
    // https://github.com/rust-bitcoin/rust-bitcoin/pull/4639 makes it into a release.
    fn get_port(net: &Network) -> u16 {
        match net {
            Network::Bitcoin => 8332,
            Network::Signet => 38332,
            Network::Testnet => 18332,
            Network::Testnet4 => 48332,
            Network::Regtest => 18442,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        chain: Blockchain,
        wallet: Arc<AddressCache<KvDatabase>>,
        node: NodeInterface,
        kill_signal: Arc<RwLock<bool>>,
        network: Network,
        block_filter_storage: Option<Arc<NetworkFilters<FlatFiltersStore>>>,
        block_filter_start: Option<u32>,
        address: Option<SocketAddr>,
        log_path: impl AsRef<Path>,
        user_agent: String,
        proxy: Option<SocketAddr>,
    ) {
        let address = address.unwrap_or_else(|| {
            format!("127.0.0.1:{}", Self::get_port(&network))
                .parse()
                .unwrap()
        });

        let listener = match tokio::net::TcpListener::bind(address).await {
            Ok(listener) => {
                let local_addr = listener
                    .local_addr()
                    .expect("Infallible: listener binding was `Ok`");
                info!("RPC server is running at {local_addr}");
                listener
            }
            Err(_) => {
                error!(
                    "Failed to bind to address {address}. Floresta is probably already running.",
                );
                std::process::exit(-1);
            }
        };

        let router = Router::new()
            .route("/", post(json_rpc_request).get(cannot_get))
            .layer(
                CorsLayer::new()
                    .allow_private_network(true)
                    .allow_methods([Method::POST, Method::HEAD]),
            )
            .with_state(Arc::new(RpcImpl {
                chain,
                wallet,
                node,
                kill_signal,
                network,
                block_filter_storage,
                block_filter_start,
                inflight: Arc::new(RwLock::new(HashMap::new())),
                log_path: log_path.as_ref().into(),
                start_time: Instant::now(),
                rescan_in_progress: Arc::new(AtomicBool::new(false)),
                rescan_blocks_processed: Arc::new(AtomicU32::new(0)),
                rescan_blocks_total: Arc::new(AtomicU32::new(0)),
                user_agent,
                proxy,
            }));

        axum::serve(listener, router)
            .await
            .expect("failed to start rpc server");
    }
}
