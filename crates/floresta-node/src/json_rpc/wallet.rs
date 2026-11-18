// SPDX-License-Identifier: MIT OR Apache-2.0

use bitcoin::constants::genesis_block;
use floresta_rpc::rpc_interfaces::WalletRpc;
use floresta_rpc::rpc_types::RescanConfidence;
use tracing::debug;
use tracing::info;

use super::server::RpcChain;
use super::server::RpcImpl;
use crate::json_rpc::res::jsonrpc_interface::JsonRpcError;

impl<Blockchain: RpcChain> WalletRpc for RpcImpl<Blockchain> {
    type Error = JsonRpcError;

    // rescanblockchain
    async fn rescan_blockchain(
        &self,
        start: Option<u32>,
        stop: Option<u32>,
        use_timestamp: Option<bool>,
        confidence: Option<RescanConfidence>,
    ) -> Result<bool, JsonRpcError> {
        let start = start.unwrap_or(0);
        let stop = stop.unwrap_or(0);
        let use_timestamp = use_timestamp.unwrap_or(false);
        let confidence = confidence.unwrap_or(RescanConfidence::Medium);
        let (start_height, stop_height) =
            self.get_rescan_interval(use_timestamp, start, stop, confidence)?;

        if stop_height != 0 && start_height > stop_height {
            return Err(JsonRpcError::InvalidRescanVal);
        }
        if self.chain.is_in_ibd() {
            return Err(JsonRpcError::InInitialBlockDownload);
        }

        let addresses = self.wallet.get_cached_addresses()?;
        if addresses.is_empty() {
            return Err(JsonRpcError::NoAddressesToRescan);
        }

        let filters = self.filters.clone().ok_or(JsonRpcError::NoBlockFilters)?;

        // Refuse to spawn a duplicate rescan if one is already running. This
        // backstops the UI: rapid taps on the Rescan button no longer launch
        // overlapping tasks that re-download the same filters and blocks.
        let tracker = self
            .rescan
            .try_start()
            .ok_or(JsonRpcError::RescanInProgress)?;

        let start = (start_height != 0).then_some(start_height);
        let stop = (stop_height != 0).then_some(stop_height);
        self.spawn_wallet_rescan(filters, addresses, start, stop, tracker);

        Ok(true)
    }

    // listdescriptors
    async fn list_descriptors(&self) -> Result<Vec<String>, JsonRpcError> {
        let descriptors = self
            .wallet
            .get_descriptors()
            .map_err(|e| JsonRpcError::Wallet(e.to_string()))?;
        Ok(descriptors)
    }

    // loaddescriptor
    async fn load_descriptor(&self, descriptor: String) -> Result<bool, JsonRpcError> {
        let addresses = self.wallet.push_descriptor(&descriptor)?;
        info!("Descriptor pushed: {descriptor}");
        debug!("Rescanning with block filters for addresses: {addresses:?}");

        if addresses.is_empty() {
            return Ok(true);
        }

        let filters = self.filters.clone().ok_or(JsonRpcError::NoBlockFilters)?;

        // Always persist the descriptor; only kick off a rescan if one isn't
        // already running. Otherwise ask the running one for a follow-up pass:
        // it took its addresses before this descriptor was cached.
        let tracker = match self.rescan.try_start() {
            Some(tracker) => tracker,
            None => {
                debug!(
                    "rescan already in progress; descriptor cached, a follow-up rescan will cover it"
                );
                self.rescan.request_followup();

                // The running rescan may have ended between our failed claim and the request,
                // after it last looked for one. Then nobody is left to take it: run it ourselves.
                let Some(tracker) = self.rescan.try_start() else {
                    return Ok(true);
                };
                if !self.rescan.take_followup() {
                    // Whoever ended in between saw the request and is running the follow-up.
                    return Ok(true);
                }
                tracker
            }
        };

        let addresses = self.wallet.get_cached_addresses()?;
        self.spawn_wallet_rescan(filters, addresses, None, None, tracker);

        Ok(true)
    }
}

impl<Blockchain: RpcChain> RpcImpl<Blockchain> {
    fn get_rescan_interval(
        &self,
        use_timestamp: bool,
        start: u32,
        stop: u32,
        confidence: RescanConfidence,
    ) -> Result<(u32, u32), JsonRpcError> {
        if use_timestamp {
            let start_height = self.get_block_height_by_timestamp(start, &confidence)?;

            let stop_height = self.get_block_height_by_timestamp(stop, &RescanConfidence::Exact)?;

            return Ok((start_height, stop_height));
        }

        let (tip, _) = self
            .chain
            .get_best_block()
            .map_err(|_| JsonRpcError::Chain)?;

        if stop > tip {
            return Err(JsonRpcError::InvalidRescanVal);
        }

        Ok((start, stop))
    }

    /// Retrieves the height of the block that was mined in the given timestamp.
    ///
    /// `timestamp` has an alias, 0 will directly refer to the network's genesis timestamp.
    fn get_block_height_by_timestamp(
        &self,
        timestamp: u32,
        confidence: &RescanConfidence,
    ) -> Result<u32, JsonRpcError> {
        /// Simple helper to avoid code reuse.
        fn get_block_time<BlockChain: RpcChain>(
            provider: &RpcImpl<BlockChain>,
            at: u32,
        ) -> Result<u32, JsonRpcError> {
            let hash = provider.get_block_hash_inner(at)?;
            let block = provider.get_block_header_inner(hash)?;
            Ok(block.time)
        }

        let genesis_timestamp = genesis_block(self.network).header.time;

        if timestamp == 0 || timestamp == genesis_timestamp {
            return Ok(0);
        };

        let (tip_height, _) = self
            .chain
            .get_best_block()
            .map_err(|_| JsonRpcError::BlockNotFound)?;

        let tip_time = get_block_time(self, tip_height)?;

        if timestamp < genesis_timestamp || timestamp > tip_time {
            return Err(JsonRpcError::InvalidTimestamp);
        }

        let adjusted_target = timestamp.saturating_sub(confidence.as_secs());

        let mut high = tip_height;
        let mut low = 0;
        let max_iters = tip_height.ilog2() + 1;
        for _ in 0..max_iters {
            let cut = (high + low) / 2;

            let block_timestamp = get_block_time(self, cut)?;

            if block_timestamp == adjusted_target {
                debug!("found a precise block; returning {cut}");
                return Ok(cut);
            }

            if high - low <= 2 {
                debug!("didn't find a precise block; returning {low}");
                return Ok(low);
            }

            if block_timestamp > adjusted_target {
                high = cut;
            } else {
                low = cut;
            }
        }

        // This is pretty much unreachable.
        Err(JsonRpcError::BlockNotFound)
    }
}
