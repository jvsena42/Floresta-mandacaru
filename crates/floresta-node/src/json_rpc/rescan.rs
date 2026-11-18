// SPDX-License-Identifier: MIT OR Apache-2.0

//! Wallet rescans driven by the compact-filter manager.
//!
//! Only one rescan runs at a time. [`RescanState`] holds that slot and the progress
//! `getblockchaininfo` reports; descriptors loaded while a rescan runs ask it for a
//! follow-up pass instead of starting one of their own.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;
use std::time::Duration;

use bitcoin::ScriptBuf;
use floresta_compact_filters::filters_man::FilterManError;
use floresta_compact_filters::filters_man::FilterManHandle;
use floresta_compact_filters::filters_man::RescanProgress;
use floresta_compact_filters::filters_man::RescanRequest;
use floresta_compact_filters::filters_man::RescanStatus;
use floresta_watch_only::AddressCache;
use floresta_watch_only::kv_database::KvDatabase;
use serde_json::Value;
use tracing::error;
use tracing::info;
use tracing::warn;

use super::res::jsonrpc_interface::JsonRpcError;
use super::server::RpcChain;
use super::server::RpcImpl;

type Result<T> = std::result::Result<T, JsonRpcError>;

impl<Blockchain: RpcChain> RpcImpl<Blockchain> {
    /// Runs a tracked wallet rescan in the background, followed by one more
    /// pass over every cached address for each descriptor loaded meanwhile, and
    /// by a pass over the addresses the wallet derived while scanning.
    pub(super) fn spawn_wallet_rescan(
        &self,
        filters: FilterManHandle,
        mut addresses: Vec<ScriptBuf>,
        mut start: Option<u32>,
        mut stop: Option<u32>,
        mut tracker: RescanTracker,
    ) {
        let chain = self.chain.clone();
        let wallet = self.wallet.clone();
        let rescan = self.rescan.clone();

        tokio::spawn(async move {
            // Addresses taken from the wallet's pending-rescan queue that the current pass
            // covers: handed back if it fails, so the next rescan takes them again.
            let mut taken: Vec<ScriptBuf> = Vec::new();
            loop {
                let result = Self::rescan_with_block_filters(
                    addresses,
                    chain.clone(),
                    wallet.clone(),
                    filters.clone(),
                    start,
                    stop,
                    Some(&tracker),
                )
                .await;
                let failed = result.is_err();
                if let Err(error) = result {
                    error!(?error, "wallet rescan failed");
                    // The same wording a caller of the RPC would have got.
                    let rpc_error = error.rpc_error();
                    tracker.fail(match rpc_error.data.as_ref().and_then(Value::as_str) {
                        Some(detail) => format!("{}: {detail}", rpc_error.message),
                        None => rpc_error.message,
                    });
                    Self::requeue(&wallet, std::mem::take(&mut taken));
                }
                drop(tracker);

                // Checked after the slot is free: a `loaddescriptor` that loses the
                // race for it from here on finds it free and rescans by itself.
                let followup = rescan.take_followup();
                // Addresses derived past the horizon by what this pass found: they may
                // have history in the very range just scanned. After a failure they stay
                // queued instead, or a rescan that keeps failing would never stop.
                let derived = if failed {
                    Vec::new()
                } else {
                    wallet
                        .take_addresses_pending_rescan()
                        .unwrap_or_else(|error| {
                            error!(%error, "could not read the addresses pending a rescan");
                            Vec::new()
                        })
                };
                if !followup && derived.is_empty() {
                    break;
                }
                let Some(next) = rescan.try_start() else {
                    // Whoever took the slot read the addresses after the follow-up
                    // was requested, so the new descriptor is covered. The derived
                    // addresses may not be: leave them for the next rescan.
                    Self::requeue(&wallet, derived);
                    break;
                };
                taken = derived;
                if followup {
                    // Every cached address, the derived ones included, over the whole chain
                    addresses = match wallet.get_cached_addresses() {
                        Ok(addresses) => addresses,
                        Err(error) => {
                            error!(%error, "could not read the wallet's addresses for a follow-up rescan");
                            next.fail(format!("Wallet error: {error}"));
                            Self::requeue(&wallet, taken);
                            break;
                        }
                    };
                    (start, stop) = (None, None);
                } else {
                    // Only the derived addresses, over the range just scanned
                    addresses = taken.clone();
                }
                tracker = next;
            }
        });
    }

    fn requeue(wallet: &AddressCache<KvDatabase>, addresses: Vec<ScriptBuf>) {
        if let Err(error) = wallet.requeue_addresses_pending_rescan(addresses) {
            error!(%error, "could not requeue the addresses pending a rescan");
        }
    }
}

/// Shared record of the wallet rescan that may be running.
#[derive(Clone, Default)]
pub(super) struct RescanState {
    in_progress: Arc<AtomicBool>,
    blocks_processed: Arc<AtomicU32>,
    blocks_total: Arc<AtomicU32>,
    followup_requested: Arc<AtomicBool>,
    last_error: Arc<std::sync::Mutex<Option<String>>>,
}

impl RescanState {
    /// Claims the single rescan slot, or returns `None` if a rescan is running.
    pub(super) fn try_start(&self) -> Option<RescanTracker> {
        self.in_progress
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .ok()?;
        self.blocks_processed.store(0, Ordering::SeqCst);
        self.blocks_total.store(0, Ordering::SeqCst);
        // A new rescan supersedes the outcome of the previous one.
        *self.last_error.lock().unwrap_or_else(|e| e.into_inner()) = None;
        Some(RescanTracker(self.clone()))
    }

    /// Asks the running rescan to go over the wallet's addresses once more when it ends.
    pub(super) fn request_followup(&self) {
        self.followup_requested.store(true, Ordering::SeqCst);
    }

    pub(super) fn take_followup(&self) -> bool {
        self.followup_requested.swap(false, Ordering::SeqCst)
    }

    /// Why the last wallet rescan failed, until another one starts. Without it a failed rescan
    /// looks exactly like a completed one: `rescan_in_progress` just goes back to `false`.
    pub(super) fn last_error(&self) -> Option<String> {
        self.last_error
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// `(blocks scanned, blocks to scan)` of the running rescan, if any.
    pub(super) fn progress(&self) -> Option<(u32, u32)> {
        self.in_progress.load(Ordering::SeqCst).then(|| {
            (
                self.blocks_processed.load(Ordering::SeqCst),
                self.blocks_total.load(Ordering::SeqCst),
            )
        })
    }
}

/// Held by the running rescan. Frees the slot on drop, so it is released on
/// every exit path of the spawned task — normal completion, early return, or
/// panic — and a future rescan is never permanently blocked.
pub(super) struct RescanTracker(RescanState);

impl RescanTracker {
    fn fail(&self, error: String) {
        *self.0.last_error.lock().unwrap_or_else(|e| e.into_inner()) = Some(error);
    }

    fn report(&self, progress: &RescanProgress) {
        let total = progress.end_height - progress.start_height + 1;
        self.0.blocks_total.store(total, Ordering::SeqCst);
        self.0
            .blocks_processed
            .store(progress.scanned.min(total), Ordering::SeqCst);
    }
}

impl Drop for RescanTracker {
    fn drop(&mut self) {
        self.0.in_progress.store(false, Ordering::SeqCst);
    }
}

impl<Blockchain: RpcChain> RpcImpl<Blockchain> {
    const FILTER_SYNC_POLL_INTERVAL: Duration = Duration::from_secs(5);

    /// Scans `[start_height, stop_height]` for `addresses` and feeds every
    /// matched block to the wallet. `tracker`, when given, is kept up to date so
    /// `getblockchaininfo` can report how far the scan has gone.
    pub(super) async fn rescan_with_block_filters(
        addresses: Vec<ScriptBuf>,
        chain: Blockchain,
        wallet: Arc<AddressCache<KvDatabase>>,
        filters: FilterManHandle,
        start_height: Option<u32>,
        stop_height: Option<u32>,
        tracker: Option<&RescanTracker>,
    ) -> Result<()> {
        let request = RescanRequest::new(addresses).with_range(start_height, stop_height);
        let ticket = loop {
            match filters.rescan(request.clone()).await {
                Ok(ticket) => break ticket,
                // A background rescan asked for during the filter-header sync waits for it,
                // still reported as in progress. Failing would only show up in the logs and
                // the client would take the wallet for scanned.
                Err(FilterManError::FiltersNotSynced { .. }) if tracker.is_some() => {
                    tokio::time::sleep(Self::FILTER_SYNC_POLL_INTERVAL).await;
                }
                Err(error) => return Err(JsonRpcError::Filters(error.to_string())),
            }
        };
        let mut processed: u32 = 0;

        loop {
            for block in filters
                .get_blocks(ticket)
                .await
                .map_err(|error| JsonRpcError::Filters(error.to_string()))?
            {
                // A matched block should always have a height; a miss means a
                // chain-store error or a reorg evicted it while we scanned.
                // Skip it rather than abandoning the rest of the rescan.
                match chain.get_block_height(&block.block_hash()) {
                    Ok(Some(height)) => {
                        wallet.block_process(&block, height)?;
                        processed += 1;
                    }
                    Ok(None) => warn!(
                        "rescan: matched block {} has no height (reorged out?); skipping",
                        block.block_hash()
                    ),
                    Err(e) => warn!(
                        "rescan: height lookup failed for block {}: {e:?}; skipping",
                        block.block_hash()
                    ),
                }
            }

            if let Some(tracker) = tracker {
                if let Ok(progress) = filters.get_progress(ticket).await {
                    tracker.report(&progress);
                }
            }

            match filters
                .get_info(ticket)
                .await
                .map_err(|error| JsonRpcError::Filters(error.to_string()))?
            {
                RescanStatus::Finished => {
                    info!("rescan complete: processed {processed} matched block(s)");
                    return Ok(());
                }
                RescanStatus::Available => continue,
                RescanStatus::Started | RescanStatus::Waiting => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use floresta_compact_filters::filters_man::RescanProgress;

    use super::RescanState;

    #[test]
    fn only_one_rescan_holds_the_slot() {
        let state = RescanState::default();
        assert_eq!(state.progress(), None);

        let tracker = state.try_start().expect("slot is free");
        assert!(state.try_start().is_none());
        assert_eq!(state.progress(), Some((0, 0)));

        drop(tracker);
        assert_eq!(state.progress(), None);
        assert!(state.try_start().is_some());
    }

    #[test]
    fn progress_counts_the_blocks_of_the_range() {
        let state = RescanState::default();
        let tracker = state.try_start().unwrap();

        tracker.report(&RescanProgress {
            start_height: 800_000,
            end_height: 800_999,
            scanned: 250,
        });
        assert_eq!(state.progress(), Some((250, 1_000)));

        // A new rescan starts from zero instead of the previous one's numbers.
        drop(tracker);
        let _tracker = state.try_start().unwrap();
        assert_eq!(state.progress(), Some((0, 0)));
    }

    #[test]
    fn a_failure_is_reported_until_the_next_rescan() {
        let state = RescanState::default();
        let tracker = state.try_start().unwrap();
        tracker.fail("no valid filters".to_owned());
        drop(tracker);
        assert_eq!(state.progress(), None);
        assert_eq!(state.last_error().as_deref(), Some("no valid filters"));

        let _tracker = state.try_start().unwrap();
        assert_eq!(state.last_error(), None);
    }

    #[test]
    fn a_followup_is_taken_once() {
        let state = RescanState::default();
        assert!(!state.take_followup());

        state.request_followup();
        state.request_followup();
        assert!(state.take_followup());
        assert!(!state.take_followup());
    }
}
