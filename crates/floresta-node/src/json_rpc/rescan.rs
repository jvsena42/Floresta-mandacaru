// SPDX-License-Identifier: MIT OR Apache-2.0

//! Wallet rescans driven by the compact-filter manager.
//!
//! Only one rescan runs at a time. [`RescanState`] holds that slot and the progress
//! `getblockchaininfo` reports; descriptors loaded while a rescan runs ask it for a
//! follow-up pass instead of starting one of their own.

use std::collections::HashSet;
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
use floresta_compact_filters::filters_man::RescanTicket;
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
    /// for the addresses the wallet derived past its horizon (see
    /// [`AddressCache::get_addresses_pending_rescan`]).
    ///
    /// Every pass scans *all* cached addresses: a pass over the new addresses alone would
    /// replay a block paying one of them without the later block that spends another wallet
    /// coin it pays, and so credit that coin again.
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
            // Queued before this run (startup, live blocks, a killed rescan): their history
            // may be anywhere, so only a pass over the whole chain covers them. Those derived
            // by what a pass of this run found are covered by a pass over the same range.
            let inherited: HashSet<ScriptBuf> = Self::pending(&wallet).into_iter().collect();
            // Queued addresses when the current pass starts
            let mut queued: Vec<ScriptBuf> = inherited.iter().cloned().collect();
            loop {
                let full_range = start.is_none() && stop.is_none();
                let covered: Vec<ScriptBuf> = {
                    let scanned: HashSet<&ScriptBuf> = addresses.iter().collect();
                    queued
                        .iter()
                        .filter(|address| scanned.contains(address))
                        .filter(|address| full_range || !inherited.contains(*address))
                        .cloned()
                        .collect()
                };

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
                // Whether to leave the queue for the next rescan instead of going on
                let stalled = match result {
                    Ok(()) => match wallet.ack_addresses_rescanned(&covered) {
                        Ok(()) => false,
                        Err(error) => {
                            // They would come back as pending at once: don't loop on them.
                            error!(%error, "could not dequeue the rescanned addresses");
                            true
                        }
                    },
                    Err(error) => {
                        error!(?error, "wallet rescan failed");
                        // The same wording a caller of the RPC would have got.
                        let rpc_error = error.rpc_error();
                        tracker.fail(match rpc_error.data.as_ref().and_then(Value::as_str) {
                            Some(detail) => format!("{}: {detail}", rpc_error.message),
                            None => rpc_error.message,
                        });
                        true
                    }
                };
                drop(tracker);

                // Checked after the slot is free: a `loaddescriptor` that loses the
                // race for it from here on finds it free and rescans by itself.
                let followup = rescan.take_followup();
                // Addresses still queued stay queued (and persisted) until a pass covers
                // them. After a failure they wait for the next rescan: retrying here would
                // never stop while the failure lasts.
                let pending = if stalled {
                    Vec::new()
                } else {
                    Self::pending(&wallet)
                };
                if !followup && pending.is_empty() {
                    break;
                }
                let Some(next) = rescan.try_start() else {
                    // Whoever took the slot reads the addresses and the queue itself.
                    break;
                };

                if followup || pending.iter().any(|address| inherited.contains(address)) {
                    (start, stop) = (None, None);
                }
                // Read before the addresses, so that every queued address is among them
                queued = Self::pending(&wallet);
                addresses = match wallet.get_cached_addresses() {
                    Ok(addresses) => addresses,
                    Err(error) => {
                        error!(%error, "could not read the wallet's addresses for a follow-up rescan");
                        next.fail(format!("Wallet error: {error}"));
                        break;
                    }
                };
                tracker = next;
            }
        });
    }

    fn pending(wallet: &AddressCache<KvDatabase>) -> Vec<ScriptBuf> {
        wallet
            .get_addresses_pending_rescan()
            .unwrap_or_else(|error| {
                error!(%error, "could not read the addresses pending a rescan");
                Vec::new()
            })
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

/// Where a rescan that stopped after `progress` picks up again, or `None` to start over.
///
/// Every match below `start + scanned` was pushed to the ticket's queue. A failed ticket
/// hands the queue out before reporting the failure, so that is the exact resume point.
/// A lost ticket dropped its queue: nothing past the last block delivered is certain.
fn resume_height(
    progress: Option<RescanProgress>,
    last_delivered: Option<u32>,
    ticket_lost: bool,
) -> Option<u32> {
    let progress = progress?;
    let scanned_to = progress
        .start_height
        .saturating_add(progress.scanned)
        .max(progress.start_height);
    if !ticket_lost {
        return Some(scanned_to);
    }
    Some(match last_delivered {
        Some(height) => scanned_to
            .min(height.saturating_add(1))
            .max(progress.start_height),
        None => progress.start_height,
    })
}

impl<Blockchain: RpcChain> RpcImpl<Blockchain> {
    const FILTER_SYNC_POLL_INTERVAL: Duration = Duration::from_secs(5);

    /// How many times in a row a background rescan is resumed after a failure before giving
    /// up. Progress resets the count.
    const RESCAN_MAX_ATTEMPTS: u32 = 20;
    const RESCAN_RETRY_BASE_DELAY: Duration = Duration::from_secs(15);
    const RESCAN_RETRY_MAX_DELAY: Duration = Duration::from_secs(10 * 60);

    /// Scans `[start_height, stop_height]` for `addresses` and feeds every
    /// matched block to the wallet. `tracker`, when given, is kept up to date so
    /// `getblockchaininfo` can report how far the scan has gone, and the scan
    /// resumes after a transient failure instead of giving up: the ticket is lost
    /// when the device sleeps long enough, the network comes and goes.
    pub(super) async fn rescan_with_block_filters(
        addresses: Vec<ScriptBuf>,
        chain: Blockchain,
        wallet: Arc<AddressCache<KvDatabase>>,
        filters: FilterManHandle,
        start_height: Option<u32>,
        stop_height: Option<u32>,
        tracker: Option<&RescanTracker>,
    ) -> Result<()> {
        let mut request = RescanRequest::new(addresses).with_range(start_height, stop_height);
        let mut processed: u32 = 0;
        let mut attempts: u32 = 0;
        // The range as first reported, so a resumed scan keeps reporting against it
        let mut original_start: Option<u32> = None;
        let mut furthest_scanned: u32 = 0;

        loop {
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

            let mut last_progress: Option<RescanProgress> = None;
            let mut last_delivered: Option<u32> = None;
            // A wallet error ends the rescan (`?`); a filter error may be resumed below
            let outcome = Self::drain_rescan(
                &chain,
                &wallet,
                &filters,
                ticket,
                tracker,
                &mut processed,
                &mut original_start,
                &mut last_progress,
                &mut last_delivered,
            )
            .await?;

            let error = match outcome {
                Ok(()) => {
                    info!("rescan complete: processed {processed} matched block(s)");
                    return Ok(());
                }
                Err(error) if tracker.is_none() => {
                    return Err(JsonRpcError::Filters(error.to_string()));
                }
                Err(error) => error,
            };

            // Getting further than last time earns a fresh set of attempts
            if let Some(progress) = &last_progress {
                let scanned_to = progress.start_height.saturating_add(progress.scanned);
                if scanned_to > furthest_scanned {
                    furthest_scanned = scanned_to;
                    attempts = 0;
                }
            }
            if attempts >= Self::RESCAN_MAX_ATTEMPTS {
                return Err(JsonRpcError::Filters(error.to_string()));
            }

            let delay = Self::RESCAN_RETRY_BASE_DELAY
                .saturating_mul(1 << attempts.min(16))
                .min(Self::RESCAN_RETRY_MAX_DELAY);
            attempts += 1;

            // A ticket that is gone took its undelivered matches with it; a failed one hands
            // them out before reporting the failure.
            let ticket_lost = matches!(error, FilterManError::RescanNotFound(_));
            let range_end = last_progress.map(|progress| progress.end_height);
            match resume_height(last_progress, last_delivered, ticket_lost) {
                // Everything up to the end of the range was delivered before the ticket went
                // away: the scan is done, and asking for a range past its end would fail.
                Some(resume) if range_end.is_some_and(|end| resume > end) => {
                    info!("rescan complete: processed {processed} matched block(s)");
                    return Ok(());
                }
                Some(resume) => {
                    request.start_height = Some(resume);
                    warn!(%error, ?delay, resume, "wallet rescan interrupted; resuming");
                }
                None => warn!(%error, ?delay, "wallet rescan interrupted; restarting"),
            }
            tokio::time::sleep(delay).await;
        }
    }

    /// Feeds the wallet every block a rescan ticket delivers until it is finished. The outer
    /// error is the wallet's and ends the rescan; the inner one is the filter manager's.
    #[allow(clippy::too_many_arguments)]
    async fn drain_rescan(
        chain: &Blockchain,
        wallet: &AddressCache<KvDatabase>,
        filters: &FilterManHandle,
        ticket: RescanTicket,
        tracker: Option<&RescanTracker>,
        processed: &mut u32,
        original_start: &mut Option<u32>,
        last_progress: &mut Option<RescanProgress>,
        last_delivered: &mut Option<u32>,
    ) -> Result<core::result::Result<(), FilterManError>> {
        loop {
            let blocks = match filters.get_blocks(ticket).await {
                Ok(blocks) => blocks,
                Err(error) => return Ok(Err(error)),
            };
            for block in blocks {
                // A matched block should always have a height; a miss means a
                // chain-store error or a reorg evicted it while we scanned.
                // Skip it rather than abandoning the rest of the rescan.
                match chain.get_block_height(&block.block_hash()) {
                    Ok(Some(height)) => {
                        wallet.block_process(&block, height)?;
                        *processed += 1;
                        *last_delivered = Some(height.max(last_delivered.unwrap_or(0)));
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

            if let Ok(mut progress) = filters.get_progress(ticket).await {
                *last_progress = Some(progress);
                let start = *original_start.get_or_insert(progress.start_height);
                if let Some(tracker) = tracker {
                    // Report against the range the scan was asked for, also when resumed
                    if progress.start_height > start {
                        progress.scanned += progress.start_height - start;
                        progress.start_height = start;
                    }
                    tracker.report(&progress);
                }
            }

            match filters.get_info(ticket).await {
                Ok(RescanStatus::Finished) => return Ok(Ok(())),
                Ok(RescanStatus::Available) => continue,
                Ok(RescanStatus::Started | RescanStatus::Waiting) => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(error) => return Ok(Err(error)),
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

#[cfg(test)]
mod resume_height_tests {
    use floresta_compact_filters::filters_man::RescanProgress;

    use super::resume_height;

    fn progress(start_height: u32, scanned: u32) -> RescanProgress {
        RescanProgress {
            start_height,
            end_height: 1_000,
            scanned,
        }
    }

    #[test]
    fn no_progress_starts_over() {
        assert_eq!(resume_height(None, Some(500), true), None);
        assert_eq!(resume_height(None, None, false), None);
    }

    #[test]
    fn a_failed_ticket_resumes_right_after_what_was_scanned() {
        assert_eq!(
            resume_height(Some(progress(100, 300)), None, false),
            Some(400)
        );
        assert_eq!(
            resume_height(Some(progress(100, 300)), Some(250), false),
            Some(400)
        );
        assert_eq!(
            resume_height(Some(progress(100, 0)), None, false),
            Some(100)
        );
    }

    #[test]
    fn a_lost_ticket_resumes_after_the_last_delivered_block() {
        assert_eq!(
            resume_height(Some(progress(100, 300)), Some(250), true),
            Some(251)
        );
        // Nothing delivered yet: everything scanned so far may still have been queued
        assert_eq!(
            resume_height(Some(progress(100, 300)), None, true),
            Some(100)
        );
        // Delivered blocks never come from past what was scanned
        assert_eq!(
            resume_height(Some(progress(100, 300)), Some(900), true),
            Some(400)
        );
    }
}
