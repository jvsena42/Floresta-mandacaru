// SPDX-License-Identifier: MIT OR Apache-2.0

//! Wallet rescans driven by the compact-filter manager.
//!
//! Only one rescan runs at a time. [`RescanState`] holds that slot, the progress
//! `getblockchaininfo` reports, and the [`RescanJob`] the wallet database keeps until the rescan
//! is done, so that a restart of the node resumes it instead of dropping it.
//!
//! A descriptor loaded while a rescan over the default range runs makes that rescan start over
//! with the new addresses, instead of waiting for it to end and then scanning the whole range
//! again. Addresses the wallet derives past its horizon while a rescan runs join it from the
//! block that made the wallet derive them.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use bitcoin::ScriptBuf;
use floresta_compact_filters::filters_man::FilterManError;
use floresta_compact_filters::filters_man::FilterManHandle;
use floresta_compact_filters::filters_man::RescanProgress;
use floresta_compact_filters::filters_man::RescanRequest;
use floresta_compact_filters::filters_man::RescanStatus;
use floresta_compact_filters::filters_man::RescanTicket;
use floresta_domain::wallet::error::WatchOnlyError;
use floresta_watch_only::AddressCache;
use floresta_watch_only::RescanJob;
use floresta_watch_only::kv_database::KvDatabase;
use serde_json::Value;
use tracing::error;
use tracing::info;
use tracing::warn;

use super::res::jsonrpc_interface::JsonRpcError;
use super::server::RpcChain;
use super::server::RpcImpl;

type Result<T> = std::result::Result<T, JsonRpcError>;

type Wallet = AddressCache<KvDatabase>;

/// How many passes of a job may fail in a row before a start of the node stops resuming it.
const RESCAN_MAX_RESUMED_FAILURES: u32 = 3;

/// What a tracked rescan needs besides its range: where to report its progress, and the job it
/// keeps up to date.
pub(super) struct Tracked<'a> {
    tracker: &'a RescanTracker,
    state: &'a RescanState,
    job: &'a RescanJob,
    /// The wallet's derivation horizon when the addresses to scan were read
    horizon: u32,
}

/// Why [`RpcImpl::drain_rescan`] stopped.
enum Drained {
    /// Every matched block of the ticket was processed.
    Finished,
    /// The filter manager failed the ticket.
    Failed(FilterManError),
    /// The scan has to go on with every cached address: from this height, or from the start
    /// of the range when `None`.
    Restart(Option<u32>),
}

impl<Blockchain: RpcChain> RpcImpl<Blockchain> {
    /// Starts the wallet rescan the node left unfinished when it last stopped, if any.
    pub(super) fn resume_wallet_rescan(&self) {
        let job = match self.wallet.get_rescan_job() {
            Ok(Some(job)) => job,
            Ok(None) => return,
            Err(error) => {
                error!(%error, "could not read the unfinished wallet rescan");
                return;
            }
        };
        // Known from now on also when it is not resumed: what the next rescan owes builds on it
        self.rescan.load_job(job.clone());
        let Some(filters) = self.filters.clone() else {
            return;
        };
        if job.failures >= RESCAN_MAX_RESUMED_FAILURES {
            // Resumed on every start, a rescan that keeps failing would hold the slot for good
            warn!(
                failures = job.failures,
                "not resuming a wallet rescan that keeps failing"
            );
            self.rescan.set_error(Some(format!(
                "The wallet rescan failed {} times in a row; ask for a new one",
                job.failures
            )));
            return;
        }
        let Some(tracker) = self.rescan.try_start() else {
            return;
        };
        info!(
            start = ?job.start,
            stop = ?job.stop,
            resume = ?job.resume,
            "resuming the unfinished wallet rescan"
        );
        self.rescan.set_job(&self.wallet, Some(job));
        self.spawn_wallet_rescan(filters, tracker);
    }

    /// Runs the job a request that gave the slot back without using it may have kept from
    /// running: the one recorded when it took the slot, or one owed to a descriptor loaded
    /// meanwhile.
    pub(super) fn run_owed_rescan(&self, filters: FilterManHandle) {
        let followup = self.rescan.take_followup();
        if !followup && !self.rescan.has_runnable_job() {
            return;
        }
        let Some(tracker) = self.rescan.try_start() else {
            // Whoever holds the slot runs it
            if followup {
                self.rescan.request_followup();
            }
            return;
        };
        if followup {
            self.rescan.owe_full_pass(&self.wallet);
        }
        self.spawn_wallet_rescan(filters, tracker);
    }

    /// Runs the rescan of [`RescanState`]'s job in the background, then one more pass for each
    /// reason it leaves: a descriptor loaded once it could no longer restart, or addresses still
    /// queued for a rescan (see [`AddressCache::get_addresses_pending_rescan`]).
    ///
    /// Every pass scans *all* cached addresses: a pass over the new addresses alone would
    /// replay a block paying one of them without the later block that spends another wallet
    /// coin it pays, and so credit that coin again.
    pub(super) fn spawn_wallet_rescan(&self, filters: FilterManHandle, mut tracker: RescanTracker) {
        let chain = self.chain.clone();
        let wallet = self.wallet.clone();
        let rescan = self.rescan.clone();
        // A new rescan supersedes the outcome of the previous one. Cleared here and not when
        // the slot is taken: a request that gives the slot back unused leaves it alone.
        rescan.set_error(None);

        tokio::spawn(async move {
            loop {
                let job = rescan.job_or_default(&wallet);
                let result =
                    Self::wallet_rescan_pass(&chain, &wallet, &filters, &rescan, &tracker, &job)
                        .await;
                // Whether the job is done. One that isn't stays recorded, and the next rescan
                // or the next start of the node takes it up again.
                let done = match result {
                    Ok(covered) => match wallet.ack_addresses_rescanned(&covered) {
                        Ok(()) => true,
                        Err(error) => {
                            // They would come back as pending at once: don't loop on them.
                            error!(%error, "could not dequeue the rescanned addresses");
                            tracker.fail(format!("Wallet error: {error}"));
                            false
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
                        false
                    }
                };
                // Retrying after a failure would never stop while the failure lasts. A failed
                // range that owes a pass over the default one gives way to it; its failure stays
                // reported, so whoever asked for it can ask again.
                let another_pass = if done {
                    rescan.finish_job(&wallet)
                } else {
                    rescan.supersede_failed_job(&wallet) || {
                        rescan.record_failure(&wallet);
                        false
                    }
                };
                drop(tracker);

                // Checked after the slot is free: a `loaddescriptor` that loses the
                // race for it from here on finds it free and rescans by itself.
                let followup = rescan.take_followup();
                if !another_pass && !followup {
                    break;
                }
                let Some(next) = rescan.try_start() else {
                    // Whoever took the slot reads the job and the addresses itself.
                    break;
                };
                if followup {
                    rescan.owe_full_pass(&wallet);
                }
                tracker = next;
            }
        });
    }

    /// Scans the range of `job`, from where it was left, for every cached address. Returns the
    /// addresses queued for a rescan that it covered.
    async fn wallet_rescan_pass(
        chain: &Blockchain,
        wallet: &Arc<Wallet>,
        filters: &FilterManHandle,
        rescan: &RescanState,
        tracker: &RescanTracker,
        job: &RescanJob,
    ) -> Result<Vec<ScriptBuf>> {
        // Read first: addresses derived from now on are noticed by the scan
        let horizon = wallet.get_stats()?.derivation_index;
        let addresses = wallet.get_cached_addresses()?;
        if addresses.is_empty() {
            return Ok(Vec::new());
        }
        let mut resume = job.resume;
        if let Some(height) = resume {
            if job.horizon != Some(horizon) {
                // Derived after the resume height was saved, e.g. by the block being processed
                // when the node stopped: go back for them
                let from = Self::lookback_from(height, job.range_start);
                rescan.lower_resume(wallet, from);
                resume = Some(from);
            }
        }
        let start = resume.or(job.start);
        if let Some(start) = start {
            let (tip, _) = chain.get_best_block().map_err(|_| JsonRpcError::Chain)?;
            if start > job.stop.unwrap_or(tip) {
                // Interrupted right after its last block
                return Ok(covered(wallet, job, addresses));
            }
        }

        let scanned = Self::rescan_with_block_filters(
            addresses,
            chain.clone(),
            wallet.clone(),
            filters.clone(),
            start,
            job.stop,
            Some(&Tracked {
                tracker,
                state: rescan,
                job,
                horizon,
            }),
        )
        .await?;
        Ok(covered(wallet, job, scanned))
    }

    /// Whether the wallet derived more addresses since `horizon` was last read, which it
    /// updates.
    fn horizon_moved(wallet: &Wallet, horizon: &mut Option<u32>) -> Result<bool> {
        let current = wallet.get_stats()?.derivation_index;
        Ok(horizon.replace(current).is_some_and(|last| last != current))
    }
}

/// The queued addresses a successful pass of `job` over `scanned` covered.
///
/// Those queued when the job was created may have history anywhere, so only a pass over
/// the default range covers them: the job's resume height guarantees that every address
/// cached when it was created was scanned from the start of the range. The others were
/// derived since, after a payment within the gap limit of the horizon, and the scan
/// followed them from a week before the block it was in: an address past the horizon isn't
/// paid much before one within the gap limit of it.
fn covered(wallet: &Wallet, job: &RescanJob, scanned: Vec<ScriptBuf>) -> Vec<ScriptBuf> {
    let full_range = job.start.is_none() && job.stop.is_none();
    let inherited: HashSet<&ScriptBuf> = job.inherited.iter().collect();
    let scanned: HashSet<ScriptBuf> = scanned.into_iter().collect();
    pending(wallet)
        .into_iter()
        .filter(|address| scanned.contains(address))
        // With an explicit end, blocks after it were processed before they were derived
        .filter(|address| full_range || (job.stop.is_none() && !inherited.contains(address)))
        .collect()
}

fn pending(wallet: &Wallet) -> Vec<ScriptBuf> {
    wallet
        .get_addresses_pending_rescan()
        .unwrap_or_else(|error| {
            error!(%error, "could not read the addresses pending a rescan");
            Vec::new()
        })
}

/// Shared record of the wallet rescan that may be running.
#[derive(Clone, Default)]
pub(super) struct RescanState {
    in_progress: Arc<AtomicBool>,
    blocks_processed: Arc<AtomicU32>,
    blocks_total: Arc<AtomicU32>,
    followup_requested: Arc<AtomicBool>,
    /// A descriptor was loaded while a rescan held the slot: the pass running over the default
    /// range starts over. Changed only with the job lock held, and cleared only by that pass.
    restart_owed: Arc<AtomicBool>,
    last_error: Arc<Mutex<Option<String>>>,
    /// The unfinished rescan, mirrored in the wallet database. Changed only with the lock
    /// held, by the running rescan and by `loaddescriptor`, and saved before the lock is
    /// released.
    job: Arc<Mutex<Option<RescanJob>>>,
}

impl RescanState {
    /// Claims the single rescan slot, or returns `None` if a rescan is running.
    pub(super) fn try_start(&self) -> Option<RescanTracker> {
        self.in_progress
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .ok()?;
        self.blocks_processed.store(0, Ordering::SeqCst);
        self.blocks_total.store(0, Ordering::SeqCst);
        Some(RescanTracker(self.clone()))
    }

    /// Asks the running rescan to go over the wallet's addresses once more.
    pub(super) fn request_followup(&self) {
        self.followup_requested.store(true, Ordering::SeqCst);
    }

    pub(super) fn take_followup(&self) -> bool {
        self.followup_requested.swap(false, Ordering::SeqCst)
    }

    /// Adds `descriptor` to the wallet, after recording the pass it is owed: a restart of the
    /// node at any point after the descriptor is saved scans it. `running` tells whether a
    /// rescan holds the slot; it starts over for the descriptor if it scans the default range.
    pub(super) fn add_descriptor(
        &self,
        wallet: &Wallet,
        descriptor: &str,
        running: bool,
    ) -> std::result::Result<Vec<ScriptBuf>, WatchOnlyError> {
        let mut job = self.lock_job();
        let previous = job.clone();
        Self::owe_full_pass_locked(&mut job, wallet);
        if let Err(error) = wallet.save_rescan_job(job.as_ref()) {
            *job = previous;
            return Err(error);
        }

        let addresses = match wallet.push_descriptor(descriptor) {
            Ok(addresses) if !addresses.is_empty() => addresses,
            other => {
                *job = previous;
                Self::save(wallet, &job);
                return other;
            }
        };
        if let Some(current) = job.as_mut() {
            // Pushing derived up to the wallet's horizon: what the job's resume height is for
            current.horizon = horizon(wallet);
            Self::save(wallet, &job);
        }
        if running {
            // Set with the lock held, so the running rescan doesn't record a resume height
            // past what the new addresses were scanned for in between.
            self.restart_owed.store(true, Ordering::SeqCst);
            // And in case the one holding the slot is past its last pass
            self.request_followup();
        }
        Ok(addresses)
    }

    /// Whether the running pass over the default range has to start over for a descriptor
    /// loaded meanwhile. The pass covers it from then on, so no other pass is owed for it.
    fn take_restart(&self) -> bool {
        let _job = self.lock_job();
        let owed = self.restart_owed.swap(false, Ordering::SeqCst);
        if owed {
            self.followup_requested.store(false, Ordering::SeqCst);
        }
        owed
    }

    /// Makes the job owe a pass over the default range to every cached address.
    pub(super) fn owe_full_pass(&self, wallet: &Wallet) {
        let mut job = self.lock_job();
        Self::owe_full_pass_locked(&mut job, wallet);
        Self::save(wallet, &job);
    }

    fn owe_full_pass_locked(job: &mut Option<RescanJob>, wallet: &Wallet) {
        match job {
            Some(job) if is_default_range(job) => {
                job.resume = None;
                job.failures = 0;
            }
            Some(job) => {
                job.followup = true;
                job.failures = 0;
            }
            None => *job = Some(new_job(wallet, None, None)),
        }
    }

    /// Records a rescan over `[start, stop]` asked for by `rescanblockchain`. It replaces the
    /// one left unfinished, if any, but not the pass over the default range that one owes.
    pub(super) fn start_job(
        &self,
        wallet: &Wallet,
        start: Option<u32>,
        stop: Option<u32>,
    ) -> std::result::Result<(), WatchOnlyError> {
        let mut job = self.lock_job();
        let mut new = new_job(wallet, start, stop);
        if !is_default_range(&new) {
            new.followup = job
                .as_ref()
                .is_some_and(|old| old.followup || is_default_range(old));
        }
        wallet.save_rescan_job(Some(&new))?;
        *job = Some(new);
        Ok(())
    }

    /// Whether a job is recorded that a start of the node would resume.
    fn has_runnable_job(&self) -> bool {
        self.lock_job()
            .as_ref()
            .is_some_and(|job| job.failures < RESCAN_MAX_RESUMED_FAILURES)
    }

    /// Takes up the job the database holds, without saving it again.
    fn load_job(&self, loaded: RescanJob) {
        *self.lock_job() = Some(loaded);
    }

    pub(super) fn set_job(&self, wallet: &Wallet, new: Option<RescanJob>) {
        let mut job = self.lock_job();
        *job = new;
        Self::save(wallet, &job);
    }

    /// The job to run, after recording a new one over the default range if there is none.
    fn job_or_default(&self, wallet: &Wallet) -> RescanJob {
        let mut job = self.lock_job();
        // A pass that starts reads the addresses after this: it scans every descriptor loaded
        // so far, and needs no restart for them
        self.restart_owed.store(false, Ordering::SeqCst);
        self.followup_requested.store(false, Ordering::SeqCst);
        if let Some(job) = job.as_ref() {
            return job.clone();
        }
        let new = new_job(wallet, None, None);
        *job = Some(new.clone());
        Self::save(wallet, &job);
        new
    }

    /// Records that every cached address was scanned up to `resume`, exclusively, from
    /// `range_start`, the start of the job's range.
    fn record_progress(&self, wallet: &Wallet, range_start: u32, resume: Option<u32>) {
        let mut job = self.lock_job();
        let Some(current) = job.as_mut() else {
            return;
        };
        current.range_start = Some(range_start);
        if let Some(resume) = resume {
            // A descriptor was loaded, and the scan hasn't started over for it yet
            let restart_owed =
                is_default_range(current) && self.restart_owed.load(Ordering::SeqCst);
            if !restart_owed {
                if current.resume.is_none_or(|last| resume > last) {
                    current.failures = 0;
                }
                current.resume = Some(resume);
            }
        }
        Self::save(wallet, &job);
    }

    /// Makes a restart of the node resume the job from `height` at the latest: the scan went
    /// back there for addresses the wallet derived.
    fn lower_resume(&self, wallet: &Wallet, height: u32) {
        let mut job = self.lock_job();
        if let Some(current) = job.as_mut() {
            if current.resume.is_some_and(|resume| resume > height) {
                current.resume = Some(height);
            }
            current.horizon = horizon(wallet);
            Self::save(wallet, &job);
        }
    }

    /// Ends the job after a successful pass. Returns whether another pass is owed, recorded
    /// as the new job.
    fn finish_job(&self, wallet: &Wallet) -> bool {
        let mut job = self.lock_job();
        let finished = job.take().unwrap_or_default();
        let pending = pending(wallet);
        // A descriptor loaded since the scan last looked: it has to be covered, also if the node
        // stops before the next pass starts
        let descriptor_loaded = self.restart_owed.swap(false, Ordering::SeqCst)
            || self.followup_requested.load(Ordering::SeqCst);
        // Addresses still queued were not covered by the pass: only one over the default range
        // covers addresses whatever their history
        *job = if finished.followup || descriptor_loaded || !pending.is_empty() {
            Some(new_job(wallet, None, None))
        } else {
            None
        };
        Self::save(wallet, &job);
        job.is_some()
    }

    /// Replaces a failed job over another range that owes a pass over the default one with
    /// that pass. Returns whether it did.
    fn supersede_failed_job(&self, wallet: &Wallet) -> bool {
        let mut job = self.lock_job();
        let owes_default = job
            .as_ref()
            .is_some_and(|failed| !is_default_range(failed) && failed.followup);
        if owes_default {
            *job = Some(new_job(wallet, None, None));
            Self::save(wallet, &job);
        }
        owes_default
    }

    fn record_failure(&self, wallet: &Wallet) {
        let mut job = self.lock_job();
        if let Some(failed) = job.as_mut() {
            failed.failures = failed.failures.saturating_add(1);
            Self::save(wallet, &job);
        }
    }

    /// Reports `error` as the outcome of the last rescan, as if one had just failed with it.
    pub(super) fn set_error(&self, error: Option<String>) {
        *self.last_error.lock().unwrap_or_else(|e| e.into_inner()) = error;
    }

    fn lock_job(&self) -> MutexGuard<'_, Option<RescanJob>> {
        self.job.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn save(wallet: &Wallet, job: &Option<RescanJob>) {
        if let Err(error) = wallet.save_rescan_job(job.as_ref()) {
            error!(%error, "could not save the wallet rescan");
        }
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

fn is_default_range(job: &RescanJob) -> bool {
    job.start.is_none() && job.stop.is_none()
}

/// A job over `[start, stop]` from its start, for the addresses cached now.
fn new_job(wallet: &Wallet, start: Option<u32>, stop: Option<u32>) -> RescanJob {
    RescanJob {
        start,
        stop,
        inherited: pending(wallet),
        horizon: horizon(wallet),
        ..RescanJob::default()
    }
}

fn horizon(wallet: &Wallet) -> Option<u32> {
    wallet.get_stats().map(|stats| stats.derivation_index).ok()
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

    /// How far before the block that made the wallet derive more addresses a rescan looks for
    /// them: a payment to a new address may confirm a little before the one that made the
    /// wallet derive it, e.g. after a fee bump. About a week of blocks.
    const DERIVATION_LOOKBACK: u32 = 1_008;

    /// How often a tracked rescan saves how far it has got.
    const RESCAN_SAVE_INTERVAL: Duration = Duration::from_secs(10);

    /// Scans `[start_height, stop_height]` for `addresses` and feeds every matched block to the
    /// wallet. Returns the addresses it scanned for.
    ///
    /// A tracked rescan keeps `getblockchaininfo` up to date with how far it has gone, saves
    /// that in its job, and resumes after a transient failure instead of giving up: the ticket
    /// is lost when the device sleeps long enough, the network comes and goes. It also goes on
    /// with every cached address when the wallet gets new ones: from the start of its range for
    /// a descriptor, from where they were derived for addresses past the horizon.
    pub(super) async fn rescan_with_block_filters(
        addresses: Vec<ScriptBuf>,
        chain: Blockchain,
        wallet: Arc<Wallet>,
        filters: FilterManHandle,
        start_height: Option<u32>,
        stop_height: Option<u32>,
        tracked: Option<&Tracked<'_>>,
    ) -> Result<Vec<ScriptBuf>> {
        let mut request = RescanRequest::new(addresses).with_range(start_height, stop_height);
        let mut processed: u32 = 0;
        let mut attempts: u32 = 0;
        // The range as first reported, so a resumed scan keeps reporting against it
        let mut original_start: Option<u32> = tracked.and_then(|tracked| tracked.job.range_start);
        let mut furthest_scanned: u32 = 0;
        let mut horizon: Option<u32> = tracked.map(|tracked| tracked.horizon);
        let mut last_saved: Option<Instant> = None;

        loop {
            let ticket = loop {
                match filters.rescan(request.clone()).await {
                    Ok(ticket) => break ticket,
                    // A background rescan asked for during the filter-header sync waits for it,
                    // still reported as in progress. Failing would only show up in the logs and
                    // the client would take the wallet for scanned.
                    Err(FilterManError::FiltersNotSynced { .. }) if tracked.is_some() => {
                        tokio::time::sleep(Self::FILTER_SYNC_POLL_INTERVAL).await;
                    }
                    // A job resumed after the chain lost some blocks: they come back
                    Err(FilterManError::InvalidRescanRange { end, tip, .. })
                        if tracked.is_some() && end > tip =>
                    {
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
                tracked,
                &mut processed,
                &mut original_start,
                &mut last_progress,
                &mut last_delivered,
                &mut horizon,
                &mut last_saved,
            )
            .await?;

            let error = match outcome {
                Drained::Finished => {
                    info!("rescan complete: processed {processed} matched block(s)");
                    return Ok(request.scripts);
                }
                Drained::Restart(from) => {
                    filters.cancel_rescan(ticket).await;
                    // A new scan: it earns its own attempts
                    attempts = 0;
                    furthest_scanned = 0;
                    request.scripts = wallet.get_cached_addresses()?;
                    // The start of the range, not where a resumed job took it up again
                    request.start_height =
                        from.or(tracked.map_or(start_height, |tracked| tracked.job.start));
                    if let Some(from) = request.start_height {
                        let (tip, _) = chain.get_best_block().map_err(|_| JsonRpcError::Chain)?;
                        if from > stop_height.unwrap_or(tip) {
                            // Every block of the range was scanned for the new addresses too
                            info!("rescan complete: processed {processed} matched block(s)");
                            return Ok(request.scripts);
                        }
                    }
                    continue;
                }
                Drained::Failed(error) if tracked.is_none() => {
                    return Err(JsonRpcError::Filters(error.to_string()));
                }
                Drained::Failed(error) => error,
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
                    return Ok(request.scripts);
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

    /// Where a scan goes back to for addresses derived after a payment in block `height`.
    fn lookback_from(height: u32, range_start: Option<u32>) -> u32 {
        let from = height.saturating_sub(Self::DERIVATION_LOOKBACK);
        range_start.map_or(from, |start| from.max(start))
    }

    /// Feeds the wallet every block a rescan ticket delivers until it is finished, or until a
    /// tracked rescan has to go on with new addresses. A wallet error ends the rescan.
    #[allow(clippy::too_many_arguments)]
    async fn drain_rescan(
        chain: &Blockchain,
        wallet: &Wallet,
        filters: &FilterManHandle,
        ticket: RescanTicket,
        tracked: Option<&Tracked<'_>>,
        processed: &mut u32,
        original_start: &mut Option<u32>,
        last_progress: &mut Option<RescanProgress>,
        last_delivered: &mut Option<u32>,
        horizon: &mut Option<u32>,
        last_saved: &mut Option<Instant>,
    ) -> Result<Drained> {
        // Every match below this height was delivered and processed
        let mut safe: Option<u32> = None;
        loop {
            // Every match below what this reports is in the ticket's queue already
            let queued_below = match tracked {
                Some(_) => filters.get_progress(ticket).await.ok(),
                None => None,
            };
            if original_start.is_none() {
                *original_start = queued_below.map(|progress| progress.start_height);
            }
            let blocks = match filters.get_blocks(ticket).await {
                Ok(blocks) => blocks,
                Err(error) => return Ok(Drained::Failed(error)),
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
                        // A payment near the horizon: the addresses derived for it are paid in
                        // this block or later ones, give or take a reordering of confirmations.
                        if let Some(tracked) = tracked {
                            if Self::horizon_moved(wallet, horizon)? {
                                let from = Self::lookback_from(height, *original_start);
                                // Saved at once: a restart of the node must not resume past it
                                tracked.state.lower_resume(wallet, from);
                                info!(
                                    height,
                                    from,
                                    "rescan: the wallet derived more addresses; scanning for them"
                                );
                                return Ok(Drained::Restart(Some(from)));
                            }
                        }
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
                if let Some(tracked) = tracked {
                    // Report against the range the scan was asked for, also when resumed
                    if progress.start_height > start {
                        progress.scanned += progress.start_height - start;
                        progress.start_height = start;
                    }
                    tracked.tracker.report(&progress);
                }
            }

            if let Some(tracked) = tracked {
                if is_default_range(tracked.job) && tracked.state.take_restart() {
                    info!(
                        "rescan: a descriptor was loaded; scanning the range again from its start"
                    );
                    return Ok(Drained::Restart(None));
                }
                // Derived after a block that arrived from the network, or a transaction
                if Self::horizon_moved(wallet, horizon)? {
                    let ticket_start = last_progress.map(|progress| progress.start_height);
                    let (tip, _) = chain.get_best_block().map_err(|_| JsonRpcError::Chain)?;
                    let from = Self::lookback_from(tip, *original_start);
                    // Without a known position, the whole range again
                    let Some(position) = safe.or(ticket_start) else {
                        return Ok(Drained::Restart(None));
                    };
                    let from = position.min(from);
                    tracked.state.lower_resume(wallet, from);
                    info!(
                        from,
                        "rescan: the wallet derived more addresses; scanning for them"
                    );
                    return Ok(Drained::Restart(Some(from)));
                }
            }

            let status = match filters.get_info(ticket).await {
                Ok(status) => status,
                Err(error) => return Ok(Drained::Failed(error)),
            };
            if let (Some(tracked), Some(progress), Some(range_start)) =
                (tracked, queued_below, *original_start)
            {
                if status != RescanStatus::Available {
                    // Nothing left in the queue: every match it held was processed above
                    safe = Some(progress.start_height.saturating_add(progress.scanned));
                } else if let Some(delivered) = *last_delivered {
                    // Matches come in height order: every one up to the last delivered was
                    safe = Some(safe.map_or(delivered + 1, |safe| safe.max(delivered + 1)));
                }
                if last_saved.is_none_or(|saved| saved.elapsed() >= Self::RESCAN_SAVE_INTERVAL) {
                    *last_saved = Some(Instant::now());
                    tracked.state.record_progress(wallet, range_start, safe);
                }
            }
            match status {
                RescanStatus::Finished => return Ok(Drained::Finished),
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

        // A request that takes the slot and gives it back unused leaves it
        drop(state.try_start().unwrap());
        assert_eq!(state.last_error().as_deref(), Some("no valid filters"));

        // A rescan that starts supersedes it
        let _tracker = state.try_start().unwrap();
        state.set_error(None);
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
mod job_tests {
    use floresta_chain::pruned_utreexo::merkle::ConsensusMerkle;
    use floresta_watch_only::AddressCache;
    use floresta_watch_only::RescanJob;
    use floresta_watch_only::kv_database::KvDatabase;

    use super::RescanState;
    use super::Wallet;

    const DESCRIPTOR: &str = "wpkh([54ff5a12/48h/1h/0h/2h]tpubDDw6pwZA3hYxcSN32q7a5ynsKmWr4BbkBNHydHPKkM4BZwUfiK7tQ26h7USm8kA1E2FvCy7f7Er7QXKF8RNptATywydARtzgrxuPDwyYv4x/0/*)";

    fn wallet(dir: &tempfile::TempDir) -> Wallet {
        AddressCache::new(KvDatabase::new(dir.path()).unwrap(), ConsensusMerkle)
    }

    fn saved(wallet: &Wallet) -> Option<RescanJob> {
        wallet.get_rescan_job().unwrap()
    }

    #[test]
    fn a_job_survives_a_restart_until_it_is_finished() {
        let dir = tempfile::tempdir().unwrap();
        let wallet = wallet(&dir);
        {
            let state = RescanState::default();
            state.owe_full_pass(&wallet);
            state.record_progress(&wallet, 822_375, Some(900_000));
        }

        // The node restarts: nothing is left in memory, the job is read from the database
        let job = saved(&wallet).expect("the job was saved");
        assert_eq!(job.start, None);
        assert_eq!(job.range_start, Some(822_375));
        assert_eq!(job.resume, Some(900_000));

        let state = RescanState::default();
        state.set_job(&wallet, Some(job));
        assert!(!state.finish_job(&wallet));
        assert_eq!(saved(&wallet), None);
    }

    #[test]
    fn a_descriptor_restarts_a_rescan_over_the_default_range() {
        let dir = tempfile::tempdir().unwrap();
        let wallet = wallet(&dir);
        let state = RescanState::default();
        state.owe_full_pass(&wallet);
        state.record_progress(&wallet, 822_375, Some(850_000));

        state.add_descriptor(&wallet, DESCRIPTOR, true).unwrap();
        assert_eq!(saved(&wallet).unwrap().resume, None);

        // Until the scan starts over, what it scans is not recorded
        state.record_progress(&wallet, 822_375, Some(860_000));
        assert_eq!(saved(&wallet).unwrap().resume, None);

        assert!(state.take_restart());
        // The restart covers the descriptor: no other pass is owed for it
        assert!(!state.take_followup());
        state.record_progress(&wallet, 822_375, Some(830_000));
        assert_eq!(saved(&wallet).unwrap().resume, Some(830_000));
        assert!(!saved(&wallet).unwrap().followup);
    }

    #[test]
    fn a_descriptor_loaded_during_another_range_owes_a_pass_over_the_default_one() {
        let dir = tempfile::tempdir().unwrap();
        let wallet = wallet(&dir);
        let state = RescanState::default();
        state.start_job(&wallet, Some(100), Some(200)).unwrap();
        state.record_progress(&wallet, 100, Some(150));

        state.add_descriptor(&wallet, DESCRIPTOR, true).unwrap();
        let job = saved(&wallet).unwrap();
        assert!(job.followup);
        // The range itself goes on
        assert_eq!(job.resume, Some(150));
        state.record_progress(&wallet, 100, Some(160));
        assert_eq!(saved(&wallet).unwrap().resume, Some(160));

        assert!(state.finish_job(&wallet));
        let next = saved(&wallet).unwrap();
        assert_eq!((next.start, next.stop, next.resume), (None, None, None));
        assert!(!next.followup);
    }

    #[test]
    fn a_descriptor_loaded_as_the_pass_ends_keeps_a_job() {
        let dir = tempfile::tempdir().unwrap();
        let wallet = wallet(&dir);
        let state = RescanState::default();
        state.owe_full_pass(&wallet);

        // The drain is done, the task hasn't ended the job yet
        state.add_descriptor(&wallet, DESCRIPTOR, true).unwrap();
        assert!(state.finish_job(&wallet));
        let next = saved(&wallet).expect("the descriptor is still owed a pass");
        assert_eq!((next.start, next.stop, next.resume), (None, None, None));
    }

    #[test]
    fn going_back_for_derived_addresses_only_lowers_the_resume_height() {
        let dir = tempfile::tempdir().unwrap();
        let wallet = wallet(&dir);
        let state = RescanState::default();
        state.owe_full_pass(&wallet);
        state.record_progress(&wallet, 822_375, Some(900_000));

        state.lower_resume(&wallet, 899_000);
        assert_eq!(saved(&wallet).unwrap().resume, Some(899_000));
        state.lower_resume(&wallet, 950_000);
        assert_eq!(saved(&wallet).unwrap().resume, Some(899_000));

        // The horizon the resume height is good for follows the wallet's
        wallet.push_descriptor(DESCRIPTOR).unwrap();
        wallet.derive_addresses().unwrap();
        state.lower_resume(&wallet, 950_000);
        assert_eq!(
            saved(&wallet).unwrap().horizon,
            Some(wallet.get_stats().unwrap().derivation_index)
        );
    }

    #[test]
    fn the_restart_is_left_to_the_running_pass() {
        let dir = tempfile::tempdir().unwrap();
        let wallet = wallet(&dir);
        let state = RescanState::default();
        state.owe_full_pass(&wallet);
        state.add_descriptor(&wallet, DESCRIPTOR, true).unwrap();

        // A previous owner ending late takes the hand-off flag: the restart is still owed
        let _ = state.take_followup();
        state.record_progress(&wallet, 822_375, Some(860_000));
        assert_eq!(saved(&wallet).unwrap().resume, None);
        assert!(state.take_restart());
    }

    #[test]
    fn a_failed_range_gives_way_to_the_default_pass_it_owes() {
        let dir = tempfile::tempdir().unwrap();
        let wallet = wallet(&dir);
        let state = RescanState::default();
        state.start_job(&wallet, Some(100), Some(200)).unwrap();
        assert!(!state.supersede_failed_job(&wallet));
        assert_eq!(saved(&wallet).unwrap().start, Some(100));

        state.add_descriptor(&wallet, DESCRIPTOR, false).unwrap();
        assert!(state.supersede_failed_job(&wallet));
        let job = saved(&wallet).unwrap();
        assert_eq!((job.start, job.stop, job.resume), (None, None, None));
    }

    #[test]
    fn a_descriptor_that_cannot_be_added_leaves_the_job_alone() {
        let dir = tempfile::tempdir().unwrap();
        let wallet = wallet(&dir);
        let state = RescanState::default();
        state.add_descriptor(&wallet, DESCRIPTOR, false).unwrap();
        let job = saved(&wallet);

        assert!(state.add_descriptor(&wallet, DESCRIPTOR, true).is_err());
        assert!(
            state
                .add_descriptor(&wallet, "not a descriptor", true)
                .is_err()
        );
        assert_eq!(saved(&wallet), job);
        assert!(!state.take_restart());
    }

    #[test]
    fn failures_count_until_the_scan_gets_further() {
        let dir = tempfile::tempdir().unwrap();
        let wallet = wallet(&dir);
        let state = RescanState::default();
        state.owe_full_pass(&wallet);
        state.record_failure(&wallet);
        state.record_failure(&wallet);
        assert_eq!(saved(&wallet).unwrap().failures, 2);

        state.record_progress(&wallet, 822_375, Some(830_000));
        assert_eq!(saved(&wallet).unwrap().failures, 0);
        state.record_failure(&wallet);
        // Not getting further doesn't earn a fresh count
        state.record_progress(&wallet, 822_375, Some(830_000));
        assert_eq!(saved(&wallet).unwrap().failures, 1);
    }

    #[test]
    fn a_job_that_is_not_resumed_still_shapes_the_next_one() {
        let dir = tempfile::tempdir().unwrap();
        let wallet = wallet(&dir);
        let parked = RescanJob {
            failures: 3,
            ..RescanJob::default()
        };
        wallet.save_rescan_job(Some(&parked)).unwrap();

        // After a start that didn't resume it, a new range keeps the default pass it owed
        let state = RescanState::default();
        state.load_job(parked);
        state.start_job(&wallet, Some(100), None).unwrap();
        assert!(saved(&wallet).unwrap().followup);

        // And a descriptor that can't be added doesn't erase it
        let job = saved(&wallet);
        assert!(
            state
                .add_descriptor(&wallet, "not a descriptor", false)
                .is_err()
        );
        assert_eq!(saved(&wallet), job);
    }

    #[test]
    fn a_pass_that_starts_covers_the_descriptors_loaded_so_far() {
        let dir = tempfile::tempdir().unwrap();
        let wallet = wallet(&dir);
        let state = RescanState::default();
        // Loaded while another request held the slot but before its pass started
        state.add_descriptor(&wallet, DESCRIPTOR, true).unwrap();

        state.job_or_default(&wallet);
        assert!(!state.take_restart());
        assert!(!state.take_followup());
        assert!(!state.finish_job(&wallet));
    }

    #[test]
    fn a_new_range_keeps_the_default_pass_the_unfinished_job_owed() {
        let dir = tempfile::tempdir().unwrap();
        let wallet = wallet(&dir);
        let state = RescanState::default();
        state.owe_full_pass(&wallet);

        state.start_job(&wallet, Some(100), None).unwrap();
        let job = saved(&wallet).unwrap();
        assert_eq!(job.start, Some(100));
        assert!(job.followup);

        // A new rescan over the default range covers what was owed by itself
        state.start_job(&wallet, None, None).unwrap();
        assert!(!saved(&wallet).unwrap().followup);
    }

    #[test]
    fn queued_addresses_from_before_the_job_need_the_default_range() {
        let dir = tempfile::tempdir().unwrap();
        let wallet = wallet(&dir);
        wallet.push_descriptor(DESCRIPTOR).unwrap();
        wallet.derive_addresses().unwrap();
        let queued = wallet.get_addresses_pending_rescan().unwrap();
        assert!(!queued.is_empty());

        let state = RescanState::default();
        state.start_job(&wallet, Some(100), Some(200)).unwrap();
        let job = saved(&wallet).unwrap();
        assert_eq!(job.inherited, queued);

        // A pass over another range doesn't cover them
        let covered = super::covered(&wallet, &job, wallet.get_cached_addresses().unwrap());
        assert!(covered.is_empty());
        assert!(state.finish_job(&wallet));
        let next = saved(&wallet).unwrap();
        assert_eq!((next.start, next.stop), (None, None));

        // A pass over the default range does
        let covered = super::covered(&wallet, &next, wallet.get_cached_addresses().unwrap());
        assert_eq!(covered.len(), queued.len());
        wallet.ack_addresses_rescanned(&covered).unwrap();
        assert!(!state.finish_job(&wallet));
        assert_eq!(saved(&wallet), None);
    }

    #[test]
    fn addresses_derived_during_the_job_are_covered_where_they_were_scanned() {
        let dir = tempfile::tempdir().unwrap();
        let wallet = wallet(&dir);
        wallet.push_descriptor(DESCRIPTOR).unwrap();
        let state = RescanState::default();
        state.start_job(&wallet, Some(100), None).unwrap();
        let job = saved(&wallet).unwrap();
        assert!(job.inherited.is_empty());

        wallet.derive_addresses().unwrap();
        let derived = wallet.get_addresses_pending_rescan().unwrap();
        let covered = super::covered(&wallet, &job, wallet.get_cached_addresses().unwrap());
        assert_eq!(covered, derived);

        // With an explicit end, the blocks after it were processed before they were derived
        let bounded = RescanJob {
            stop: Some(200),
            ..job
        };
        let covered = super::covered(&wallet, &bounded, wallet.get_cached_addresses().unwrap());
        assert!(covered.is_empty());
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
