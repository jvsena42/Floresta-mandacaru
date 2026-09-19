// SPDX-License-Identifier: MIT OR Apache-2.0

//! Compact block-filter synchronization and rescan service.
//!
//! [`FiltersMan`] persists filter headers, validates every downloaded filter against that chain,
//! caches recent filters, builds filters for newly connected local blocks, and serves paginated
//! rescans through cloneable [`FilterManHandle`] values.

use core::fmt;
use core::fmt::Display;
use core::fmt::Formatter;
use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::PoisonError;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use bitcoin::Block;
use bitcoin::BlockHash;
use bitcoin::FilterHeader;
use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::VarInt;
use bitcoin::bip158::BlockFilter;
use bitcoin::consensus::Decodable;
use bitcoin::hashes::Hash;
use bitcoin::p2p::message_filter::CFHeaders;
use floresta_chain::BlockConsumer;
use floresta_chain::BlockchainInterface;
use floresta_chain::UtxoData;
pub use floresta_common::ChainMethods;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::time::MissedTickBehavior;
use tracing::debug;
use tracing::info;
use tracing::warn;

use crate::FilterHeadersStore;
use crate::FlatFilterStoreError;

const BASIC_FILTER_TYPE: u8 = 0;
const FILTER_HEADER_BATCH_SIZE: u32 = 1_000;
const FILTER_BATCH_SIZE: u32 = 1_000;
const FILTER_REQUEST_SIZE: usize = 100;
const CHECKPOINT_INTERVAL: u32 = 1_000;
const CONNECTED_BLOCK_BUFFER: usize = 16;
const DEFAULT_RESCAN_PAGE_SIZE: usize = 50;
const MAX_RESCAN_PAGE_SIZE: usize = 10_000;
const SYNC_INTERVAL: Duration = Duration::from_secs(30);
const RESCAN_RETRY_INTERVAL: Duration = Duration::from_secs(1);

/// After a failed synchronization, connected blocks don't trigger another one for this long.
/// Blocks connect by the dozen per second during IBD, and without a compact-filters peer each
/// of them would otherwise start a synchronization that fails right away.
const SYNC_RETRY_INTERVAL: Duration = Duration::from_secs(10);

/// How many times a rescan asks again for a batch whose filters failed validation. Each failure
/// is reported to the node, which sheds the peer on its second one, so the attempts reach more
/// than one peer. A batch that still doesn't validate means our header chain is off.
const MAX_INVALID_BATCH_ATTEMPTS: u32 = 5;

/// A rescan nobody asked about for this long was abandoned by its consumer (consumers poll many
/// times per second). It is dropped so its task stops instead of holding a page of blocks forever.
const RESCAN_IDLE_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// Bits a BIP158 basic filter spends on each element, at the very least: a Golomb-Rice code with
/// `P = 19` is a unary quotient of one bit or more followed by a 19-bit remainder.
const MIN_BITS_PER_FILTER_ELEMENT: u64 = 20;

/// Whether the element count `filter` starts with can fit in the bytes that follow.
///
/// Matching multiplies that count by the BIP158 `M` parameter, and rust-bitcoin does it unchecked.
/// The count comes from a peer, and the filter header we validate filters against was handed to
/// us by a peer as well, so both can be crafted: the product then overflows, which panics in
/// builds with overflow checks and silently corrupts the match otherwise.
pub fn declares_plausible_element_count(filter: &BlockFilter) -> bool {
    let mut content = filter.content.as_slice();
    let Ok(VarInt(elements)) = VarInt::consensus_decode(&mut content) else {
        // No count to read: matching treats that as an empty filter.
        return true;
    };

    elements <= content.len() as u64 * 8 / MIN_BITS_PER_FILTER_ELEMENT
}

/// Sentinel published through [`FilterManHandle::get_height`] while the store is empty.
const NO_FILTER_HEADERS: u32 = u32::MAX;

/// Minimal blockchain view required by [`FiltersMan`].
pub trait FilterChain: Clone + Send + Sync + 'static {
    /// Error returned by the chain backend.
    type Error: Error + Send + Sync + 'static;

    /// Returns the current best-chain height.
    fn get_height(&self) -> Result<u32, Self::Error>;

    /// Returns the best-chain block hash at `height`.
    fn get_block_hash(&self, height: u32) -> Result<BlockHash, Self::Error>;
}

impl<T> FilterChain for T
where
    T: BlockchainInterface + Clone + Send + Sync + 'static,
    T::Error: Error + Send + Sync + 'static,
{
    type Error = T::Error;

    fn get_height(&self) -> Result<u32, Self::Error> {
        BlockchainInterface::get_height(self)
    }

    fn get_block_hash(&self, height: u32) -> Result<BlockHash, Self::Error> {
        BlockchainInterface::get_block_hash(self, height)
    }
}

/// Parameters for a compact-filter rescan.
#[derive(Debug, Clone)]
pub struct RescanRequest {
    /// Scripts to match against each filter.
    pub scripts: Vec<ScriptBuf>,

    /// First height to scan. Genesis is used when omitted.
    pub start_height: Option<u32>,

    /// Last height to scan, inclusively. The current tip is used when omitted.
    pub end_height: Option<u32>,

    /// Maximum number of matched blocks buffered until the caller consumes a page.
    pub max_blocks_per_page: Option<usize>,
}

impl RescanRequest {
    /// Creates a full-chain rescan for `scripts`.
    pub fn new(scripts: Vec<ScriptBuf>) -> Self {
        Self {
            scripts,
            start_height: None,
            end_height: None,
            max_blocks_per_page: None,
        }
    }

    /// Restricts this rescan to an inclusive height range.
    pub fn with_range(mut self, start_height: Option<u32>, end_height: Option<u32>) -> Self {
        self.start_height = start_height;
        self.end_height = end_height;
        self
    }

    /// Sets the maximum number of matched blocks buffered for this rescan.
    pub fn with_max_blocks_per_page(mut self, max_blocks_per_page: usize) -> Self {
        self.max_blocks_per_page = Some(max_blocks_per_page);
        self
    }
}

/// How far a rescan has gone through its height range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RescanProgress {
    /// First height of the rescan, after the default start height was applied.
    pub start_height: u32,

    /// Last height of the rescan, inclusively.
    pub end_height: u32,

    /// Number of heights whose filter was already checked.
    pub scanned: u32,
}

/// Current state of an asynchronous rescan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RescanStatus {
    /// The rescan was accepted but has not produced a result yet.
    Started,

    /// At least one matched block is ready to consume.
    Available,

    /// Filters are still being scanned and no matched block is currently ready.
    Waiting,

    /// Every matched block has been consumed.
    Finished,
}

impl Display for RescanStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Started => write!(f, "rescan started"),
            Self::Available => write!(f, "rescan blocks are available"),
            Self::Waiting => write!(f, "rescan is still scanning filters"),
            Self::Finished => write!(f, "rescan finished"),
        }
    }
}

/// Stable identifier for an in-flight rescan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RescanTicket(u64);

/// Errors returned by the compact-filter service or its handles.
#[derive(Debug)]
pub enum FilterManError {
    /// The chain backend rejected a lookup.
    Chain(Box<dyn Error + Send + Sync>),

    /// The node interface failed while fetching network data.
    Node(Box<dyn Error + Send + Sync>),
    /// A concurrent filter request task failed.
    Task(tokio::task::JoinError),

    /// Persistent filter-header storage failed.
    Store(FlatFilterStoreError),

    /// BIP158 filter construction or matching failed.
    Bip158(bitcoin::bip158::Error),

    /// A peer returned filter headers or checkpoints that violate BIP157.
    InvalidHeaders(String),

    /// A downloaded filter does not commit to the stored header.
    InvalidFilter(u32),
    /// A peer returned a different number of filters than requested.
    InvalidFilterCount {
        /// Number of requested filters.
        expected: usize,

        /// Number of returned filters.
        received: usize,
    },

    /// A rescan request contained no scripts.
    EmptyRescan,

    /// A rescan reaches past the synchronized filter headers, so its filters can't be validated.
    FiltersNotSynced {
        /// Height of the last stored filter header, if any.
        filters: Option<u32>,

        /// Requested last height.
        end: u32,
    },

    /// The stored filter header at this height is for a block that left the best chain. The
    /// store catches up on its own, so the request can be retried.
    StaleFilterHeaders(u32),

    /// A rescan range is outside the current best chain or is reversed.
    InvalidRescanRange {
        /// Requested first height.
        start: u32,

        /// Requested last height.
        end: u32,

        /// Best-chain height when the request was accepted.
        tip: u32,
    },

    /// A rescan page size was zero or exceeded the service limit.
    InvalidPageSize(usize),

    /// The requested rescan ticket does not exist.
    RescanNotFound(RescanTicket),

    /// A background rescan failed.
    RescanFailed(String),

    /// The manager task has stopped.
    ManagerStopped,

    /// Internal shared state was poisoned.
    PoisonedLock,
}

impl FilterManError {
    fn chain<E>(error: E) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        Self::Chain(Box::new(error))
    }

    fn node<E>(error: E) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        Self::Node(Box::new(error))
    }
}

impl Display for FilterManError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Chain(error) => write!(f, "chain error: {error}"),
            Self::Node(error) => write!(f, "node error: {error}"),
            Self::Task(error) => write!(f, "filter request task failed: {error}"),
            Self::Store(error) => write!(f, "filter store error: {error}"),
            Self::Bip158(error) => write!(f, "BIP158 error: {error}"),
            Self::InvalidHeaders(reason) => write!(f, "invalid filter headers: {reason}"),
            Self::InvalidFilter(height) => {
                write!(f, "filter at height {height} does not match its header")
            }
            Self::InvalidFilterCount { expected, received } => write!(
                f,
                "peer returned {received} compact filters; expected {expected}"
            ),
            Self::EmptyRescan => write!(f, "a rescan requires at least one script"),
            Self::FiltersNotSynced { filters, end } => write!(
                f,
                "filter headers are synchronized up to {filters:?}, can't rescan up to {end} yet"
            ),
            Self::StaleFilterHeaders(height) => write!(
                f,
                "no filter header is stored for the best-chain block at height {height} (yet)"
            ),
            Self::InvalidRescanRange { start, end, tip } => write!(
                f,
                "invalid rescan range {start}..={end}; current tip is {tip}"
            ),
            Self::InvalidPageSize(size) => write!(
                f,
                "invalid rescan page size {size}; expected 1..={MAX_RESCAN_PAGE_SIZE}"
            ),
            Self::RescanNotFound(ticket) => write!(f, "rescan ticket {ticket:?} was not found"),
            Self::RescanFailed(error) => write!(f, "rescan failed: {error}"),
            Self::ManagerStopped => write!(f, "compact-filter manager stopped"),
            Self::PoisonedLock => write!(f, "compact-filter store lock was poisoned"),
        }
    }
}

impl Error for FilterManError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Chain(error) | Self::Node(error) => Some(error.as_ref()),
            Self::Store(error) => Some(error),
            Self::Bip158(error) => Some(error),
            Self::Task(error) => Some(error),
            _ => None,
        }
    }
}

impl From<FlatFilterStoreError> for FilterManError {
    fn from(error: FlatFilterStoreError) -> Self {
        Self::Store(error)
    }
}

impl From<bitcoin::bip158::Error> for FilterManError {
    fn from(error: bitcoin::bip158::Error) -> Self {
        Self::Bip158(error)
    }
}

impl<Store> From<PoisonError<MutexGuard<'_, Store>>> for FilterManError {
    fn from(_: PoisonError<MutexGuard<'_, Store>>) -> Self {
        Self::PoisonedLock
    }
}

#[derive(Debug)]
struct ConnectedBlock {
    block: Block,
    height: u32,
    spent_utxos: HashMap<OutPoint, UtxoData>,
}

#[derive(Clone)]
struct FilterBlockConsumer {
    sender: mpsc::Sender<ConnectedBlock>,
}

impl BlockConsumer for FilterBlockConsumer {
    fn wants_spent_utxos(&self) -> bool {
        true
    }

    fn on_block(
        &self,
        block: &Block,
        height: u32,
        spent_utxos: Option<&HashMap<OutPoint, UtxoData>>,
    ) {
        let Some(spent_utxos) = spent_utxos else {
            return;
        };
        let Ok(permit) = self.sender.try_reserve() else {
            return;
        };

        permit.send(ConnectedBlock {
            block: block.clone(),
            height,
            spent_utxos: spent_utxos.clone(),
        });
    }
}

enum ManagerRequest {
    Rescan {
        request: RescanRequest,
        response: oneshot::Sender<Result<RescanTicket, FilterManError>>,
    },
    RescanStatus {
        ticket: RescanTicket,
        response: oneshot::Sender<Result<RescanStatus, FilterManError>>,
    },
    RescanBlocks {
        ticket: RescanTicket,
        response: oneshot::Sender<Result<Vec<Block>, FilterManError>>,
    },
    RescanProgress {
        ticket: RescanTicket,
        response: oneshot::Sender<Result<RescanProgress, FilterManError>>,
    },
    CancelRescan {
        ticket: RescanTicket,
    },
    /// A rescan couldn't get valid filters for the batch starting at `height` from anyone.
    DistrustHeaders {
        height: u32,
    },
    Filter {
        height: u32,
        response: oneshot::Sender<Result<BlockFilter, FilterManError>>,
    },
}

struct RescanState {
    blocks: mpsc::Receiver<Block>,
    /// Sent by the rescan task as its last action, after its last block.
    outcome: oneshot::Receiver<Result<(), String>>,
    /// The received `outcome`, kept because the channel only yields it once.
    result: Option<Result<(), String>>,
    /// Last time the consumer asked about this rescan, to tell abandoned ones apart.
    last_polled: Instant,
    page_size: usize,
    first_status: bool,
    start: u32,
    /// Moves up while a rescan without an explicit end follows the tip.
    end: Arc<AtomicU32>,
    scanned: Arc<AtomicU32>,
}

/// Cloneable interface to a running [`FiltersMan`].
#[derive(Clone)]
pub struct FilterManHandle {
    sender: mpsc::Sender<ManagerRequest>,
    height: Arc<AtomicU32>,
}

impl FilterManHandle {
    /// Starts a rescan and returns its ticket without waiting for completion.
    pub async fn rescan(&self, request: RescanRequest) -> Result<RescanTicket, FilterManError> {
        let (response, receiver) = oneshot::channel();
        self.send(ManagerRequest::Rescan { request, response }, receiver)
            .await
    }

    /// Returns the current state of `ticket`.
    pub async fn get_info(&self, ticket: RescanTicket) -> Result<RescanStatus, FilterManError> {
        let (response, receiver) = oneshot::channel();
        self.send(ManagerRequest::RescanStatus { ticket, response }, receiver)
            .await
    }

    /// Consumes at most one page of currently available matched blocks.
    pub async fn get_blocks(&self, ticket: RescanTicket) -> Result<Vec<Block>, FilterManError> {
        let (response, receiver) = oneshot::channel();
        self.send(ManagerRequest::RescanBlocks { ticket, response }, receiver)
            .await
    }

    /// Stops `ticket` and frees what it holds. Consumers that give up on a rescan before it
    /// reports [`RescanStatus::Finished`] or a failure should call this.
    pub async fn cancel_rescan(&self, ticket: RescanTicket) {
        let _ = self
            .sender
            .send(ManagerRequest::CancelRescan { ticket })
            .await;
    }

    /// Returns how far `ticket` has gone through its height range.
    pub async fn get_progress(
        &self,
        ticket: RescanTicket,
    ) -> Result<RescanProgress, FilterManError> {
        let (response, receiver) = oneshot::channel();
        self.send(
            ManagerRequest::RescanProgress { ticket, response },
            receiver,
        )
        .await
    }

    /// Returns the height of the last persisted filter header, if any.
    ///
    /// Unlike the other methods this doesn't go through the manager's request queue, so it
    /// keeps answering while the manager is busy synchronizing headers.
    pub fn get_height(&self) -> Option<u32> {
        match self.height.load(Ordering::Relaxed) {
            NO_FILTER_HEADERS => None,
            height => Some(height),
        }
    }

    /// Returns a validated filter, fetching and caching it when necessary.
    pub async fn get_filter(&self, height: u32) -> Result<BlockFilter, FilterManError> {
        let (response, receiver) = oneshot::channel();
        self.send(ManagerRequest::Filter { height, response }, receiver)
            .await
    }

    async fn send<T>(
        &self,
        request: ManagerRequest,
        receiver: oneshot::Receiver<Result<T, FilterManError>>,
    ) -> Result<T, FilterManError> {
        self.sender
            .send(request)
            .await
            .map_err(|_| FilterManError::ManagerStopped)?;
        receiver.await.map_err(|_| FilterManError::ManagerStopped)?
    }
}

/// Compact-filter synchronization and rescan service.
pub struct FiltersMan<Store, Chain, Node> {
    store: Arc<Mutex<Store>>,
    node: Node,
    chain: Chain,
    requests: mpsc::Receiver<ManagerRequest>,
    request_sender: mpsc::Sender<ManagerRequest>,
    connected_blocks: mpsc::Receiver<ConnectedBlock>,
    block_sender: mpsc::Sender<ConnectedBlock>,
    rescans: HashMap<RescanTicket, RescanState>,
    next_ticket: u64,
    checkpoints: Vec<FilterHeader>,
    published_height: Arc<AtomicU32>,
    default_rescan_start: Option<i32>,
    /// Height at which a peer's message last contradicted the stored headers. See
    /// [`FiltersMan::contradicted_at`].
    suspect_height: Option<u32>,
    /// The request the current checkpoints came from, to tell the node whose they were.
    checkpoints_stop_hash: Option<BlockHash>,
    /// When the last synchronization failed, if the last one did.
    last_sync_failure: Option<Instant>,
    /// Peers' answers that contradicted what we hold, not yet reported to the node.
    unreported: Vec<Contradicted>,
}

/// A peer's answer that contradicted the stored headers, identified by its request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Contradicted {
    /// The `cfheaders` fetched up to this block.
    Headers(BlockHash),

    /// The `cfcheckpt` fetched through this block.
    Checkpoints(BlockHash),
}

impl<Store, Chain, Node> FiltersMan<Store, Chain, Node>
where
    Store: FilterHeadersStore,
    Chain: FilterChain,
    Node: ChainMethods + Clone + Send + Sync + 'static,
    Node::Error: Error + Send + Sync + 'static,
{
    /// Creates a compact-filter manager.
    pub fn new(store: Store, node: Node, chain: Chain) -> Self {
        let (request_sender, requests) = mpsc::channel(128);
        let (block_sender, connected_blocks) = mpsc::channel(CONNECTED_BLOCK_BUFFER);
        let published_height = store
            .get_height()
            .ok()
            .flatten()
            .unwrap_or(NO_FILTER_HEADERS);

        Self {
            store: Arc::new(Mutex::new(store)),
            node,
            chain,
            requests,
            request_sender,
            connected_blocks,
            block_sender,
            rescans: HashMap::new(),
            next_ticket: 0,
            checkpoints: Vec::new(),
            published_height: Arc::new(AtomicU32::new(published_height)),
            default_rescan_start: None,
            suspect_height: None,
            checkpoints_stop_hash: None,
            last_sync_failure: None,
            unreported: Vec::new(),
        }
    }

    /// Sets the height rescans start from when the request doesn't name one, e.g. a wallet
    /// birthday. A negative value is relative to the tip at the time of the rescan.
    ///
    /// A rescan downloads every full filter in its range, so this bounds the bandwidth spent
    /// on blocks that can't contain wallet history.
    pub fn with_default_rescan_start(mut self, height: Option<i32>) -> Self {
        self.default_rescan_start = height;
        self
    }

    /// Tells the node about the answers that contradicted us since the last time.
    async fn report_contradictions(&mut self) {
        for contradicted in std::mem::take(&mut self.unreported) {
            match contradicted {
                Contradicted::Headers(stop_hash) => {
                    self.node.report_invalid_cfheaders(stop_hash).await;
                }
                Contradicted::Checkpoints(stop_hash) => {
                    self.node.report_invalid_cfcheckpt(stop_hash).await;
                }
            }
        }
    }

    /// Publishes the store height after a step that may have failed halfway, e.g. between a
    /// truncation and the write that follows it. Whatever mutation path ran, and however it
    /// ended, the published height can't stay ahead of the store.
    fn republish_height(&self) {
        if let Err(error) = self.publish_height() {
            warn!(%error, "could not publish the compact filter header height");
        }
    }

    fn publish_height(&self) -> Result<(), FilterManError> {
        let height = self.store.lock()?.get_height()?;
        self.published_height
            .store(height.unwrap_or(NO_FILTER_HEADERS), Ordering::Relaxed);
        Ok(())
    }

    /// Returns a cloneable service handle.
    pub fn get_handle(&self) -> FilterManHandle {
        FilterManHandle {
            sender: self.request_sender.clone(),
            height: self.published_height.clone(),
        }
    }

    /// Returns a chain subscriber that builds filters for newly connected blocks.
    pub fn block_consumer(&self) -> Arc<dyn BlockConsumer> {
        Arc::new(FilterBlockConsumer {
            sender: self.block_sender.clone(),
        })
    }

    /// Runs synchronization and serves requests until every producer is dropped.
    pub async fn main_loop(mut self) -> Result<(), FilterManError> {
        if let Err(error) = self.sync().await {
            warn!(%error, "initial compact-filter synchronization failed; will retry");
        }
        self.republish_height();
        self.report_contradictions().await;

        let mut sync_interval = tokio::time::interval(SYNC_INTERVAL);
        sync_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        sync_interval.tick().await;

        loop {
            tokio::select! {
                request = self.requests.recv() => {
                    let Some(request) = request else {
                        return Ok(());
                    };
                    self.handle_request(request);
                }
                connected = self.connected_blocks.recv() => {
                    if let Some(connected) = connected {
                        let busy_since = Instant::now();
                        if let Err(error) = self.process_connected_block(connected).await {
                            warn!(%error, "failed to build compact filter for connected block");
                        }
                        self.republish_height();
                        self.report_contradictions().await;
                        self.excuse_rescan_consumers(busy_since);
                    }
                }
                _ = sync_interval.tick() => {
                    self.prune_abandoned_rescans();
                    let busy_since = Instant::now();
                    if let Err(error) = self.sync().await {
                        warn!(%error, "periodic compact-filter synchronization failed");
                    }
                    self.republish_height();
                    self.report_contradictions().await;
                    self.excuse_rescan_consumers(busy_since);
                }
            }
        }
    }

    fn handle_request(&mut self, request: ManagerRequest) {
        match request {
            ManagerRequest::Rescan { request, response } => {
                let _ = response.send(self.start_rescan(request));
            }
            ManagerRequest::RescanStatus { ticket, response } => {
                let _ = response.send(self.rescan_status(ticket));
            }
            ManagerRequest::RescanBlocks { ticket, response } => {
                let _ = response.send(self.rescan_blocks(ticket));
            }
            ManagerRequest::RescanProgress { ticket, response } => {
                let _ = response.send(self.rescan_progress(ticket));
            }
            ManagerRequest::DistrustHeaders { height } => {
                if let Err(error) = self.distrust_from(height) {
                    warn!(%error, "could not drop inconsistent compact filter headers");
                }
            }
            ManagerRequest::CancelRescan { ticket } => {
                // Dropping the receiver is what stops the rescan task.
                self.rescans.remove(&ticket);
            }
            ManagerRequest::Filter { height, response } => {
                // Fetched off the manager loop: the round trip to a peer would otherwise hold
                // back every other request.
                let store = self.store.clone();
                let node = self.node.clone();
                let chain = self.chain.clone();
                tokio::spawn(async move {
                    let result = Self::fetch_filter(store, node, chain, height).await;
                    let _ = response.send(result);
                });
            }
        }
    }

    fn start_rescan(&mut self, request: RescanRequest) -> Result<RescanTicket, FilterManError> {
        if request.scripts.is_empty() {
            return Err(FilterManError::EmptyRescan);
        }

        let tip = self.chain.get_height().map_err(FilterManError::chain)?;
        let end = request.end_height.unwrap_or(tip);
        let default_start = match self.default_rescan_start {
            None => 0,
            Some(height) if height >= 0 => height.unsigned_abs(),
            Some(offset) => tip.saturating_sub(offset.unsigned_abs()),
        };
        let default_start = if default_start <= end {
            default_start
        } else if request.end_height.is_some() {
            // The caller named an end before the default start: they asked for blocks the
            // default exists to skip, so it doesn't apply and the range starts at genesis.
            0
        } else if request.start_height.is_none() {
            // Nothing was named and the chain hasn't reached the default start. No block can
            // hold wallet history yet; scanning from genesis instead would download every
            // filter there is for nothing.
            return Ok(self.finished_rescan(tip));
        } else {
            default_start
        };
        let start = request.start_height.unwrap_or(default_start);
        if start > end || end > tip {
            return Err(FilterManError::InvalidRescanRange { start, end, tip });
        }

        // Failing here is synchronous and visible. Past this point the rescan runs detached
        // and would die on the first filter it has no header to validate against.
        let filters = self.store.lock()?.get_height()?;
        if filters.is_none_or(|filters| filters < end) {
            return Err(FilterManError::FiltersNotSynced { filters, end });
        }

        let page_size = request
            .max_blocks_per_page
            .unwrap_or(DEFAULT_RESCAN_PAGE_SIZE);
        if page_size == 0 || page_size > MAX_RESCAN_PAGE_SIZE {
            return Err(FilterManError::InvalidPageSize(page_size));
        }

        let ticket = RescanTicket(self.next_ticket);
        self.next_ticket = self.next_ticket.wrapping_add(1);
        let (sender, blocks) = mpsc::channel(page_size);
        let (outcome_sender, outcome) = oneshot::channel();
        let scanned = Arc::new(AtomicU32::new(0));
        let end = Arc::new(AtomicU32::new(end));
        self.rescans.insert(
            ticket,
            RescanState {
                blocks,
                outcome,
                result: None,
                last_polled: Instant::now(),
                page_size,
                first_status: true,
                start,
                end: end.clone(),
                scanned: scanned.clone(),
            },
        );

        let store = self.store.clone();
        let node = self.node.clone();
        let chain = self.chain.clone();
        let manager = self.request_sender.clone();
        tokio::spawn(async move {
            let result = Self::run_rescan(
                store, node, chain, request, start, &end, &sender, &scanned, &manager,
            )
            .await;
            // After the last block, so an `Ok` outcome means every match is already queued.
            let _ = outcome_sender.send(result.map_err(|error| error.to_string()));
        });

        Ok(ticket)
    }

    /// Registers a rescan that has nothing to scan, so the consumer sees it finish right away.
    fn finished_rescan(&mut self, tip: u32) -> RescanTicket {
        let ticket = RescanTicket(self.next_ticket);
        self.next_ticket = self.next_ticket.wrapping_add(1);
        let (_, blocks) = mpsc::channel(1);
        let (outcome_sender, outcome) = oneshot::channel();
        let _ = outcome_sender.send(Ok(()));
        self.rescans.insert(
            ticket,
            RescanState {
                blocks,
                outcome,
                result: None,
                last_polled: Instant::now(),
                page_size: 1,
                first_status: true,
                start: tip,
                end: Arc::new(AtomicU32::new(tip)),
                scanned: Arc::new(AtomicU32::new(1)),
            },
        );

        ticket
    }

    fn rescan_status(&mut self, ticket: RescanTicket) -> Result<RescanStatus, FilterManError> {
        let state = self
            .rescans
            .get_mut(&ticket)
            .ok_or(FilterManError::RescanNotFound(ticket))?;
        state.last_polled = Instant::now();

        // The outcome is sampled before the queue: the rescan task sends it after its last
        // block, so once it reads `Ok` an empty queue really means every match was consumed.
        // Anything short of an explicit `Ok` (a failure, or a task that died) is not a finish.
        let status = match Self::rescan_outcome(state) {
            Some(Err(error)) => Err(FilterManError::RescanFailed(error)),
            _ if !state.blocks.is_empty() => return Ok(RescanStatus::Available),
            Some(Ok(())) => Ok(RescanStatus::Finished),
            None if state.first_status => {
                state.first_status = false;
                return Ok(RescanStatus::Started);
            }
            None => return Ok(RescanStatus::Waiting),
        };

        // Reported to the consumer, so the rescan is over.
        self.rescans.remove(&ticket);
        status
    }

    fn rescan_progress(&mut self, ticket: RescanTicket) -> Result<RescanProgress, FilterManError> {
        let state = self
            .rescans
            .get_mut(&ticket)
            .ok_or(FilterManError::RescanNotFound(ticket))?;
        state.last_polled = Instant::now();

        Ok(RescanProgress {
            start_height: state.start,
            end_height: state.end.load(Ordering::Relaxed),
            scanned: state.scanned.load(Ordering::Relaxed),
        })
    }

    fn rescan_blocks(&mut self, ticket: RescanTicket) -> Result<Vec<Block>, FilterManError> {
        let state = self
            .rescans
            .get_mut(&ticket)
            .ok_or(FilterManError::RescanNotFound(ticket))?;
        state.last_polled = Instant::now();

        if let Some(Err(error)) = Self::rescan_outcome(state) {
            self.rescans.remove(&ticket);
            return Err(FilterManError::RescanFailed(error));
        }

        let mut blocks = Vec::with_capacity(state.page_size);
        for _ in 0..state.page_size {
            match state.blocks.try_recv() {
                Ok(block) => blocks.push(block),
                Err(mpsc::error::TryRecvError::Empty | mpsc::error::TryRecvError::Disconnected) => {
                    break;
                }
            }
        }

        Ok(blocks)
    }

    fn rescan_outcome(state: &mut RescanState) -> Option<Result<(), String>> {
        if state.result.is_none() {
            state.result = match state.outcome.try_recv() {
                Ok(outcome) => Some(outcome),
                Err(oneshot::error::TryRecvError::Empty) => None,
                // The task went away without an outcome: it panicked or was aborted.
                Err(oneshot::error::TryRecvError::Closed) => {
                    Some(Err("rescan task stopped unexpectedly".to_owned()))
                }
            };
        }

        state.result.clone()
    }

    /// The manager doesn't serve requests while it synchronizes, so time spent there says
    /// nothing about whether a consumer is still around.
    fn excuse_rescan_consumers(&mut self, busy_since: Instant) {
        let busy_for = busy_since.elapsed();
        for state in self.rescans.values_mut() {
            state.last_polled += busy_for;
        }
    }

    /// Drops the rescans whose consumer stopped asking about them.
    fn prune_abandoned_rescans(&mut self) {
        self.rescans.retain(|ticket, state| {
            let abandoned = state.last_polled.elapsed() > RESCAN_IDLE_TIMEOUT;
            if abandoned {
                warn!(?ticket, "dropping abandoned compact-filter rescan");
            }
            !abandoned
        });
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_rescan(
        store: Arc<Mutex<Store>>,
        node: Node,
        chain: Chain,
        request: RescanRequest,
        start: u32,
        end_height: &AtomicU32,
        blocks: &mpsc::Sender<Block>,
        scanned: &AtomicU32,
        manager: &mpsc::Sender<ManagerRequest>,
    ) -> Result<(), FilterManError> {
        // The consumer keeps feeding its wallet the blocks that connect while we scan, and a
        // wallet only sees a spend if it already knows the output being spent. A block that
        // connected during the scan and spends an output we deliver later would leave that
        // output looking unspent forever. So a rescan that wasn't given an end isn't over until
        // it caught up with the tip: those blocks are delivered again, after the historical ones.
        let follows_tip = request.end_height.is_none();
        let mut end = end_height.load(Ordering::Relaxed);
        let mut batch_start = start;
        let mut matching_blocks = tracing::enabled!(tracing::Level::DEBUG).then(Vec::new);
        loop {
            let batch_end = batch_start.saturating_add(FILTER_BATCH_SIZE - 1).min(end);
            let mut invalid_attempts = 0;
            let filters = loop {
                if blocks.is_closed() {
                    return Err(FilterManError::ManagerStopped);
                }

                match Self::fetch_filters(
                    store.clone(),
                    node.clone(),
                    chain.clone(),
                    batch_start,
                    batch_end,
                )
                .await
                {
                    Ok(filters) => break filters,
                    Err(
                        error @ (FilterManError::Node(_) | FilterManError::StaleFilterHeaders(_)),
                    ) => {
                        warn!(
                            %error,
                            start = batch_start,
                            end = batch_end,
                            "compact-filter rescan batch failed; retrying"
                        );
                        tokio::time::sleep(RESCAN_RETRY_INTERVAL).await;
                    }
                    // One peer serving bad data shouldn't cost the whole rescan: everything
                    // scanned so far would be downloaded again by the next attempt.
                    Err(
                        error @ (FilterManError::InvalidFilter(_)
                        | FilterManError::InvalidFilterCount { .. }),
                    ) if invalid_attempts + 1 < MAX_INVALID_BATCH_ATTEMPTS => {
                        invalid_attempts += 1;
                        warn!(
                            %error,
                            start = batch_start,
                            end = batch_end,
                            attempt = invalid_attempts,
                            "compact-filter rescan batch failed validation; retrying"
                        );
                        tokio::time::sleep(RESCAN_RETRY_INTERVAL).await;
                    }
                    Err(
                        error @ (FilterManError::InvalidFilter(_)
                        | FilterManError::InvalidFilterCount { .. }),
                    ) => {
                        // Every attempt was reported to the node, which sheds a peer after two
                        // bad batches, so by now more than one peer disagreed with our headers.
                        // The headers are the likelier culprit: have them fetched again, or
                        // every later rescan of this range fails the same way.
                        let _ = manager
                            .send(ManagerRequest::DistrustHeaders {
                                height: batch_start,
                            })
                            .await;
                        return Err(error);
                    }
                    Err(error) => return Err(error),
                }
            };

            for (block_hash, filter) in filters {
                let matches = filter.match_any(
                    &block_hash,
                    request.scripts.iter().map(|script| script.as_bytes()),
                )?;
                if !matches {
                    continue;
                }

                let block = loop {
                    if blocks.is_closed() {
                        return Err(FilterManError::ManagerStopped);
                    }
                    match node.get_block(block_hash).await {
                        Ok(Some(block)) => break block,
                        Ok(None) => {
                            warn!(%block_hash, "rescan block unavailable; retrying");
                        }
                        Err(error) => {
                            warn!(%error, %block_hash, "rescan block request failed; retrying");
                        }
                    }
                    tokio::time::sleep(RESCAN_RETRY_INTERVAL).await;
                };
                blocks
                    .send(block)
                    .await
                    .map_err(|_| FilterManError::ManagerStopped)?;
                if let Some(matching_blocks) = &mut matching_blocks {
                    matching_blocks.push(block_hash);
                }
            }

            scanned.store(batch_end - start + 1, Ordering::Relaxed);

            if batch_end == end && follows_tip {
                let tip = chain.get_height().map_err(FilterManError::chain)?;
                if tip > end {
                    debug!(
                        end,
                        tip, "compact-filter rescan is catching up with the tip"
                    );
                    end = tip;
                    end_height.store(tip, Ordering::Relaxed);
                }
            }

            if batch_end == end {
                if let Some(matching_blocks) = matching_blocks {
                    debug!(
                        start,
                        end,
                        ?matching_blocks,
                        "compact-filter rescan finished"
                    );
                }
                return Ok(());
            }
            batch_start = batch_end + 1;
        }
    }

    async fn fetch_filter(
        store: Arc<Mutex<Store>>,
        node: Node,
        chain: Chain,
        height: u32,
    ) -> Result<BlockFilter, FilterManError> {
        let mut filters = Self::fetch_filters(store, node, chain, height, height).await?;
        Ok(filters
            .pop()
            .expect("a one-height filter range returns one filter")
            .1)
    }

    async fn fetch_filters(
        store: Arc<Mutex<Store>>,
        node: Node,
        chain: Chain,
        start: u32,
        end: u32,
    ) -> Result<Vec<(BlockHash, BlockFilter)>, FilterManError> {
        let heights = start..=end;
        let mut block_hashes = Vec::with_capacity(heights.size_hint().0);
        for height in heights.clone() {
            block_hashes.push(
                chain
                    .get_block_hash(height)
                    .map_err(FilterManError::chain)?,
            );
        }

        let mut filters = {
            let mut store = store.lock()?;
            // The cache and the headers filters are validated against are keyed by height. After
            // a reorg they describe the old branch until the store is reconciled, and a filter
            // of the old block matched with the new block's hash gives false negatives.
            for (height, block_hash) in heights.clone().zip(&block_hashes) {
                // A height missing from the store was just dropped by a reorg or a repair.
                if !Self::stores_header_for(&mut *store, height, *block_hash)? {
                    return Err(FilterManError::StaleFilterHeaders(height));
                }
            }
            heights
                .clone()
                .map(|height| store.get_filter(height))
                .collect::<Result<Vec<_>, _>>()?
        };
        let mut requests = tokio::task::JoinSet::new();
        for first in (0..filters.len()).step_by(FILTER_REQUEST_SIZE) {
            let last = (first + FILTER_REQUEST_SIZE).min(filters.len());
            if filters[first..last].iter().all(Option::is_some) {
                continue;
            }

            let node = node.clone();
            let requested_hashes = block_hashes[first..last].to_vec();
            let request_height = start + first as u32;
            requests.spawn(async move {
                let expected = requested_hashes.len();
                let filters = node.get_cfilter(request_height, requested_hashes).await?;
                Ok::<_, Node::Error>((first, expected, filters))
            });
        }

        while let Some(response) = requests.join_next().await {
            let (first, expected, received_filters) = response
                .map_err(FilterManError::Task)?
                .map_err(FilterManError::node)?;
            let validated = Self::accept_filters(
                &store,
                start + first as u32,
                &block_hashes[first..first + expected],
                received_filters,
            );
            let accepted = match validated {
                Ok(accepted) => accepted,
                Err(error) => {
                    // Whoever served this chunk is either misbehaving or disagrees with the
                    // header chain we hold. Let the node know, so a retry goes somewhere else.
                    if matches!(
                        error,
                        FilterManError::InvalidFilter(_)
                            | FilterManError::InvalidFilterCount { .. }
                    ) {
                        let stop_hash = block_hashes[first + expected - 1];
                        node.report_invalid_cfilters(stop_hash).await;
                    }
                    return Err(error);
                }
            };
            for (offset, filter) in accepted.into_iter().enumerate() {
                filters[first + offset] = Some(filter);
            }
        }

        Ok(block_hashes
            .into_iter()
            .zip(filters)
            .map(|(block_hash, filter)| {
                (
                    block_hash,
                    filter.expect("every requested compact filter is available"),
                )
            })
            .collect())
    }

    /// Validates the filters a peer returned for the `expected` heights from `first_height` on,
    /// and caches them. Nothing is cached unless the whole chunk is valid.
    fn accept_filters(
        store: &Mutex<Store>,
        first_height: u32,
        block_hashes: &[BlockHash],
        received: Vec<BlockFilter>,
    ) -> Result<Vec<BlockFilter>, FilterManError> {
        let expected = block_hashes.len();
        if received.len() != expected {
            return Err(FilterManError::InvalidFilterCount {
                expected,
                received: received.len(),
            });
        }

        let mut store = store.lock()?;
        for (offset, filter) in received.iter().enumerate() {
            let height = first_height + offset as u32;
            // The store may have been truncated, or refilled for another branch, during the
            // round trip. That isn't the peer's fault and isn't fatal: the caller retries once
            // the store caught up.
            if !Self::stores_header_for(&mut *store, height, block_hashes[offset])? {
                return Err(FilterManError::StaleFilterHeaders(height));
            }
            Self::validate_filter(&mut *store, height, filter)?;
            // A crafted header can vouch for a crafted filter, so this isn't implied by the above.
            if !declares_plausible_element_count(filter) {
                return Err(FilterManError::InvalidFilter(height));
            }
        }
        for (offset, filter) in received.iter().enumerate() {
            store.put_filter(first_height + offset as u32, filter.clone())?;
        }

        Ok(received)
    }

    /// Whether `store` holds a filter header at `height`, and it is the one for `block_hash`.
    fn stores_header_for(
        store: &mut Store,
        height: u32,
        block_hash: BlockHash,
    ) -> Result<bool, FilterManError> {
        match store.get_block_hash(height) {
            Ok(stored_hash) => Ok(stored_hash == block_hash),
            Err(FlatFilterStoreError::NotFound) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    fn validate_filter(
        store: &mut Store,
        height: u32,
        filter: &BlockFilter,
    ) -> Result<(), FilterManError> {
        let previous_header = if height == 0 {
            FilterHeader::all_zeros()
        } else {
            store.get_filter_header(height - 1)?
        };
        let expected_header = store.get_filter_header(height)?;

        if filter.filter_header(&previous_header) != expected_header {
            return Err(FilterManError::InvalidFilter(height));
        }

        Ok(())
    }

    async fn process_connected_block(
        &mut self,
        connected: ConnectedBlock,
    ) -> Result<(), FilterManError> {
        let filter = BlockFilter::new_script_filter(&connected.block, |outpoint| {
            connected
                .spent_utxos
                .get(outpoint)
                .map(|utxo| utxo.txout.script_pubkey.as_script())
                .ok_or(bitcoin::bip158::Error::UtxoMissing(*outpoint))
        })?;

        let height = connected.height;
        let needs_sync = match self.store.lock()?.get_height()? {
            Some(stored_height) => stored_height.saturating_add(1) < height,
            None => height > 0,
        };
        if needs_sync {
            // The headers below this block are missing. If we just failed to fetch them, the
            // periodic synchronization will, and this block's header comes with them.
            if self.synced_recently_failed() {
                debug!(height, "not building a filter: header sync is failing");
                return Ok(());
            }
            self.sync().await?;
        }

        // Block notifications are dropped while we are busy, so the entry below this block may
        // belong to a branch that was reorged out. Chaining onto it would store a header that
        // no filter ever validates against.
        if height > 0 && !self.stores_parent_of(&connected)? {
            if self.synced_recently_failed() {
                debug!(height, "not building a filter: header sync is failing");
                return Ok(());
            }
            self.sync().await?;
            if !self.stores_parent_of(&connected)? {
                return Err(FilterManError::InvalidHeaders(format!(
                    "the filter header below height {height} is not for the block's parent"
                )));
            }
        }

        let block_hash = connected.block.block_hash();
        let mut store = self.store.lock()?;
        let previous_header = if height == 0 {
            FilterHeader::all_zeros()
        } else {
            store.get_filter_header(height - 1)?
        };
        let filter_header = filter.filter_header(&previous_header);

        let expected_checkpoint = if height > 0 && height % CHECKPOINT_INTERVAL == 0 {
            self.checkpoints
                .get((height / CHECKPOINT_INTERVAL - 1) as usize)
                .copied()
        } else {
            None
        };
        match store.get_height()? {
            Some(stored_height) if stored_height >= height => {
                let stored_hash = store.get_block_hash(height)?;
                let stored_header = store.get_filter_header(height)?;
                if stored_hash == block_hash {
                    if stored_header != filter_header {
                        // Both chain onto the same previous header, so they differ in the
                        // filter hash, and ours comes from a block we validated. Everything
                        // above was chained onto the wrong header and is fetched again.
                        warn!(
                            height,
                            "stored filter header disagrees with the local filter"
                        );
                        store.truncate(height.checked_sub(1))?;
                        store.put_filter_header(block_hash, filter_header)?;
                        self.checkpoints.clear();
                    }
                } else {
                    store.truncate(height.checked_sub(1))?;
                    store.put_filter_header(block_hash, filter_header)?;
                    self.checkpoints
                        .truncate((height.saturating_sub(1) / CHECKPOINT_INTERVAL) as usize);
                }
            }
            Some(stored_height) if stored_height.saturating_add(1) == height => {
                if expected_checkpoint.is_some_and(|expected| expected != filter_header) {
                    // Either the checkpoint or the headers below are wrong. The next
                    // synchronization compares fresh checkpoints with what is stored.
                    drop(store);
                    let by = self.checkpoints_stop_hash.map(Contradicted::Checkpoints);
                    self.contradicted_at(height, by)?;
                    return Err(FilterManError::InvalidHeaders(format!(
                        "locally built filter disagrees with checkpoint at height {height}"
                    )));
                }
                store.put_filter_header(block_hash, filter_header)?;
            }
            None if height == 0 => {
                store.put_filter_header(block_hash, filter_header)?;
            }
            _ => {
                return Err(FilterManError::InvalidHeaders(format!(
                    "cannot connect locally built filter at height {height}"
                )));
            }
        }

        store.put_filter(height, filter)?;
        store.flush()?;
        self.published_height.store(
            store.get_height()?.unwrap_or(NO_FILTER_HEADERS),
            Ordering::Relaxed,
        );
        Ok(())
    }

    fn synced_recently_failed(&self) -> bool {
        self.last_sync_failure
            .is_some_and(|failed_at| failed_at.elapsed() < SYNC_RETRY_INTERVAL)
    }

    fn stores_parent_of(&self, connected: &ConnectedBlock) -> Result<bool, FilterManError> {
        let mut store = self.store.lock()?;
        let parent_height = connected.height - 1;
        if store.get_height()?.is_none_or(|tip| tip < parent_height) {
            return Ok(false);
        }

        Ok(store.get_block_hash(parent_height)? == connected.block.header.prev_blockhash)
    }

    /// Synchronizes filter headers and BIP157 checkpoints to the current best-chain tip.
    pub async fn sync(&mut self) -> Result<(), FilterManError> {
        let result = self.sync_inner().await;
        self.last_sync_failure = result.is_err().then(Instant::now);
        result
    }

    async fn sync_inner(&mut self) -> Result<(), FilterManError> {
        self.reconcile_store()?;
        let tip = self.chain.get_height().map_err(FilterManError::chain)?;
        self.sync_checkpoints(tip).await?;
        self.verify_stored_checkpoints()?;

        loop {
            let Some((start, stop, stop_hash)) = self.next_header_range()? else {
                break;
            };
            debug!(start, stop, %stop_hash, "requesting compact filter headers");
            let headers = self
                .node
                .get_cfilters_headers(start, stop_hash)
                .await
                .map_err(FilterManError::node)?;
            self.apply_headers(start, stop, stop_hash, headers)?;
        }

        // Fresh checkpoints and every batch agreed with what is stored.
        self.suspect_height = None;
        let height = self.store.lock()?.get_height()?;
        info!(?height, "compact filter headers synchronized");
        Ok(())
    }

    fn reconcile_store(&mut self) -> Result<(), FilterManError> {
        let tip = self.chain.get_height().map_err(FilterManError::chain)?;
        let Some(stored_tip) = self.store.lock()?.get_height()? else {
            return Ok(());
        };
        let mut height = stored_tip.min(tip);

        loop {
            let stored_hash = self.store.lock()?.get_block_hash(height)?;
            let chain_hash = self
                .chain
                .get_block_hash(height)
                .map_err(FilterManError::chain)?;
            if stored_hash == chain_hash {
                if height != stored_tip {
                    self.store.lock()?.truncate(Some(height))?;
                    self.checkpoints
                        .truncate((height / CHECKPOINT_INTERVAL) as usize);
                    self.publish_height()?;
                }
                return Ok(());
            }

            if height == 0 {
                self.store.lock()?.truncate(None)?;
                self.checkpoints.clear();
                self.publish_height()?;
                return Ok(());
            }
            height -= 1;
        }
    }

    async fn sync_checkpoints(&mut self, tip: u32) -> Result<(), FilterManError> {
        let expected_count = (tip / CHECKPOINT_INTERVAL) as usize;
        if expected_count == 0 {
            self.checkpoints.clear();
            return Ok(());
        }
        if self.checkpoints.len() == expected_count {
            return Ok(());
        }

        let stop_hash = self
            .chain
            .get_block_hash(tip)
            .map_err(FilterManError::chain)?;
        let response = self
            .node
            .get_cfcheckpt(stop_hash)
            .await
            .map_err(FilterManError::node)?;

        if response.filter_type != BASIC_FILTER_TYPE {
            return Err(FilterManError::InvalidHeaders(format!(
                "unexpected checkpoint filter type {}",
                response.filter_type
            )));
        }
        if response.stop_hash != stop_hash {
            return Err(FilterManError::InvalidHeaders(format!(
                "checkpoint stop hash {} does not match requested {stop_hash}",
                response.stop_hash
            )));
        }
        if response.filter_headers.len() != expected_count {
            return Err(FilterManError::InvalidHeaders(format!(
                "received {} checkpoints, expected {expected_count}",
                response.filter_headers.len()
            )));
        }

        self.checkpoints = response.filter_headers;
        self.checkpoints_stop_hash = Some(stop_hash);
        Ok(())
    }

    /// Forgets the filter headers from the checkpoint interval containing `height` onwards, and
    /// the checkpoints with them, so the next synchronization fetches both again.
    ///
    /// Headers and checkpoints each come from a single peer. When they disagree with each other,
    /// or with a filter we built ourselves, we can't tell which one is wrong, and keeping either
    /// would make every later synchronization fail the same way forever. Both are cheap to fetch.
    fn distrust_from(&mut self, height: u32) -> Result<(), FilterManError> {
        let last_trusted = (height.saturating_sub(1) / CHECKPOINT_INTERVAL) * CHECKPOINT_INTERVAL;
        let keep = (last_trusted > 0).then_some(last_trusted);
        warn!(
            height,
            ?keep,
            "compact filter headers are inconsistent; fetching them again"
        );

        {
            let mut store = self.store.lock()?;
            if store
                .get_height()?
                .is_some_and(|tip| keep.is_none_or(|keep| tip > keep))
            {
                store.truncate(keep)?;
            }
        }
        self.checkpoints.clear();
        self.publish_height()
    }

    /// A message from a peer contradicts the headers stored at `height`.
    ///
    /// The stored chain has been checked before (against an earlier checkpoint set, and by every
    /// filter validated against it), so one message isn't enough to throw it away: a single
    /// lying `cfcheckpt` would make us delete and download the whole chain again. The first
    /// strike only forgets the checkpoints, so the next synchronization fetches them again. If
    /// what it gets contradicts the same height, the headers go.
    ///
    /// Either way the peer behind `by` gets reported: we can't tell whether it or the peer our
    /// headers came from is wrong, which is why a report costs a peer half a ban, not a whole
    /// one. It also keeps a liar from stalling us by contradicting a different height each time.
    fn contradicted_at(
        &mut self,
        height: u32,
        by: Option<Contradicted>,
    ) -> Result<(), FilterManError> {
        self.unreported.extend(by);
        self.checkpoints.clear();
        if self.suspect_height.replace(height) != Some(height) {
            warn!(
                height,
                "a peer contradicts the stored compact filter headers; asking again"
            );
            return Ok(());
        }

        self.suspect_height = None;
        self.distrust_from(height)
    }

    fn verify_stored_checkpoints(&mut self) -> Result<(), FilterManError> {
        let Some(stored_tip) = self.store.lock()?.get_height()? else {
            return Ok(());
        };

        for (index, checkpoint) in self.checkpoints.iter().enumerate() {
            let height = u32::try_from(index + 1)
                .ok()
                .and_then(|index| index.checked_mul(CHECKPOINT_INTERVAL))
                .ok_or_else(|| {
                    FilterManError::InvalidHeaders("checkpoint height overflow".to_owned())
                })?;
            if height > stored_tip {
                break;
            }
            if self.store.lock()?.get_filter_header(height)? != *checkpoint {
                let by = self.checkpoints_stop_hash.map(Contradicted::Checkpoints);
                self.contradicted_at(height, by)?;
                return Err(FilterManError::InvalidHeaders(format!(
                    "stored filter header disagrees with checkpoint at height {height}"
                )));
            }
        }

        Ok(())
    }

    fn next_header_range(&self) -> Result<Option<(u32, u32, BlockHash)>, FilterManError> {
        let tip = self.chain.get_height().map_err(FilterManError::chain)?;
        let start = self
            .store
            .lock()?
            .get_height()?
            .map_or(0, |height| height.saturating_add(1));
        if start > tip {
            return Ok(None);
        }

        let stop = start.saturating_add(FILTER_HEADER_BATCH_SIZE - 1).min(tip);
        let stop_hash = self
            .chain
            .get_block_hash(stop)
            .map_err(FilterManError::chain)?;
        Ok(Some((start, stop, stop_hash)))
    }

    fn apply_headers(
        &mut self,
        start: u32,
        stop: u32,
        stop_hash: BlockHash,
        response: CFHeaders,
    ) -> Result<(), FilterManError> {
        if response.filter_type != BASIC_FILTER_TYPE {
            return Err(FilterManError::InvalidHeaders(format!(
                "unexpected filter type {}",
                response.filter_type
            )));
        }
        if response.stop_hash != stop_hash {
            return Err(FilterManError::InvalidHeaders(format!(
                "response stop hash {} does not match requested {stop_hash}",
                response.stop_hash
            )));
        }

        let expected_count = usize::try_from(stop - start + 1).map_err(|_| {
            FilterManError::InvalidHeaders("filter-header count overflow".to_owned())
        })?;
        if response.filter_hashes.len() != expected_count {
            return Err(FilterManError::InvalidHeaders(format!(
                "received {} filter hashes, expected {expected_count}",
                response.filter_hashes.len()
            )));
        }

        let previous_header = if start == 0 {
            FilterHeader::all_zeros()
        } else {
            self.store.lock()?.get_filter_header(start - 1)?
        };
        if response.previous_filter_header != previous_header {
            // Either the peer lies or what we stored is wrong; a fresh start settles it.
            if start > 0 {
                self.contradicted_at(start, Some(Contradicted::Headers(stop_hash)))?;
            }
            return Err(FilterManError::InvalidHeaders(format!(
                "filter headers do not connect at height {start}"
            )));
        }

        let mut entries = Vec::with_capacity(expected_count);
        let mut current_header = previous_header;
        for (offset, filter_hash) in response.filter_hashes.into_iter().enumerate() {
            let height = start
                + u32::try_from(offset).map_err(|_| {
                    FilterManError::InvalidHeaders("filter-header height overflow".to_owned())
                })?;
            current_header = filter_hash.filter_header(&current_header);

            if height > 0 && height % CHECKPOINT_INTERVAL == 0 {
                let checkpoint_index = (height / CHECKPOINT_INTERVAL - 1) as usize;
                if self
                    .checkpoints
                    .get(checkpoint_index)
                    .is_some_and(|checkpoint| *checkpoint != current_header)
                {
                    // A bad checkpoint set would otherwise reject every honest batch until
                    // the tip crosses the next interval.
                    self.checkpoints.clear();
                    return Err(FilterManError::InvalidHeaders(format!(
                        "filter header disagrees with checkpoint at height {height}"
                    )));
                }
            }

            let block_hash = self
                .chain
                .get_block_hash(height)
                .map_err(FilterManError::chain)?;
            entries.push((block_hash, current_header));
        }

        // The hashes were read after the round trip. If the chain moved meanwhile, they belong
        // to another branch than the headers, which were computed for `stop_hash`.
        if entries.last().is_some_and(|(hash, _)| *hash != stop_hash) {
            return Err(FilterManError::InvalidHeaders(format!(
                "best chain changed while fetching filter headers up to {stop}"
            )));
        }

        let mut store = self.store.lock()?;
        for (block_hash, filter_header) in entries {
            store.put_filter_header(block_hash, filter_header)?;
        }
        store.flush()?;
        self.published_height.store(
            store.get_height()?.unwrap_or(NO_FILTER_HEADERS),
            Ordering::Relaxed,
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fmt;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;

    use bitcoin::Network;
    use bitcoin::blockdata::constants::genesis_block;
    use bitcoin::p2p::message_filter::CFCheckpt;
    use tempfile::NamedTempFile;

    use super::*;
    use crate::FlatFilterStore;

    #[derive(Debug, Clone, Copy)]
    struct MockError(&'static str);

    impl Display for MockError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.0)
        }
    }

    impl Error for MockError {}

    #[derive(Clone)]
    struct MockChain {
        hashes: Arc<Vec<BlockHash>>,
    }

    impl FilterChain for MockChain {
        type Error = MockError;

        fn get_height(&self) -> Result<u32, Self::Error> {
            self.hashes
                .len()
                .checked_sub(1)
                .and_then(|height| u32::try_from(height).ok())
                .ok_or(MockError("empty chain"))
        }

        fn get_block_hash(&self, height: u32) -> Result<BlockHash, Self::Error> {
            self.hashes
                .get(height as usize)
                .copied()
                .ok_or(MockError("unknown height"))
        }
    }

    fn mock_block_hash(height: u32) -> BlockHash {
        let mut bytes = [0_u8; 32];
        bytes[..4].copy_from_slice(&height.to_le_bytes());
        BlockHash::from_byte_array(bytes)
    }

    #[derive(Clone)]
    struct MockNode {
        blocks: Arc<HashMap<BlockHash, Block>>,
        filters: Arc<HashMap<BlockHash, BlockFilter>>,
        header_responses: Arc<HashMap<(u32, BlockHash), CFHeaders>>,
        checkpoint_responses: Arc<HashMap<BlockHash, CFCheckpt>>,
        block_requests: Arc<AtomicUsize>,
        filter_requests: Arc<AtomicUsize>,
        filter_failures: Arc<AtomicUsize>,
        short_filter_responses: Arc<AtomicUsize>,
        invalid_reports: Arc<AtomicUsize>,
        active_filter_requests: Arc<AtomicUsize>,
        max_filter_requests: Arc<AtomicUsize>,
        header_requests: Arc<AtomicUsize>,
        checkpoint_requests: Arc<AtomicUsize>,
    }

    impl MockNode {
        fn new(
            blocks: HashMap<BlockHash, Block>,
            filters: HashMap<BlockHash, BlockFilter>,
        ) -> Self {
            Self {
                blocks: Arc::new(blocks),
                filters: Arc::new(filters),
                header_responses: Arc::new(HashMap::new()),
                checkpoint_responses: Arc::new(HashMap::new()),
                block_requests: Arc::new(AtomicUsize::new(0)),
                filter_requests: Arc::new(AtomicUsize::new(0)),
                header_requests: Arc::new(AtomicUsize::new(0)),
                filter_failures: Arc::new(AtomicUsize::new(0)),
                short_filter_responses: Arc::new(AtomicUsize::new(0)),
                invalid_reports: Arc::new(AtomicUsize::new(0)),
                active_filter_requests: Arc::new(AtomicUsize::new(0)),
                max_filter_requests: Arc::new(AtomicUsize::new(0)),
                checkpoint_requests: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    /// Decrements `counter` unless it is zero, and tells whether it did.
    fn take_one(counter: &AtomicUsize) -> bool {
        let mut current = counter.load(Ordering::Relaxed);
        while current > 0 {
            match counter.compare_exchange_weak(
                current,
                current - 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
        false
    }

    impl ChainMethods for MockNode {
        type Error = MockError;

        async fn get_block(&self, block_hash: BlockHash) -> Result<Option<Block>, Self::Error> {
            self.block_requests.fetch_add(1, Ordering::Relaxed);
            Ok(self.blocks.get(&block_hash).cloned())
        }

        async fn get_cfilters_headers(
            &self,
            start_height: u32,
            stop_hash: BlockHash,
        ) -> Result<CFHeaders, Self::Error> {
            self.header_requests.fetch_add(1, Ordering::Relaxed);
            self.header_responses
                .get(&(start_height, stop_hash))
                .cloned()
                .ok_or(MockError("unexpected filter-header request"))
        }

        async fn get_cfilter(
            &self,
            _start_height: u32,
            block_hashes: Vec<BlockHash>,
        ) -> Result<Vec<BlockFilter>, Self::Error> {
            self.filter_requests.fetch_add(1, Ordering::Relaxed);
            let active = self.active_filter_requests.fetch_add(1, Ordering::Relaxed) + 1;
            self.max_filter_requests
                .fetch_max(active, Ordering::Relaxed);
            tokio::task::yield_now().await;

            let result = if take_one(&self.filter_failures) {
                Err(MockError("filter request failed"))
            } else if take_one(&self.short_filter_responses) {
                Ok(Vec::new())
            } else {
                block_hashes
                    .into_iter()
                    .map(|block_hash| {
                        self.filters
                            .get(&block_hash)
                            .cloned()
                            .ok_or(MockError("unknown filter"))
                    })
                    .collect()
            };
            self.active_filter_requests.fetch_sub(1, Ordering::Relaxed);
            result
        }

        async fn report_invalid_cfilters(&self, _stop_hash: BlockHash) {
            self.invalid_reports.fetch_add(1, Ordering::Relaxed);
        }

        async fn get_cfcheckpt(&self, stop_hash: BlockHash) -> Result<CFCheckpt, Self::Error> {
            self.checkpoint_requests.fetch_add(1, Ordering::Relaxed);
            self.checkpoint_responses
                .get(&stop_hash)
                .cloned()
                .ok_or(MockError("unexpected filter-checkpoint request"))
        }
    }

    fn setup() -> (
        NamedTempFile,
        FlatFilterStore,
        MockChain,
        MockNode,
        Block,
        BlockFilter,
    ) {
        let file = NamedTempFile::new().unwrap();
        let mut store = FlatFilterStore::new(file.path()).unwrap();
        let block = genesis_block(Network::Regtest);
        let block_hash = block.block_hash();
        let filter = BlockFilter::new_script_filter(&block, |outpoint| {
            Err::<ScriptBuf, _>(bitcoin::bip158::Error::UtxoMissing(*outpoint))
        })
        .unwrap();
        store
            .put_filter_header(block_hash, filter.filter_header(&FilterHeader::all_zeros()))
            .unwrap();
        store.flush().unwrap();

        let chain = MockChain {
            hashes: Arc::new(vec![block_hash]),
        };
        let node = MockNode::new(
            HashMap::from([(block_hash, block.clone())]),
            HashMap::from([(block_hash, filter.clone())]),
        );
        (file, store, chain, node, block, filter)
    }

    #[tokio::test]
    async fn handle_fetches_validates_and_caches_filter() {
        let (_file, store, chain, node, _block, expected) = setup();
        let filter_requests = node.filter_requests.clone();
        let manager = FiltersMan::new(store, node, chain);
        let handle = manager.get_handle();
        let task = tokio::spawn(manager.main_loop());

        assert_eq!(handle.get_filter(0).await.unwrap(), expected);
        assert_eq!(handle.get_filter(0).await.unwrap(), expected);
        assert_eq!(filter_requests.load(Ordering::Relaxed), 1);

        task.abort();
    }

    #[tokio::test]
    async fn rescan_returns_matching_block_and_finishes() {
        let (_file, store, chain, node, block, _filter) = setup();
        let script = block.txdata[0].output[0].script_pubkey.clone();
        let manager = FiltersMan::new(store, node, chain);
        let handle = manager.get_handle();
        let task = tokio::spawn(manager.main_loop());
        let ticket = handle
            .rescan(RescanRequest::new(vec![script]).with_max_blocks_per_page(1))
            .await
            .unwrap();

        let matched = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let blocks = handle.get_blocks(ticket).await.unwrap();
                if !blocks.is_empty() {
                    break blocks;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(matched, vec![block]);

        let status = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let status = handle.get_info(ticket).await.unwrap();
                if status == RescanStatus::Finished {
                    break status;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(status, RescanStatus::Finished);

        task.abort();
    }

    #[tokio::test]
    async fn rescan_fetches_filters_in_batches() {
        let (_file, mut store, mut chain, mut node, block, first_filter) = setup();
        let mut second_block = block.clone();
        second_block.header.nonce = second_block.header.nonce.wrapping_add(1);
        let second_hash = second_block.block_hash();
        let second_filter = BlockFilter::new_script_filter(&second_block, |outpoint| {
            Err::<ScriptBuf, _>(bitcoin::bip158::Error::UtxoMissing(*outpoint))
        })
        .unwrap();
        let first_header = first_filter.filter_header(&FilterHeader::all_zeros());
        store
            .put_filter_header(second_hash, second_filter.filter_header(&first_header))
            .unwrap();
        store.flush().unwrap();
        Arc::make_mut(&mut chain.hashes).push(second_hash);
        Arc::make_mut(&mut node.blocks).insert(second_hash, second_block);
        Arc::make_mut(&mut node.filters).insert(second_hash, second_filter);
        let filter_requests = node.filter_requests.clone();

        let script = block.txdata[0].output[0].script_pubkey.clone();
        let manager = FiltersMan::new(store, node, chain);
        let handle = manager.get_handle();
        let task = tokio::spawn(manager.main_loop());
        let ticket = handle
            .rescan(RescanRequest::new(vec![script]))
            .await
            .unwrap();

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let _ = handle.get_blocks(ticket).await.unwrap();
                if handle.get_info(ticket).await.unwrap() == RescanStatus::Finished {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        assert_eq!(filter_requests.load(Ordering::Relaxed), 1);
        task.abort();
    }

    /// Extends the single-block [`setup`] chain with a second block paying to the same script.
    fn setup_two_blocks() -> (NamedTempFile, FlatFilterStore, MockChain, MockNode, Block) {
        let (file, mut store, mut chain, mut node, block, first_filter) = setup();
        let mut second_block = block.clone();
        second_block.header.nonce = second_block.header.nonce.wrapping_add(1);
        let second_hash = second_block.block_hash();
        let second_filter = BlockFilter::new_script_filter(&second_block, |outpoint| {
            Err::<ScriptBuf, _>(bitcoin::bip158::Error::UtxoMissing(*outpoint))
        })
        .unwrap();
        let first_header = first_filter.filter_header(&FilterHeader::all_zeros());
        store
            .put_filter_header(second_hash, second_filter.filter_header(&first_header))
            .unwrap();
        store.flush().unwrap();
        Arc::make_mut(&mut chain.hashes).push(second_hash);
        Arc::make_mut(&mut node.blocks).insert(second_hash, second_block.clone());
        Arc::make_mut(&mut node.filters).insert(second_hash, second_filter);

        (file, store, chain, node, second_block)
    }

    /// Consumes `ticket` to the end. The progress is read along the way, since a rescan is
    /// forgotten once it was reported as finished.
    async fn drain_rescan(
        handle: &FilterManHandle,
        ticket: RescanTicket,
    ) -> (Vec<Block>, RescanProgress) {
        tokio::time::timeout(Duration::from_secs(2), async {
            let mut matched = Vec::new();
            loop {
                matched.extend(handle.get_blocks(ticket).await.unwrap());
                let progress = handle.get_progress(ticket).await.unwrap();
                if handle.get_info(ticket).await.unwrap() == RescanStatus::Finished {
                    break (matched, progress);
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn default_rescan_start_skips_earlier_blocks() {
        let (_file, store, chain, node, second_block) = setup_two_blocks();
        let script = second_block.txdata[0].output[0].script_pubkey.clone();
        let manager = FiltersMan::new(store, node, chain).with_default_rescan_start(Some(1));
        let handle = manager.get_handle();
        let task = tokio::spawn(manager.main_loop());

        // Both blocks pay to `script`, but the one before the default start is never scanned.
        let ticket = handle
            .rescan(RescanRequest::new(vec![script.clone()]))
            .await
            .unwrap();
        let (matched, progress) = drain_rescan(&handle, ticket).await;
        assert_eq!(matched, vec![second_block]);
        assert_eq!((progress.start_height, progress.end_height), (1, 1));
        assert!(progress.scanned <= 1);

        // An explicit start height wins over the default one.
        let ticket = handle
            .rescan(RescanRequest::new(vec![script]).with_range(Some(0), None))
            .await
            .unwrap();
        assert_eq!(drain_rescan(&handle, ticket).await.0.len(), 2);

        task.abort();
    }

    #[tokio::test]
    async fn negative_default_rescan_start_is_relative_to_the_tip() {
        let (_file, store, chain, node, second_block) = setup_two_blocks();
        let script = second_block.txdata[0].output[0].script_pubkey.clone();
        let manager = FiltersMan::new(store, node, chain).with_default_rescan_start(Some(-1));
        let handle = manager.get_handle();
        let task = tokio::spawn(manager.main_loop());

        let ticket = handle
            .rescan(RescanRequest::new(vec![script.clone()]))
            .await
            .unwrap();
        let (_, progress) = drain_rescan(&handle, ticket).await;
        assert_eq!((progress.start_height, progress.end_height), (0, 1));

        task.abort();
    }

    #[tokio::test]
    async fn default_start_above_the_tip_scans_nothing() {
        let (_file, store, chain, node, second_block) = setup_two_blocks();
        let script = second_block.txdata[0].output[0].script_pubkey.clone();
        let filter_requests = node.filter_requests.clone();
        // The tip is at height 1.
        let manager = FiltersMan::new(store, node, chain).with_default_rescan_start(Some(2));
        let handle = manager.get_handle();
        let task = tokio::spawn(manager.main_loop());

        // With nothing named, falling back to genesis would download every filter for blocks
        // that can't hold wallet history.
        let ticket = handle
            .rescan(RescanRequest::new(vec![script.clone()]))
            .await
            .unwrap();
        let (matched, _) = drain_rescan(&handle, ticket).await;
        assert!(matched.is_empty());
        assert_eq!(filter_requests.load(Ordering::Relaxed), 0);

        // An explicit start above the tip stays an invalid range.
        assert!(matches!(
            handle
                .rescan(RescanRequest::new(vec![script]).with_range(Some(2), None))
                .await,
            Err(FilterManError::InvalidRescanRange { .. })
        ));

        task.abort();
    }

    #[tokio::test]
    async fn range_ending_before_the_default_start_is_scanned_from_genesis() {
        let (_file, store, chain, node, second_block) = setup_two_blocks();
        let script = second_block.txdata[0].output[0].script_pubkey.clone();
        let manager = FiltersMan::new(store, node, chain).with_default_rescan_start(Some(1));
        let handle = manager.get_handle();
        let task = tokio::spawn(manager.main_loop());

        let ticket = handle
            .rescan(RescanRequest::new(vec![script]).with_range(None, Some(0)))
            .await
            .unwrap();
        let (matched, progress) = drain_rescan(&handle, ticket).await;
        assert_eq!(matched.len(), 1);
        assert_eq!((progress.start_height, progress.end_height), (0, 0));

        task.abort();
    }

    #[tokio::test]
    async fn handle_reports_the_stored_height_without_the_manager_running() {
        let (_file, store, chain, node, _second_block) = setup_two_blocks();
        let manager = FiltersMan::new(store, node, chain);

        // `main_loop` was never spawned: the height doesn't go through the request queue.
        assert_eq!(manager.get_handle().get_height(), Some(1));

        let file = NamedTempFile::new().unwrap();
        let empty = FlatFilterStore::new(file.path()).unwrap();
        let (_file, _store, chain, node, _block, _filter) = setup();
        assert_eq!(
            FiltersMan::new(empty, node, chain)
                .get_handle()
                .get_height(),
            None
        );
    }

    #[tokio::test]
    async fn fetches_filter_chunks_concurrently() {
        let file = NamedTempFile::new().unwrap();
        let mut store = FlatFilterStore::new(file.path()).unwrap();
        let count = FILTER_REQUEST_SIZE + 1;
        let mut hashes = Vec::with_capacity(count);
        let mut filters = HashMap::with_capacity(count);
        let mut previous_header = FilterHeader::all_zeros();

        for height in 0..count {
            let height = height as u32;
            let block_hash = mock_block_hash(height);
            // Distinct per height, and declaring zero elements so the content stays plausible.
            let filter = BlockFilter::new(&[&[0][..], &height.to_le_bytes()].concat());
            previous_header = filter.filter_header(&previous_header);
            store
                .put_filter_header(block_hash, previous_header)
                .unwrap();
            hashes.push(block_hash);
            filters.insert(block_hash, filter);
        }
        store.flush().unwrap();

        let chain = MockChain {
            hashes: Arc::new(hashes),
        };
        let node = MockNode::new(HashMap::new(), filters);
        let filter_requests = node.filter_requests.clone();
        let max_filter_requests = node.max_filter_requests.clone();
        let received = FiltersMan::<FlatFilterStore, MockChain, MockNode>::fetch_filters(
            Arc::new(Mutex::new(store)),
            node,
            chain,
            0,
            count as u32 - 1,
        )
        .await
        .unwrap();

        assert_eq!(received.len(), count);
        assert_eq!(filter_requests.load(Ordering::Relaxed), 2);
        assert_eq!(max_filter_requests.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn rescan_retries_filter_request_errors() {
        let (_file, store, chain, node, block, _filter) = setup();
        node.filter_failures.store(1, Ordering::Relaxed);
        let filter_requests = node.filter_requests.clone();
        let script = block.txdata[0].output[0].script_pubkey.clone();
        let manager = FiltersMan::new(store, node, chain);
        let handle = manager.get_handle();
        let task = tokio::spawn(manager.main_loop());
        let ticket = handle
            .rescan(RescanRequest::new(vec![script]))
            .await
            .unwrap();

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let _ = handle.get_blocks(ticket).await.unwrap();
                if handle.get_info(ticket).await.unwrap() == RescanStatus::Finished {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        assert_eq!(filter_requests.load(Ordering::Relaxed), 2);
        task.abort();
    }

    #[tokio::test]
    async fn rescan_rejects_filter_with_an_overflowing_element_count() {
        let (file, _store, chain, _node, block, well_formed) = setup();
        assert!(declares_plausible_element_count(&well_formed));

        // Claims `u64::MAX` elements, whose product with BIP158's `M` overflows while matching.
        let mut content = vec![0xff; 9];
        content.extend_from_slice(&[0; 32]);
        let crafted = BlockFilter::new(&content);
        assert!(!declares_plausible_element_count(&crafted));

        // The header chain commits to the crafted filter, so it passes validation.
        drop(file);
        let file = NamedTempFile::new().unwrap();
        let mut store = FlatFilterStore::new(file.path()).unwrap();
        let block_hash = block.block_hash();
        store
            .put_filter_header(
                block_hash,
                crafted.filter_header(&FilterHeader::all_zeros()),
            )
            .unwrap();
        store.flush().unwrap();
        let node = MockNode::new(
            HashMap::from([(block_hash, block.clone())]),
            HashMap::from([(block_hash, crafted)]),
        );

        let script = block.txdata[0].output[0].script_pubkey.clone();
        let manager = FiltersMan::new(store, node, chain);
        let handle = manager.get_handle();
        let task = tokio::spawn(manager.main_loop());
        let ticket = handle
            .rescan(RescanRequest::new(vec![script]))
            .await
            .unwrap();

        // The batch is retried a few times, a second apart, before the rescan gives up.
        let failure = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                match handle.get_info(ticket).await {
                    Err(error) => break error,
                    Ok(status) => assert_ne!(status, RescanStatus::Finished),
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(matches!(failure, FilterManError::RescanFailed(_)));

        task.abort();
    }

    #[tokio::test]
    async fn rescan_retries_batches_that_fail_validation() {
        let (_file, store, chain, node, block, _filter) = setup();
        node.short_filter_responses.store(1, Ordering::Relaxed);
        let filter_requests = node.filter_requests.clone();
        let invalid_reports = node.invalid_reports.clone();
        let script = block.txdata[0].output[0].script_pubkey.clone();
        let manager = FiltersMan::new(store, node, chain);
        let handle = manager.get_handle();
        let task = tokio::spawn(manager.main_loop());
        let ticket = handle
            .rescan(RescanRequest::new(vec![script]))
            .await
            .unwrap();

        let matched = tokio::time::timeout(Duration::from_secs(3), async {
            let mut matched = Vec::new();
            loop {
                matched.extend(handle.get_blocks(ticket).await.unwrap());
                if handle.get_info(ticket).await.unwrap() == RescanStatus::Finished {
                    break matched;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        assert_eq!(matched, vec![block]);
        assert_eq!(filter_requests.load(Ordering::Relaxed), 2);
        // The node heard about the bad batch, so it can send the retry to another peer.
        assert_eq!(invalid_reports.load(Ordering::Relaxed), 1);
        task.abort();
    }

    #[tokio::test]
    async fn batch_that_never_validates_drops_the_headers_it_was_checked_against() {
        let (_file, store, chain, node, block, _filter) = setup();
        node.short_filter_responses
            .store(usize::MAX, Ordering::Relaxed);
        let invalid_reports = node.invalid_reports.clone();
        let script = block.txdata[0].output[0].script_pubkey.clone();
        let manager = FiltersMan::new(store, node, chain);
        let handle = manager.get_handle();
        let task = tokio::spawn(manager.main_loop());
        let ticket = handle
            .rescan(RescanRequest::new(vec![script]))
            .await
            .unwrap();

        // The attempts are a second apart.
        let failure = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if let Err(error) = handle.get_info(ticket).await {
                    break error;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .unwrap();
        assert!(matches!(failure, FilterManError::RescanFailed(_)));

        // Every attempt was reported; with all of them failing, the headers are the suspect.
        assert_eq!(
            invalid_reports.load(Ordering::Relaxed),
            MAX_INVALID_BATCH_ATTEMPTS as usize
        );
        tokio::time::timeout(Duration::from_secs(5), async {
            while handle.get_height().is_some() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();

        task.abort();
    }

    #[tokio::test]
    async fn rejects_rescans_past_the_synchronized_filter_headers() {
        let (_file, store, mut chain, node, block, _filter) = setup();
        // The chain is one block ahead of the filter-header store.
        let mut next_block = block.clone();
        next_block.header.nonce = next_block.header.nonce.wrapping_add(1);
        Arc::make_mut(&mut chain.hashes).push(next_block.block_hash());
        let filter_requests = node.filter_requests.clone();
        let script = block.txdata[0].output[0].script_pubkey.clone();
        let manager = FiltersMan::new(store, node, chain);
        let handle = manager.get_handle();
        let task = tokio::spawn(manager.main_loop());

        assert!(matches!(
            handle
                .rescan(RescanRequest::new(vec![script.clone()]))
                .await,
            Err(FilterManError::FiltersNotSynced {
                filters: Some(0),
                end: 1
            })
        ));
        assert_eq!(filter_requests.load(Ordering::Relaxed), 0);

        // The part that is covered can still be scanned.
        assert!(
            handle
                .rescan(RescanRequest::new(vec![script]).with_range(None, Some(0)))
                .await
                .is_ok()
        );

        task.abort();
    }

    #[tokio::test]
    async fn rejects_filter_that_does_not_match_header() {
        let (_file, mut store, chain, mut node, _block, _filter) = setup();
        let block_hash = chain.get_block_hash(0).unwrap();
        store
            .update_filter_header(0, block_hash, FilterHeader::all_zeros())
            .unwrap();
        Arc::make_mut(&mut node.filters).insert(block_hash, BlockFilter::new(&[1, 2, 3]));
        let manager = FiltersMan::new(store, node, chain);
        let handle = manager.get_handle();
        let task = tokio::spawn(manager.main_loop());

        assert!(matches!(
            handle.get_filter(0).await,
            Err(FilterManError::InvalidFilter(0))
        ));

        task.abort();
    }

    #[tokio::test]
    async fn reports_mock_node_filter_failure() {
        let (_file, store, chain, mut node, _block, _filter) = setup();
        Arc::make_mut(&mut node.filters).clear();
        let filter_requests = node.filter_requests.clone();
        let manager = FiltersMan::new(store, node, chain);
        let handle = manager.get_handle();
        let task = tokio::spawn(manager.main_loop());

        assert!(matches!(
            handle.get_filter(0).await,
            Err(FilterManError::Node(_))
        ));
        assert_eq!(filter_requests.load(Ordering::Relaxed), 1);

        task.abort();
    }

    #[tokio::test]
    async fn retries_missing_blocks_during_rescan() {
        let (_file, store, chain, mut node, block, _filter) = setup();
        Arc::make_mut(&mut node.blocks).clear();
        let block_requests = node.block_requests.clone();
        let manager = FiltersMan::new(store, node, chain);
        let handle = manager.get_handle();
        let task = tokio::spawn(manager.main_loop());
        let script = block.txdata[0].output[0].script_pubkey.clone();
        let ticket = handle
            .rescan(RescanRequest::new(vec![script]))
            .await
            .unwrap();

        tokio::time::timeout(Duration::from_secs(2), async {
            while block_requests.load(Ordering::Relaxed) < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        assert!(matches!(
            handle.get_info(ticket).await,
            Ok(RescanStatus::Started | RescanStatus::Waiting)
        ));
        assert!(block_requests.load(Ordering::Relaxed) >= 2);

        task.abort();
    }

    #[tokio::test]
    async fn rejects_invalid_rescans_before_calling_mock_node() {
        let (_file, store, chain, node, _block, _filter) = setup();
        let filter_requests = node.filter_requests.clone();
        let block_requests = node.block_requests.clone();
        let manager = FiltersMan::new(store, node, chain);
        let handle = manager.get_handle();
        let task = tokio::spawn(manager.main_loop());

        assert!(matches!(
            handle.rescan(RescanRequest::new(Vec::new())).await,
            Err(FilterManError::EmptyRescan)
        ));
        assert!(matches!(
            handle
                .rescan(
                    RescanRequest::new(vec![ScriptBuf::new()])
                        .with_max_blocks_per_page(MAX_RESCAN_PAGE_SIZE + 1)
                )
                .await,
            Err(FilterManError::InvalidPageSize(_))
        ));
        assert!(matches!(
            handle
                .rescan(RescanRequest::new(vec![ScriptBuf::new()]).with_range(Some(1), Some(1)))
                .await,
            Err(FilterManError::InvalidRescanRange { .. })
        ));
        assert_eq!(filter_requests.load(Ordering::Relaxed), 0);
        assert_eq!(block_requests.load(Ordering::Relaxed), 0);

        task.abort();
    }
    #[tokio::test]
    async fn connected_block_builds_and_caches_filter() {
        let file = NamedTempFile::new().unwrap();
        let store = FlatFilterStore::new(file.path()).unwrap();
        let block = genesis_block(Network::Regtest);
        let block_hash = block.block_hash();
        let chain = MockChain {
            hashes: Arc::new(vec![block_hash]),
        };
        let node = MockNode::new(HashMap::new(), HashMap::new());
        let mut manager = FiltersMan::new(store, node, chain);

        manager
            .process_connected_block(ConnectedBlock {
                block: block.clone(),
                height: 0,
                spent_utxos: HashMap::new(),
            })
            .await
            .unwrap();

        let expected = BlockFilter::new_script_filter(&block, |outpoint| {
            Err::<ScriptBuf, _>(bitcoin::bip158::Error::UtxoMissing(*outpoint))
        })
        .unwrap();
        let mut store = manager.store.lock().unwrap();
        assert_eq!(store.get_filter(0).unwrap(), Some(expected.clone()));
        assert_eq!(store.get_block_hash(0).unwrap(), block_hash);
        assert_eq!(
            store.get_filter_header(0).unwrap(),
            expected.filter_header(&FilterHeader::all_zeros())
        );
    }

    /// A chain whose tip the test can move while a rescan runs.
    #[derive(Clone)]
    struct GrowingChain {
        hashes: Arc<Mutex<Vec<BlockHash>>>,
    }

    impl FilterChain for GrowingChain {
        type Error = MockError;

        fn get_height(&self) -> Result<u32, Self::Error> {
            Ok(self.hashes.lock().unwrap().len() as u32 - 1)
        }

        fn get_block_hash(&self, height: u32) -> Result<BlockHash, Self::Error> {
            self.hashes
                .lock()
                .unwrap()
                .get(height as usize)
                .copied()
                .ok_or(MockError("unknown height"))
        }
    }

    #[tokio::test]
    async fn rescan_without_an_end_catches_up_with_blocks_connected_meanwhile() {
        let (_file, store, first_chain, mut node, block, _filter) = setup();
        let script = block.txdata[0].output[0].script_pubkey.clone();
        // A child of the stored block, paying to the same script.
        let mut second_block = block.clone();
        second_block.header.prev_blockhash = block.block_hash();
        let second_hash = second_block.block_hash();
        let second_filter = BlockFilter::new_script_filter(&second_block, |outpoint| {
            Err::<ScriptBuf, _>(bitcoin::bip158::Error::UtxoMissing(*outpoint))
        })
        .unwrap();
        Arc::make_mut(&mut node.blocks).insert(second_hash, second_block.clone());
        Arc::make_mut(&mut node.filters).insert(second_hash, second_filter);

        // The rescan starts with the tip at height 0. Its first request fails, which holds it
        // for a second: enough for the second block to connect.
        node.filter_failures.store(1, Ordering::Relaxed);
        let chain = GrowingChain {
            hashes: Arc::new(Mutex::new(vec![first_chain.hashes[0]])),
        };
        let manager = FiltersMan::new(store, node, chain.clone());
        let handle = manager.get_handle();
        let new_blocks = manager.block_consumer();
        let task = tokio::spawn(manager.main_loop());

        let ticket = handle
            .rescan(RescanRequest::new(vec![script.clone()]))
            .await
            .unwrap();
        // The second block connects: the chain moves and the manager is told, as in production.
        chain.hashes.lock().unwrap().push(second_hash);
        new_blocks.on_block(&second_block, 1, Some(&HashMap::new()));

        let (matched, progress) = tokio::time::timeout(Duration::from_secs(10), async {
            let mut matched = Vec::new();
            loop {
                matched.extend(handle.get_blocks(ticket).await.unwrap());
                let progress = handle.get_progress(ticket).await.unwrap();
                if handle.get_info(ticket).await.unwrap() == RescanStatus::Finished {
                    break (matched, progress);
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();

        // Delivered in chain order, the late block after the historical one.
        assert_eq!(matched.len(), 2);
        assert_eq!(matched[1], second_block);
        assert_eq!(progress.end_height, 1);

        // A rescan that names its end stays within it.
        let ticket = handle
            .rescan(RescanRequest::new(vec![script]).with_range(None, Some(0)))
            .await
            .unwrap();
        assert_eq!(drain_rescan(&handle, ticket).await.0.len(), 1);

        task.abort();
    }

    #[tokio::test]
    async fn finished_and_cancelled_rescans_are_forgotten() {
        let (_file, store, chain, node, second_block) = setup_two_blocks();
        let script = second_block.txdata[0].output[0].script_pubkey.clone();
        let manager = FiltersMan::new(store, node, chain);
        let handle = manager.get_handle();
        let task = tokio::spawn(manager.main_loop());

        let ticket = handle
            .rescan(RescanRequest::new(vec![script.clone()]))
            .await
            .unwrap();
        drain_rescan(&handle, ticket).await;
        assert!(matches!(
            handle.get_info(ticket).await,
            Err(FilterManError::RescanNotFound(_))
        ));

        // Two matches but a one-block page nobody consumes: the task would wait forever.
        let ticket = handle
            .rescan(RescanRequest::new(vec![script]).with_max_blocks_per_page(1))
            .await
            .unwrap();
        handle.cancel_rescan(ticket).await;
        assert!(matches!(
            handle.get_info(ticket).await,
            Err(FilterManError::RescanNotFound(_))
        ));

        task.abort();
    }

    #[tokio::test]
    async fn rescan_task_that_dies_is_a_failure_and_idle_rescans_are_pruned() {
        let (_file, store, chain, node, _block, _filter) = setup();
        let mut manager = FiltersMan::new(store, node, chain);
        let state = |outcome, last_polled| {
            let (_block_sender, blocks) = mpsc::channel(1);
            RescanState {
                blocks,
                outcome,
                result: None,
                last_polled,
                page_size: 1,
                first_status: true,
                start: 0,
                end: Arc::new(AtomicU32::new(0)),
                scanned: Arc::new(AtomicU32::new(0)),
            }
        };

        // Both senders dropped without an outcome, as after a panic. Not a finished rescan.
        let (outcome_sender, outcome) = oneshot::channel();
        drop(outcome_sender);
        manager
            .rescans
            .insert(RescanTicket(7), state(outcome, Instant::now()));
        assert!(matches!(
            manager.rescan_status(RescanTicket(7)),
            Err(FilterManError::RescanFailed(_))
        ));
        assert!(manager.rescans.is_empty());

        let (_live_sender, live) = oneshot::channel();
        let (_idle_sender, idle) = oneshot::channel();
        let long_ago = Instant::now() - RESCAN_IDLE_TIMEOUT - Duration::from_secs(1);
        manager
            .rescans
            .insert(RescanTicket(8), state(live, Instant::now()));
        manager
            .rescans
            .insert(RescanTicket(9), state(idle, long_ago));
        manager.prune_abandoned_rescans();
        assert!(manager.rescans.contains_key(&RescanTicket(8)));
        assert!(!manager.rescans.contains_key(&RescanTicket(9)));
    }

    #[tokio::test]
    async fn refuses_filters_while_the_store_describes_another_branch() {
        let (_file, store, mut chain, node, block, _filter) = setup();
        let mut reorged = block.clone();
        reorged.header.nonce = reorged.header.nonce.wrapping_add(1);
        Arc::make_mut(&mut chain.hashes)[0] = reorged.block_hash();
        let filter_requests = node.filter_requests.clone();
        let manager = FiltersMan::new(store, node, chain);
        let handle = manager.get_handle();
        let task = tokio::spawn(manager.main_loop());

        assert!(matches!(
            handle.get_filter(0).await,
            Err(FilterManError::StaleFilterHeaders(0))
        ));
        assert_eq!(filter_requests.load(Ordering::Relaxed), 0);

        task.abort();
    }

    #[tokio::test]
    async fn connected_block_is_not_chained_onto_another_branch() {
        let (_file, store, mut chain, node, block, _filter) = setup();
        // Height 1 builds on a block at height 0 that isn't the one we stored a header for.
        let mut other_parent = block.clone();
        other_parent.header.nonce = other_parent.header.nonce.wrapping_add(1);
        let mut child = block.clone();
        child.header.prev_blockhash = other_parent.block_hash();
        Arc::make_mut(&mut chain.hashes).push(child.block_hash());
        let mut manager = FiltersMan::new(store, node, chain);

        let result = manager
            .process_connected_block(ConnectedBlock {
                block: child,
                height: 1,
                spent_utxos: HashMap::new(),
            })
            .await;

        assert!(result.is_err());
        assert_eq!(manager.store.lock().unwrap().get_height().unwrap(), Some(0));
    }

    #[test]
    fn checkpoint_mismatch_drops_the_interval_and_the_checkpoints() {
        let file = NamedTempFile::new().unwrap();
        let mut store = FlatFilterStore::new(file.path()).unwrap();
        for height in 0..=CHECKPOINT_INTERVAL + 5 {
            store
                .put_filter_header(mock_block_hash(height), FilterHeader::all_zeros())
                .unwrap();
        }
        store.flush().unwrap();
        let chain = MockChain {
            hashes: Arc::new((0..=CHECKPOINT_INTERVAL + 5).map(mock_block_hash).collect()),
        };
        let node = MockNode::new(HashMap::new(), HashMap::new());
        let mut manager = FiltersMan::new(store, node, chain);
        let lying = vec![FilterHeader::from_byte_array([1; 32])];

        // First strike: one message isn't worth the whole chain. Only the checkpoints go, so
        // the next synchronization asks for them again.
        manager.checkpoints = lying.clone();
        manager.checkpoints_stop_hash = Some(mock_block_hash(7));
        assert!(matches!(
            manager.verify_stored_checkpoints(),
            Err(FilterManError::InvalidHeaders(_))
        ));
        assert!(manager.checkpoints.is_empty());
        // Whoever served those checkpoints gets reported, whichever side turns out to be wrong.
        assert_eq!(
            manager.unreported,
            vec![Contradicted::Checkpoints(mock_block_hash(7))]
        );
        assert_eq!(
            manager.store.lock().unwrap().get_height().unwrap(),
            Some(CHECKPOINT_INTERVAL + 5)
        );

        // Second strike at the same height: nothing below the first checkpoint can be trusted,
        // so everything goes.
        manager.checkpoints = lying;
        assert!(manager.verify_stored_checkpoints().is_err());
        assert_eq!(manager.store.lock().unwrap().get_height().unwrap(), None);
        assert!(manager.checkpoints.is_empty());
        assert_eq!(manager.get_handle().get_height(), None);
        assert!(manager.verify_stored_checkpoints().is_ok());
    }

    #[test]
    fn filters_arriving_after_the_store_was_truncated_are_retryable() {
        let (_file, mut store, _chain, _node, block, filter) = setup();
        store.truncate(None).unwrap();

        let result = FiltersMan::<FlatFilterStore, MockChain, MockNode>::accept_filters(
            &Mutex::new(store),
            0,
            &[block.block_hash()],
            vec![filter],
        );

        // Not `Store(NotFound)`, which would end the rescan, nor `InvalidFilter`, which would
        // blame the peer.
        assert!(matches!(result, Err(FilterManError::StaleFilterHeaders(0))));
    }

    /// `block` and a child of it, with the `cfheaders` a peer would serve for `heights`.
    fn linked_pair(block: &Block, first_height: u32) -> (Block, BlockFilter, CFHeaders) {
        let mut child = block.clone();
        child.header.prev_blockhash = block.block_hash();
        let filter_of = |block: &Block| {
            BlockFilter::new_script_filter(block, |outpoint| {
                Err::<ScriptBuf, _>(bitcoin::bip158::Error::UtxoMissing(*outpoint))
            })
            .unwrap()
        };
        let parent_filter = filter_of(block);
        let child_filter = filter_of(&child);
        let parent_header = parent_filter.filter_header(&FilterHeader::all_zeros());

        let response = if first_height == 0 {
            CFHeaders {
                filter_type: BASIC_FILTER_TYPE,
                stop_hash: child.block_hash(),
                previous_filter_header: FilterHeader::all_zeros(),
                filter_hashes: vec![
                    bitcoin::FilterHash::hash(&parent_filter.content),
                    bitcoin::FilterHash::hash(&child_filter.content),
                ],
            }
        } else {
            CFHeaders {
                filter_type: BASIC_FILTER_TYPE,
                stop_hash: child.block_hash(),
                previous_filter_header: parent_header,
                filter_hashes: vec![bitcoin::FilterHash::hash(&child_filter.content)],
            }
        };
        (child, child_filter, response)
    }

    #[tokio::test]
    async fn connected_block_whose_parent_is_still_missing_after_a_sync_is_refused() {
        let (_file, store, mut chain, mut node, block, _filter) = setup();
        let (child, _, response) = linked_pair(&block, 1);
        // The chain and the peers agree on `child` at height 1, so the sync succeeds. The block
        // we are handed claims another parent than the one stored at height 0.
        Arc::make_mut(&mut chain.hashes).push(child.block_hash());
        Arc::make_mut(&mut node.header_responses).insert((1, child.block_hash()), response);
        let mut orphan = child.clone();
        orphan.header.prev_blockhash = child.block_hash();
        let mut manager = FiltersMan::new(store, node, chain);

        let result = manager
            .process_connected_block(ConnectedBlock {
                block: orphan,
                height: 1,
                spent_utxos: HashMap::new(),
            })
            .await;

        assert!(matches!(result, Err(FilterManError::InvalidHeaders(_))));
    }

    #[tokio::test]
    async fn connected_block_is_accepted_once_a_sync_repaired_its_parent() {
        let (file, _store, mut chain, mut node, block, _filter) = setup();
        let (child, child_filter, response) = linked_pair(&block, 0);
        Arc::make_mut(&mut chain.hashes).push(child.block_hash());
        Arc::make_mut(&mut node.header_responses).insert((0, child.block_hash()), response);
        // The store describes a branch that was reorged out: another block at height 0.
        drop(file);
        let file = NamedTempFile::new().unwrap();
        let mut store = FlatFilterStore::new(file.path()).unwrap();
        store
            .put_filter_header(mock_block_hash(99), FilterHeader::all_zeros())
            .unwrap();
        store.flush().unwrap();
        let mut manager = FiltersMan::new(store, node, chain);

        manager
            .process_connected_block(ConnectedBlock {
                block: child.clone(),
                height: 1,
                spent_utxos: HashMap::new(),
            })
            .await
            .unwrap();

        let mut store = manager.store.lock().unwrap();
        assert_eq!(store.get_block_hash(0).unwrap(), block.block_hash());
        assert_eq!(store.get_block_hash(1).unwrap(), child.block_hash());
        assert_eq!(store.get_filter(1).unwrap(), Some(child_filter));
    }

    #[tokio::test]
    async fn connected_blocks_do_not_retry_a_sync_that_just_failed() {
        let (_file, store, mut chain, node, block, _filter) = setup();
        // The chain is well ahead of the store and the node can't serve filter headers, as
        // when no peer offers compact filters.
        for height in 1..=5 {
            Arc::make_mut(&mut chain.hashes).push(mock_block_hash(height));
        }
        let header_requests = node.header_requests.clone();
        let mut manager = FiltersMan::new(store, node, chain);
        let connected = || ConnectedBlock {
            block: block.clone(),
            height: 4,
            spent_utxos: HashMap::new(),
        };

        assert!(manager.process_connected_block(connected()).await.is_err());
        assert_eq!(header_requests.load(Ordering::Relaxed), 1);

        // IBD connects blocks by the dozen per second; they must not each start a sync.
        for _ in 0..50 {
            manager.process_connected_block(connected()).await.unwrap();
        }
        assert_eq!(header_requests.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn local_filter_replaces_a_stored_header_it_contradicts() {
        let (_file, mut store, mut chain, node, block, filter) = setup();
        let (child, child_filter, _) = linked_pair(&block, 1);
        Arc::make_mut(&mut chain.hashes).push(child.block_hash());
        // A peer gave us a wrong header for `child`.
        store
            .put_filter_header(child.block_hash(), FilterHeader::from_byte_array([7; 32]))
            .unwrap();
        store.flush().unwrap();
        let mut manager = FiltersMan::new(store, node, chain);
        manager.checkpoints = vec![FilterHeader::all_zeros()];

        manager
            .process_connected_block(ConnectedBlock {
                block: child.clone(),
                height: 1,
                spent_utxos: HashMap::new(),
            })
            .await
            .unwrap();

        let parent_header = filter.filter_header(&FilterHeader::all_zeros());
        assert_eq!(
            manager.store.lock().unwrap().get_filter_header(1).unwrap(),
            child_filter.filter_header(&parent_header)
        );
        assert!(manager.checkpoints.is_empty());
    }

    #[test]
    fn applying_headers_persists_best_chain_mapping() {
        let file = NamedTempFile::new().unwrap();
        let store = FlatFilterStore::new(file.path()).unwrap();
        let block = genesis_block(Network::Regtest);
        let block_hash = block.block_hash();
        let filter = BlockFilter::new(&[1, 2, 3]);
        let filter_hash = bitcoin::FilterHash::hash(&filter.content);
        let chain = MockChain {
            hashes: Arc::new(vec![block_hash]),
        };
        let node = MockNode::new(HashMap::new(), HashMap::new());
        let mut manager = FiltersMan::new(store, node, chain);

        manager
            .apply_headers(
                0,
                0,
                block_hash,
                CFHeaders {
                    filter_type: BASIC_FILTER_TYPE,
                    stop_hash: block_hash,
                    previous_filter_header: FilterHeader::all_zeros(),
                    filter_hashes: vec![filter_hash],
                },
            )
            .unwrap();

        let mut store = manager.store.lock().unwrap();
        assert_eq!(store.get_block_hash(0).unwrap(), block_hash);
        assert_eq!(
            store.get_filter_header(0).unwrap(),
            filter.filter_header(&FilterHeader::all_zeros())
        );
    }

    #[tokio::test]
    async fn sync_requests_headers_and_checkpoints_from_mock_node() {
        let file = NamedTempFile::new().unwrap();
        let store = FlatFilterStore::new(file.path()).unwrap();
        let hashes = (0_u32..=CHECKPOINT_INTERVAL)
            .map(mock_block_hash)
            .collect::<Vec<_>>();
        let filter_hashes = (0_u32..=CHECKPOINT_INTERVAL)
            .map(|height| {
                let mut bytes = [1_u8; 32];
                bytes[..4].copy_from_slice(&height.to_le_bytes());
                bitcoin::FilterHash::from_byte_array(bytes)
            })
            .collect::<Vec<_>>();
        let mut previous_header = FilterHeader::all_zeros();
        let filter_headers = filter_hashes
            .iter()
            .map(|filter_hash| {
                previous_header = filter_hash.filter_header(&previous_header);
                previous_header
            })
            .collect::<Vec<_>>();
        let checkpoint = filter_headers[CHECKPOINT_INTERVAL as usize];
        let stop_999 = hashes[(CHECKPOINT_INTERVAL - 1) as usize];
        let stop_1000 = hashes[CHECKPOINT_INTERVAL as usize];
        let chain = MockChain {
            hashes: Arc::new(hashes),
        };
        let mut node = MockNode::new(HashMap::new(), HashMap::new());
        node.header_responses = Arc::new(HashMap::from([
            (
                (0, stop_999),
                CFHeaders {
                    filter_type: BASIC_FILTER_TYPE,
                    stop_hash: stop_999,
                    previous_filter_header: FilterHeader::all_zeros(),
                    filter_hashes: filter_hashes[..CHECKPOINT_INTERVAL as usize].to_vec(),
                },
            ),
            (
                (CHECKPOINT_INTERVAL, stop_1000),
                CFHeaders {
                    filter_type: BASIC_FILTER_TYPE,
                    stop_hash: stop_1000,
                    previous_filter_header: filter_headers[(CHECKPOINT_INTERVAL - 1) as usize],
                    filter_hashes: vec![filter_hashes[CHECKPOINT_INTERVAL as usize]],
                },
            ),
        ]));
        node.checkpoint_responses = Arc::new(HashMap::from([(
            stop_1000,
            CFCheckpt {
                filter_type: BASIC_FILTER_TYPE,
                stop_hash: stop_1000,
                filter_headers: vec![checkpoint],
            },
        )]));
        let header_requests = node.header_requests.clone();
        let checkpoint_requests = node.checkpoint_requests.clone();
        let mut manager = FiltersMan::new(store, node, chain);

        manager.sync().await.unwrap();

        assert_eq!(header_requests.load(Ordering::Relaxed), 2);
        assert_eq!(checkpoint_requests.load(Ordering::Relaxed), 1);
        let mut store = manager.store.lock().unwrap();
        assert_eq!(store.get_height().unwrap(), Some(CHECKPOINT_INTERVAL));
        assert_eq!(
            store.get_filter_header(CHECKPOINT_INTERVAL).unwrap(),
            checkpoint
        );
        assert_eq!(
            store.get_block_hash(CHECKPOINT_INTERVAL).unwrap(),
            stop_1000
        );
    }
    #[tokio::test]
    async fn rejects_missing_filter_header_checkpoint() {
        let file = NamedTempFile::new().unwrap();
        let store = FlatFilterStore::new(file.path()).unwrap();
        let hashes = (0_u32..=CHECKPOINT_INTERVAL)
            .map(|height| {
                let mut bytes = [0_u8; 32];
                bytes[..4].copy_from_slice(&height.to_le_bytes());
                BlockHash::from_byte_array(bytes)
            })
            .collect::<Vec<_>>();
        let stop_hash = hashes[CHECKPOINT_INTERVAL as usize];
        let chain = MockChain {
            hashes: Arc::new(hashes),
        };
        let mut node = MockNode::new(HashMap::new(), HashMap::new());
        node.checkpoint_responses = Arc::new(HashMap::from([(
            stop_hash,
            CFCheckpt {
                filter_type: BASIC_FILTER_TYPE,
                stop_hash,
                filter_headers: Vec::new(),
            },
        )]));
        let mut manager = FiltersMan::new(store, node, chain);

        assert!(matches!(
            manager.sync_checkpoints(CHECKPOINT_INTERVAL).await,
            Err(FilterManError::InvalidHeaders(_))
        ));
    }
}
