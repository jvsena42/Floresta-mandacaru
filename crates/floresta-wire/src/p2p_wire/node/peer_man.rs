// SPDX-License-Identifier: MIT OR Apache-2.0

use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use bitcoin::BlockHash;
use bitcoin::Transaction;
use bitcoin::p2p::ServiceFlags;
use bitcoin::p2p::address::AddrV2Message;
use bitcoin::p2p::message_blockdata::Inventory;
use floresta_chain::ChainBackend;
use floresta_common::service_flags;
use floresta_common::service_flags_strings;
use floresta_common::try_and_log;
use rand::distr::Distribution;
use rand::distr::weighted::WeightedIndex;
use rand::prelude::IteratorRandom;
use rand::seq::IndexedRandom;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::warn;

use super::ConnectionKind;
use super::InflightRequests;
use super::LocalPeerView;
use super::NodeRequest;
use super::PeerStatus;
use super::UtreexoNode;
use crate::address_man::AddressMan;
use crate::address_man::AddressState;
use crate::address_man::LocalAddress;
use crate::bitcoin_socket_addr::BitcoinSocketAddr;
use crate::block_proof::Bitmap;
use crate::node::running_ctx::RunningNode;
use crate::node_context::NodeContext;
use crate::node_context::PeerId;
use crate::node_handle::FilterDataKind;
use crate::node_handle::NodeResponse;
use crate::node_handle::UserRequest;
use crate::node_interface::PeerInfo;
use crate::p2p_wire::error::WireError;
use crate::p2p_wire::peer::PeerMessages;
use crate::p2p_wire::peer::Version;

#[derive(Debug, Clone)]
/// A simple struct of added peers, used to track the ones we added manually by `addnode <ip:port> add` command.
pub struct AddedPeerInfo {
    /// The address of the peer
    pub(crate) address: BitcoinSocketAddr,

    /// Whether we should allow V1 fallback for this connection
    pub(crate) v1_fallback: bool,

    /// Connection attempts since the last session that lasted; each one waits longer
    pub(crate) failed_attempts: u32,

    /// Don't dial again before this instant
    pub(crate) retry_after: Option<Instant>,

    /// When we last dialed this peer, to measure how long the session lasted
    pub(crate) dialed_at: Option<Instant>,
}

impl AddedPeerInfo {
    /// How long a session has to last for the peer to count as reachable again
    pub(crate) const STABLE_SESSION: Duration = Duration::from_secs(60);
    const FIRST_RETRY: Duration = Duration::from_secs(10);
    const MAX_RETRY: Duration = Duration::from_secs(10 * 60);

    pub(crate) fn new(address: BitcoinSocketAddr, v1_fallback: bool) -> Self {
        Self {
            address,
            v1_fallback,
            failed_attempts: 0,
            retry_after: None,
            dialed_at: None,
        }
    }

    /// Whether it is time to dial this peer again
    pub(crate) fn due(&self, now: Instant) -> bool {
        self.retry_after
            .is_none_or(|retry_after| now >= retry_after)
    }

    /// Records a dial. A peer that drops us right after the handshake would otherwise be
    /// redialed on every maintenance tick, all day, which on a phone is battery and data.
    /// The first redial after a session ends is not delayed, so a single drop (e.g. a peer
    /// we disconnected for flooding us) is recovered as quickly as before.
    pub(crate) fn note_attempt(&mut self, now: Instant) {
        let wait = match self.failed_attempts {
            0 => Duration::ZERO,
            failed => Self::FIRST_RETRY
                .saturating_mul(1 << (failed - 1).min(6))
                .min(Self::MAX_RETRY),
        };
        self.retry_after = Some(now + wait);
        self.dialed_at = Some(now);
        self.failed_attempts = self.failed_attempts.saturating_add(1);
    }

    /// Records the end of a session. One that lasted means the peer is reachable, so the next
    /// drop is dialed right away again.
    pub(crate) fn note_session_end(&mut self, now: Instant) {
        let lasted = self.dialed_at.is_some_and(|dialed_at| {
            now.saturating_duration_since(dialed_at) >= Self::STABLE_SESSION
        });
        if lasted {
            self.failed_attempts = 0;
            self.retry_after = None;
        }
    }
}

impl<T, Chain> UtreexoNode<Chain, T>
where
    T: 'static + Default + NodeContext,
    Chain: ChainBackend + 'static,
    WireError: From<Chain::Error>,
{
    // === SENDING TO PEERS ===

    /// How far behind a requested height a peer's last known height may be for it to still be
    /// asked first: about a day of blocks, so a peer that had the tip when it connected keeps
    /// being preferred over one that was already far behind.
    const RECENT_HEIGHT_MARGIN: u32 = 144;

    /// Picks a `Ready` peer supporting `service`, biased toward lower message latency.
    ///
    /// Each candidate weight is computed as `lowest_time / time_i`. For instance, if we have two
    /// candidates with latencies of 50ms and 100ms, weights are 1.0 and 0.5 respectively, and the
    /// probability of being chosen is 2/3 and 1/3.
    ///
    /// With `min_height`, peers known to have reached that height come first; failing that,
    /// peers that were within [`Self::RECENT_HEIGHT_MARGIN`] blocks of it when we last heard
    /// (they had the tip at handshake and just haven't told us about newer blocks); the rest
    /// only when nobody else is left. A bridge a thousand blocks behind the tip cannot serve a
    /// proof for a block it has not seen, and the request would only time out on it.
    fn choose_peer_by_latency(
        &self,
        service: ServiceFlags,
        min_height: Option<u32>,
    ) -> Option<(&PeerId, &LocalPeerView)> {
        // Epsilon is a small positive floor for `f64`. If by any chance a peer has extremely low
        // message latency, we clamp it to `EPS` so `lowest_time / time_i` stays finite and stable.
        const EPS: f64 = 1e-9;

        let is_ready =
            |peer: &LocalPeerView| peer.services.has(service) && peer.state == PeerStatus::Ready;
        let ready_peers = |at_least: u32| -> Vec<(&PeerId, &LocalPeerView)> {
            self.peers
                .iter()
                .filter(|(_, peer)| is_ready(peer) && peer.height >= at_least)
                .collect()
        };

        let tiers = match min_height {
            Some(height) => vec![height, height.saturating_sub(Self::RECENT_HEIGHT_MARGIN), 0],
            None => vec![0],
        };
        let ready_peers = tiers
            .into_iter()
            .map(ready_peers)
            .find(|peers| !peers.is_empty())
            .unwrap_or_default();

        let candidates: Vec<(&PeerId, &LocalPeerView, f64)> = ready_peers
            .into_iter()
            .filter_map(|(id, peer)| {
                // Get the average message latency from each peer
                let Some(t) = peer.message_times.value() else {
                    error!("Peer {peer:?} has no message times");
                    return None;
                };
                Some((id, peer, t.max(EPS)))
            })
            .collect();

        // Fastest observed time among candidates. Returns `None` if no candidate is found.
        let lowest_time = candidates.iter().map(|(_, _, t)| *t).reduce(f64::min)?;

        let weights: Vec<f64> = candidates
            .iter()
            .map(|(_, _, time)| lowest_time / time)
            .collect();

        let dist = WeightedIndex::new(&weights).ok()?;
        let idx = dist.sample(&mut rand::rng());

        let (id, peer, _) = candidates[idx];
        Some((id, peer))
    }

    /// Whether the node was configured with a fixed peer list (via `--connect`).
    ///
    /// When this is true, we connect *only* to those peers and skip the usual
    /// peer-discovery paths (address manager, feelers, hardcoded fallback).
    pub(crate) fn has_fixed_peers(&self) -> bool {
        !self.fixed_peers.is_empty()
    }

    /// Returns how many connected peers we have.
    ///
    /// This function will only count peers that completed handshake and are ready
    /// to be used.
    pub(crate) fn connected_peers(&self) -> usize {
        self.peers
            .values()
            .filter(|p| p.state == PeerStatus::Ready && p.kind.is_long_lived())
            .count()
    }

    /// Sends a request to an initialized peer that supports `required_service`, chosen via a
    /// latency-weighted distribution (lower latency => more likely).
    ///
    /// Returns an error if no ready peer has `required_service` or if sending the request failed.
    pub(crate) fn send_to_fast_peer(
        &self,
        request: NodeRequest,
        required_service: ServiceFlags,
    ) -> Result<PeerId, WireError> {
        self.send_to_fast_peer_at_height(request, required_service, None)
    }

    /// Like [`Self::send_to_fast_peer`], preferring peers known to have reached `height`.
    pub(crate) fn send_to_fast_peer_at_height(
        &self,
        request: NodeRequest,
        required_service: ServiceFlags,
        height: Option<u32>,
    ) -> Result<PeerId, WireError> {
        let (peer_id, peer) = self
            .choose_peer_by_latency(required_service, height)
            .ok_or(WireError::NoPeersAvailable)?;

        peer.channel.send(request)?;

        Ok(*peer_id)
    }

    /// Records that `peer` has a block at `height`: it announced or served one, so it can be
    /// asked for anything up to there.
    pub(crate) fn note_peer_height(&mut self, peer: PeerId, height: u32) {
        if let Some(peer_data) = self.peers.get_mut(&peer) {
            peer_data.height = peer_data.height.max(height);
        }
    }

    /// The height of `hash` in our chain, if we know it.
    pub(crate) fn known_height(&self, hash: &BlockHash) -> Option<u32> {
        self.chain.get_block_height(hash).ok().flatten()
    }

    #[inline]
    pub(crate) fn send_to_random_peer(
        &mut self,
        req: NodeRequest,
        required_service: ServiceFlags,
    ) -> Result<u32, WireError> {
        if self.peers.is_empty() {
            return Err(WireError::NoPeersAvailable);
        }

        let peers = match required_service {
            ServiceFlags::NONE => &self.peer_ids,
            _ => self
                .peer_by_service
                .get(&required_service)
                .ok_or(WireError::NoPeersAvailable)?,
        };

        if peers.is_empty() {
            return Err(WireError::NoPeersAvailable);
        }

        let peer = peers
            .choose(&mut rand::rng())
            .expect("infallible: we checked that peers isn't empty");

        self.peers
            .get(peer)
            .ok_or(WireError::NoPeersAvailable)?
            .channel
            .send(req)
            .map_err(WireError::ChannelSend)?;

        Ok(*peer)
    }

    #[inline]
    pub(crate) fn send_to_random_peer_with_predicate(
        &mut self,
        req: NodeRequest,
        required_service: ServiceFlags,
        predicate: impl Fn(&LocalPeerView) -> bool,
    ) -> Result<u32, WireError> {
        if self.peers.is_empty() {
            return Err(WireError::NoPeersAvailable);
        }

        let peers = match required_service {
            ServiceFlags::NONE => &self.peer_ids,
            _ => self
                .peer_by_service
                .get(&required_service)
                .ok_or(WireError::NoPeersAvailable)?,
        };

        let (peer_id, peer) = peers
            .iter()
            .filter_map(|peer_id| self.peers.get(peer_id).map(|peer| (peer_id, peer)))
            .filter(|(_, peer)| predicate(peer))
            .choose(&mut rand::rng())
            .ok_or(WireError::NoPeersAvailable)?;

        peer.channel.send(req).map_err(WireError::ChannelSend)?;

        Ok(*peer_id)
    }

    pub(crate) fn send_to_peer(&self, peer_id: u32, req: NodeRequest) -> Result<(), WireError> {
        if let Some(peer) = &self.peers.get(&peer_id) {
            if peer.state == PeerStatus::Awaiting {
                return Ok(());
            }
            peer.channel.send(req)?;
        }
        Ok(())
    }

    /// Sends the same request to all connected peers
    ///
    /// This function is best-effort, meaning that some peers may not receive the request if they
    /// are disconnected or if there is an error sending the request. We intentionally won't
    /// propagate the error to the caller, as this would request an early return from the function,
    /// which would prevent us from sending the request to the peers the comes after the first
    /// erroing one.
    pub(crate) fn broadcast_to_peers(&mut self, request: NodeRequest) {
        for peer in self.peers.values() {
            if peer.state != PeerStatus::Ready {
                continue;
            }

            if request.is_broadcast_transaction() && !peer.kind.is_full_relay() {
                continue;
            }

            if let Err(err) = peer.channel.send(request.clone()) {
                warn!("Failed to send request to peer {}: {err}", peer.address);
            }
        }
    }

    pub(crate) fn ask_for_addresses(&mut self) -> Result<(), WireError> {
        self.send_to_random_peer_with_predicate(
            NodeRequest::GetAddresses,
            ServiceFlags::NONE,
            |peer| peer.state == PeerStatus::Ready && peer.kind.is_full_relay(),
        )?;

        Ok(())
    }

    // === PEER LIFECYCLE ===

    fn is_peer_good(peer: &LocalPeerView, needs: ServiceFlags) -> bool {
        if peer.state == PeerStatus::Banned {
            return false;
        }

        peer.services.has(needs)
    }

    pub(crate) fn handle_peer_ready(
        &mut self,
        peer: u32,
        mut version: Version,
    ) -> Result<(), WireError> {
        self.inflight.remove(&InflightRequests::Connect(peer));

        // Mark this peer as ready to communicate with
        self.peers.entry(peer).and_modify(|p| {
            p.state = PeerStatus::Ready;
        });

        let good_peers_count = self.connected_peers();
        if good_peers_count > T::MAX_OUTGOING_PEERS {
            // We allow utreexo, extra and manual peers to bypass our connection limits
            let is_utreexo_peer = matches!(version.kind, ConnectionKind::OutboundFullRelay(services) if services.has(service_flags::UTREEXO.into()));
            let is_manual_peer = version.kind.is_manual();
            let is_extra = version.kind == ConnectionKind::Extra;

            if !(is_utreexo_peer || is_manual_peer || is_extra) {
                debug!(
                    "Already have {} peers, treating peer {peer} as addr-fetch before disconnecting to avoid blowing up our max of {}",
                    good_peers_count,
                    T::MAX_OUTGOING_PEERS
                );

                // If a peer exceeds our max, just turn them into an addr-fetch
                // so we can receive their AddrV2 message and then disconnect.
                self.peers.entry(peer).and_modify(|p| {
                    p.kind = ConnectionKind::AddrFetch;
                });

                version.kind = ConnectionKind::AddrFetch;
            }
        }

        if version.kind == ConnectionKind::Feeler {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            self.address_man
                .update_set_service_flag(version.address_id, version.services)
                .update_set_state(version.address_id, AddressState::Tried(now));

            debug!(
                "Feeler peer {peer} completed handshake; marking address tried and disconnecting"
            );
            self.send_to_peer(peer, NodeRequest::Shutdown)?;
            return Ok(());
        }

        if version.kind == ConnectionKind::AddrFetch {
            debug!("Addr-fetch peer {peer} completed handshake; requesting addresses");
            self.send_to_peer(peer, NodeRequest::GetAddresses)?;
            self.inflight
                .insert(InflightRequests::GetAddresses, (peer, Instant::now()));

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            self.address_man
                .update_set_service_flag(version.address_id, version.services)
                .update_set_state(version.address_id, AddressState::Tried(now));

            return Ok(());
        }

        if version.kind == ConnectionKind::Extra {
            if let Some(peer_data) = self.common.peers.get_mut(&peer) {
                peer_data.services = version.services;
                peer_data.user_agent.clone_from(&version.user_agent);
                peer_data.height = version.blocks;
                peer_data.transport_protocol = version.transport_protocol;
            }

            let locator = self.chain.get_block_locator()?;
            debug!("Extra peer {peer} completed handshake; requesting headers");
            self.send_to_peer(peer, NodeRequest::GetHeaders(locator))?;

            self.inflight
                .insert(InflightRequests::Headers, (peer, Instant::now()));

            return Ok(());
        }

        if !version.kind.is_block_relay_only() {
            debug!(
                "Requesting addresses from peer {peer} kind={:?}",
                version.kind
            );
            self.send_to_peer(peer, NodeRequest::GetAddresses)?;
            self.inflight
                .insert(InflightRequests::GetAddresses, (peer, Instant::now()));
        }

        info!(
            "New peer id={} version={} blocks={} services={}",
            version.id, version.user_agent, version.blocks, version.services
        );

        if let Some(peer_data) = self.common.peers.get_mut(&peer) {
            peer_data.services = version.services;
            peer_data.address.set_services(version.services);
            peer_data.user_agent.clone_from(&version.user_agent);
            peer_data.height = version.blocks;
            peer_data.time_offset = version.time_offset;
            peer_data.transport_protocol = version.transport_protocol;

            // If this peer doesn't have basic services, we disconnect it
            if let ConnectionKind::OutboundFullRelay(needs)
            | ConnectionKind::BlockRelayOnly(needs) = version.kind
            {
                if !Self::is_peer_good(peer_data, needs) {
                    info!(
                        "Disconnecting peer {peer} for not having the required services. has={} needs={}",
                        peer_data.services, needs
                    );
                    peer_data.channel.send(NodeRequest::Shutdown)?;
                    self.address_man.update_set_state(
                        version.address_id,
                        AddressState::Tried(
                            SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_secs(),
                        ),
                    );

                    self.address_man
                        .update_set_service_flag(version.address_id, version.services);

                    return Ok(());
                }
            };

            if peer_data.services.has(service_flags::UTREEXO.into()) {
                self.common
                    .peer_by_service
                    .entry(service_flags::UTREEXO.into())
                    .or_default()
                    .push(peer);
            }

            if peer_data.services.has(ServiceFlags::COMPACT_FILTERS) {
                self.common
                    .peer_by_service
                    .entry(ServiceFlags::COMPACT_FILTERS)
                    .or_default()
                    .push(peer);
            }

            if peer_data
                .services
                .has(service_flags::UTREEXO_ARCHIVE.into())
            {
                self.common
                    .peer_by_service
                    .entry(service_flags::UTREEXO_ARCHIVE.into())
                    .or_default()
                    .push(peer);
            }

            // We can request historical blocks from this peer
            if peer_data.services.has(ServiceFlags::NETWORK) {
                self.common
                    .peer_by_service
                    .entry(ServiceFlags::NETWORK)
                    .or_default()
                    .push(peer);
            }

            self.address_man
                .update_set_state(version.address_id, AddressState::Connected)
                .update_set_service_flag(version.address_id, version.services);

            self.peer_ids.push(peer);

            if version.kind.is_block_relay_only() {
                let locator = self.chain.get_block_locator()?;
                self.send_to_peer(peer, NodeRequest::GetHeaders(locator))?;

                self.inflight
                    .insert(InflightRequests::Headers, (peer, Instant::now()));
            }
        }

        #[cfg(feature = "metrics")]
        self.update_peer_metrics();
        Ok(())
    }

    /// Handles a NOTFOUND inventory by completing any matching inflight user request with `None`.
    pub(crate) fn handle_notfound_msg(&mut self, inv: Inventory) -> Result<(), WireError> {
        match inv {
            Inventory::Error => {}

            Inventory::Block(block)
            | Inventory::WitnessBlock(block)
            | Inventory::CompactBlock(block) => {
                if let Some(request) = self
                    .inflight_user_requests
                    .remove(&UserRequest::Block(block))
                {
                    request
                        .2
                        .send(NodeResponse::Block(None))
                        .map_err(|_| WireError::ResponseSendError)?;
                }
            }

            Inventory::WitnessTransaction(tx) | Inventory::Transaction(tx) => {
                if let Some(request) = self
                    .inflight_user_requests
                    .remove(&UserRequest::MempoolTransaction(tx))
                {
                    request
                        .2
                        .send(NodeResponse::MempoolTransaction(None))
                        .map_err(|_| WireError::ResponseSendError)?;
                }
            }
            _ => {}
        }

        Ok(())
    }

    /// Handles an incoming mempool transaction by completing any matching inflight user request.
    pub(crate) fn handle_tx_msg(&mut self, tx: Transaction) -> Result<(), WireError> {
        let txid = tx.compute_txid();
        debug!("saw a mempool transaction with txid={txid}");

        if let Some(request) = self
            .inflight_user_requests
            .remove(&UserRequest::MempoolTransaction(txid))
        {
            request
                .2
                .send(NodeResponse::MempoolTransaction(Some(tx)))
                .map_err(|_| WireError::ResponseSendError)?;
        }

        Ok(())
    }

    /// Handles peer messages where behavior is common to all node contexts, returning `Some` only
    /// for peer messages that require context-specific handling.
    pub(crate) fn handle_peer_msg_common(
        &mut self,
        msg: PeerMessages,
        peer: PeerId,
    ) -> Result<Option<PeerMessages>, WireError> {
        // Ignore queued replies from removed peers, even if retrying their requests failed.
        // They must not complete requests now assigned to another peer.
        // Still handle `Disconnected` so each node context can finish its cleanup.
        if !self.peers.contains_key(&peer) && !matches!(msg, PeerMessages::Disconnected(_)) {
            return Ok(None);
        }

        match msg {
            PeerMessages::Addr(addresses) => {
                self.handle_addresses_from_peer(peer, addresses)?;
                Ok(None)
            }
            PeerMessages::NotFound(inv) => {
                self.handle_notfound_msg(inv)?;
                Ok(None)
            }
            PeerMessages::Transaction(tx) => {
                self.handle_tx_msg(tx)?;
                Ok(None)
            }
            PeerMessages::UtreexoState(_) => {
                warn!("Utreexo state received from peer {peer}, but we didn't ask");
                self.increase_banscore(peer, 5)?;
                Ok(None)
            }
            PeerMessages::CFHeaders(headers) => {
                let request = self.inflight_user_requests.iter().find_map(
                    |(request, (request_peer, _, _))| match request {
                        UserRequest::GetCFilterHeaders { stop_hash, .. }
                            if *stop_hash == headers.stop_hash && *request_peer == peer =>
                        {
                            Some(request.clone())
                        }
                        _ => None,
                    },
                );

                if let Some(request) = request {
                    if let Some((_, _, responder)) = self.inflight_user_requests.remove(&request) {
                        self.remember_filter_server(
                            FilterDataKind::Headers,
                            headers.stop_hash,
                            peer,
                        );
                        let _ = responder.send(NodeResponse::CFilterHeaders(headers));
                    }
                } else {
                    // Most likely the tail of a request that timed out: a batch is up to
                    // a hundred messages, and a slow link delivers some after the deadline.
                    // Penalizing them bans what may be our only compact-filters peer.
                    debug!("Peer {peer} sent us a cfheaders we aren't waiting for");
                }

                Ok(None)
            }
            PeerMessages::BlockFilter((block_hash, filter)) => {
                let request = self.inflight_user_requests.iter().find_map(
                    |(request, (request_peer, _, _))| match request {
                        UserRequest::GetCFilters { block_hashes, .. }
                            if *request_peer == peer
                                && self
                                    .inflight_filter_batches
                                    .get(request)
                                    .and_then(|filters| block_hashes.get(filters.len()))
                                    == Some(&block_hash) =>
                        {
                            Some(request.clone())
                        }
                        _ => None,
                    },
                );

                if let Some(request) = request {
                    self.last_filter_progress.insert(peer, Instant::now());
                    let filters = self
                        .inflight_filter_batches
                        .get_mut(&request)
                        .expect("filter batch exists for every in-flight filter request");
                    filters.push(filter);
                    let complete = match &request {
                        UserRequest::GetCFilters { block_hashes, .. } => {
                            filters.len() == block_hashes.len()
                        }
                        _ => unreachable!("matched request is a filter batch"),
                    };

                    if complete {
                        let filters = self
                            .inflight_filter_batches
                            .remove(&request)
                            .expect("completed filter batch exists");
                        if let Some((_, _, responder)) =
                            self.inflight_user_requests.remove(&request)
                        {
                            self.remember_filter_server(FilterDataKind::Filters, block_hash, peer);
                            let _ = responder.send(NodeResponse::CFilters(filters));
                        }
                    }
                } else {
                    // Most likely the tail of a request that timed out: a batch is up to
                    // a hundred messages, and a slow link delivers some after the deadline.
                    // Penalizing them bans what may be our only compact-filters peer.
                    debug!("Peer {peer} sent us a cfilter we aren't waiting for");
                }

                Ok(None)
            }
            PeerMessages::CFCheckpt(checkpoint) => {
                let request = self.inflight_user_requests.iter().find_map(
                    |(request, (request_peer, _, _))| match request {
                        UserRequest::GetCFCheckpt { stop_hash }
                            if *stop_hash == checkpoint.stop_hash && *request_peer == peer =>
                        {
                            Some(request.clone())
                        }
                        _ => None,
                    },
                );

                if let Some(request) = request {
                    if let Some((_, _, responder)) = self.inflight_user_requests.remove(&request) {
                        self.remember_filter_server(
                            FilterDataKind::Checkpoints,
                            checkpoint.stop_hash,
                            peer,
                        );
                        let _ = responder.send(NodeResponse::CFCheckpt(checkpoint));
                    }
                } else {
                    // Most likely the tail of a request that timed out: a batch is up to
                    // a hundred messages, and a slow link delivers some after the deadline.
                    // Penalizing them bans what may be our only compact-filters peer.
                    debug!("Peer {peer} sent us a cfcheckpt we aren't waiting for");
                }

                Ok(None)
            }
            _ => Ok(Some(msg)),
        }
    }

    /// A filter batch is given up on after this many request timeouts, however steadily its
    /// peer delivers. Ten batches of a hundred filters queue on one peer at a time, so this
    /// still leaves a slow but honest link several minutes per batch.
    const MAX_FILTER_BATCH_TIMEOUTS: u64 = 5;

    /// How many served filter batches we remember the sender of.
    const REMEMBERED_FILTER_SERVERS: usize = 64;

    fn remember_filter_server(&mut self, kind: FilterDataKind, stop_hash: BlockHash, peer: PeerId) {
        if self.recent_filter_servers.len() >= Self::REMEMBERED_FILTER_SERVERS {
            self.recent_filter_servers.pop_front();
        }
        self.recent_filter_servers
            .push_back((kind, stop_hash, peer));
    }

    /// Penalizes the peer that served the filter batch ending at `stop_hash`, which the
    /// consumer found invalid. Two such batches ban it, so the consumer's retries reach another
    /// peer. It isn't banned outright: the filter-header chain the batch was checked against
    /// came from a peer too, and may be the one that is wrong.
    ///
    /// Two consequences worth knowing. Manual peers are exempt from ban scores, so with a
    /// manual compact-filters peer every retry reaches it again and the consumer ends up
    /// distrusting its headers instead. And when our headers really are the wrong ones, up to
    /// two honest peers serve a full ban before the consumer finds out; the ban is what makes
    /// the retries reach someone else, so a shorter disconnect wouldn't do.
    pub(crate) fn punish_filter_server(
        &mut self,
        kind: FilterDataKind,
        stop_hash: BlockHash,
    ) -> Result<(), WireError> {
        let Some(position) = self
            .recent_filter_servers
            .iter()
            .position(|(served, hash, _)| *served == kind && *hash == stop_hash)
        else {
            return Ok(());
        };
        let Some((_, _, peer)) = self.recent_filter_servers.remove(position) else {
            return Ok(());
        };

        warn!("Peer {peer} served compact-filter data ({kind:?}) that failed validation");
        self.increase_banscore(peer, self.max_banscore.div_ceil(2))
    }

    /// Fails every user request waiting on `peer`, so the caller retries right away instead of
    /// waiting out the request timeout for a reply that can't come anymore.
    fn fail_user_requests_of(&mut self, peer: u32) {
        // Whether or not it still owed us something: peers come and go for as long as we run.
        self.last_filter_progress.remove(&peer);

        let orphaned = self
            .inflight_user_requests
            .iter()
            .filter(|(_, (request_peer, _, _))| *request_peer == peer)
            .map(|(request, _)| request.clone())
            .collect::<Vec<_>>();

        for request in orphaned {
            debug!("Peer {peer} left with a pending user request: {request:?}");
            self.inflight_filter_batches.remove(&request);
            // Dropping the responder is what reports the failure.
            self.inflight_user_requests.remove(&request);
        }
    }

    pub(crate) fn handle_disconnection(&mut self, peer: u32, idx: usize) -> Result<(), WireError> {
        self.fail_user_requests_of(peer);

        if let Some(p) = self.peers.remove(&peer) {
            if p.kind.is_long_lived() && p.state == PeerStatus::Ready {
                info!("Peer disconnected: {peer}");
            }

            if p.kind.is_manual() && p.state == PeerStatus::Ready {
                let address = p.address.as_bitcoin_socket_addr();
                if let Some(added) = self
                    .added_peers
                    .iter_mut()
                    .find(|added| added.address == *address)
                {
                    added.note_session_end(Instant::now());
                }
            }

            std::mem::drop(p.channel);

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            match p.state {
                PeerStatus::Ready => {
                    self.address_man
                        .update_set_state(idx, AddressState::Tried(now));
                }
                PeerStatus::Awaiting => {
                    self.address_man
                        .update_set_state(idx, AddressState::Failed(now));
                }
                PeerStatus::Banned => {
                    self.address_man
                        .update_set_state(idx, AddressState::Banned(RunningNode::BAN_TIME));
                }
            }
        }

        self.peer_ids.retain(|&id| id != peer);
        for v in self.peer_by_service.values_mut() {
            v.retain(|&id| id != peer);
        }

        // User requests have no automatic retry. Dropping their response senders
        // gives callers an error instead of leaving them waiting for this peer.
        self.inflight_user_requests
            .retain(|_, (requested_peer, _, _)| *requested_peer != peer);

        let inflight = self
            .inflight
            .clone()
            .into_iter()
            .filter(|(_k, v)| v.0 == peer)
            .collect::<Vec<_>>();

        let mut retry_error = None;
        for req in inflight {
            self.inflight.remove(&req.0);

            if let Err(e) = self.redo_inflight_request(&req.0) {
                // CRITICAL: never drop the request, so we retry it later
                self.inflight.insert(req.0, req.1);
                // Retry the remaining requests before returning an error.
                retry_error = Some(e);
            }
        }

        #[cfg(feature = "metrics")]
        self.update_peer_metrics();

        retry_error.map_or(Ok(()), Err)
    }

    /// Increases the "banscore" of a peer.
    ///
    /// This is a always increasing number that, if reaches our `max_banscore` setting,
    /// will cause our peer to be banned for one BANTIME.
    /// The amount of each increment is given by factor, and it's calibrated for each misbehaving
    /// action that a peer may incur in.
    pub(crate) fn increase_banscore(&mut self, peer_id: u32, factor: u32) -> Result<(), WireError> {
        let Some(peer) = self.common.peers.get_mut(&peer_id) else {
            return Ok(());
        };

        // Manual connections are exempt from being punished
        if peer.kind.is_manual() {
            return Ok(());
        }

        peer.banscore += factor;

        // This peer is misbehaving too often, ban it
        let is_misbehaving = peer.banscore >= self.common.max_banscore;
        // extra peers should be banned immediately
        let is_extra = peer.kind == ConnectionKind::Extra;

        if is_misbehaving || is_extra {
            warn!("banning peer {peer_id} for misbehaving");
            self.disconnect_and_ban(peer_id)?;
            return Ok(());
        }

        debug!("increasing banscore for peer {peer_id}");

        Ok(())
    }

    /// Disconnects a peer and bans it for `T::BAN_TIME`.
    pub(crate) fn disconnect_and_ban(&mut self, peer: PeerId) -> Result<(), WireError> {
        if let Some(peer) = self.peers.get_mut(&peer) {
            // Manual connections are exempt from being punished
            if peer.kind.is_manual() {
                return Ok(());
            }

            // `handle_disconnection` will mark the address as banned when `Peer` object return
            peer.state = PeerStatus::Banned;
        }

        self.send_to_peer(peer, NodeRequest::Shutdown)?;
        Ok(())
    }

    /// Tries to randomly disconnect up to `n` non-protected-feature peers.
    pub(crate) fn disconnect_random_peers(&self, n: usize, protected_services: &[ServiceFlags]) {
        let mut rng = rand::rng();

        let peers = self
            .peers
            .values()
            .filter(|peer| peer.kind.is_regular() && !peer.has_any_service(protected_services))
            .sample(&mut rng, n);

        for peer in peers {
            let _ = peer.channel.send(NodeRequest::Shutdown);
        }
    }

    /// Checks whether some of our inflight requests have timed out.
    ///
    /// Disconnects unresponsive peers without banning them and retries their requests.
    /// Manual peers keep their connection when requests time out.
    /// Address timeouts only disconnect feeler peers.
    pub(crate) fn check_for_timeout(&mut self) -> Result<(), WireError> {
        let now = Instant::now();

        let timed_out_fn = |req: &InflightRequests, time: &Instant| match req {
            InflightRequests::Connect(_)
                if now.duration_since(*time).as_secs() > T::CONNECTION_TIMEOUT =>
            {
                Some(req.clone())
            }

            _ if now.duration_since(*time).as_secs() > T::REQUEST_TIMEOUT => Some(req.clone()),

            _ => None,
        };

        let timed_out: Vec<_> = self
            .inflight
            .iter()
            .filter_map(|(req, (_, time))| timed_out_fn(req, time))
            .collect();

        let mut retry_error = None;
        for req in timed_out {
            let Some(&(peer, time)) = self.inflight.get(&req) else {
                continue;
            };

            // This request was timed out when collected, but an earlier iteration
            // disconnecting the same peer may have retried it. So re-check timeouts.
            if timed_out_fn(&req, &time).is_none() {
                continue;
            }

            // Remove it now to avoid retrying it both during disconnection and below.
            self.inflight.remove(&req);

            debug!("Request timed out: {req:?} peer={peer}");
            if matches!(req, InflightRequests::Headers) {
                let stalled_for = now.duration_since(time).as_secs();
                info!(
                    "Header request to peer={peer} timed out after {stalled_for}s; re-issuing to a fresh peer"
                );
            }
            if let Some(peer_data) = self.peers.get(&peer) {
                let kind = peer_data.kind;
                let idx = peer_data.address.id;

                // Do not disconnect peers on missing address replies, except for
                // short-lived connections.
                if matches!(req, InflightRequests::GetAddresses) && !kind.is_short_lived() {
                    continue;
                }

                // Disconnect peers on timeout unless they are manual (and completed handshake).
                let is_connect = matches!(req, InflightRequests::Connect(_));
                let mut disconnect = !kind.is_manual() || is_connect;
                // Contexts that only want a fast re-issue keep a slow peer, at a cost.
                if disconnect && !T::DISCONNECT_ON_TIMEOUT && !is_connect && !kind.is_short_lived()
                {
                    disconnect = false;
                    try_and_log!(self.increase_banscore(peer, 1));
                }

                if disconnect {
                    let _ = self.send_to_peer(peer, NodeRequest::Shutdown);

                    // Remove the peer before retrying, without waiting for its task to stop.
                    // It cannot be selected again, and the common handler discards late replies.
                    if let Err(e) = self.handle_disconnection(peer, idx) {
                        retry_error = Some(e);
                    }
                } else {
                    self.penalize_timed_out_peer(peer, &req);
                }
            }

            if let Err(e) = self.redo_inflight_request(&req) {
                // CRITICAL: never drop the request, so we retry it later, on the next tick.
                // Keep the old timestamp so it stays expired.
                self.inflight.insert(req, (peer, time));
                // Retry the remaining requests before returning an error.
                retry_error = Some(e);
            }
        }

        let timed_out_user_requests = self
            .inflight_user_requests
            .iter()
            .filter(|(request, (peer, sent_at, _))| {
                // For filter batches, a peer that keeps delivering is alive (see
                // `last_filter_progress`).
                let last_activity = match request {
                    UserRequest::GetCFilters { .. } => self
                        .last_filter_progress
                        .get(peer)
                        .map_or(*sent_at, |progress| progress.max(sent_at).to_owned()),
                    _ => *sent_at,
                };
                // Progress buys time, but not forever: a peer trickling one filter per window
                // would otherwise keep every request queued on it alive indefinitely.
                let age = now.duration_since(*sent_at).as_secs();
                now.duration_since(last_activity).as_secs() > T::REQUEST_TIMEOUT
                    || age > Self::MAX_FILTER_BATCH_TIMEOUTS * T::REQUEST_TIMEOUT
            })
            .map(|(request, _)| request.clone())
            .collect::<Vec<_>>();

        for request in timed_out_user_requests {
            let Some((peer, _, responder)) = self.inflight_user_requests.remove(&request) else {
                continue;
            };
            self.inflight_filter_batches.remove(&request);
            debug!("User request timed out: {request:?}");
            try_and_log!(self.increase_banscore(peer, 1));
            drop(responder);
        }

        retry_error.map_or(Ok(()), Err)
    }

    /// Accounts for a request a peer we keep connected (a manual peer, or a slow peer in a
    /// context that doesn't disconnect on timeouts) let time out.
    ///
    /// Only answers feed the latency average, so a peer that never answers would keep the
    /// latency it earned on its handshake and stay a preferred pick: count the timeout as a very
    /// slow answer instead. And a peer that could not serve a block it claimed to have is treated
    /// as not having it, whatever its handshake said, so its claim stops attracting the requests
    /// for that height and above.
    fn penalize_timed_out_peer(&mut self, peer: PeerId, req: &InflightRequests) {
        let unserved_height = match req {
            InflightRequests::Blocks(hash) | InflightRequests::UtreexoProof(hash) => {
                self.known_height(hash)
            }
            _ => None,
        };

        if let Some(peer_data) = self.peers.get_mut(&peer) {
            peer_data
                .message_times
                .add((T::REQUEST_TIMEOUT * 1_000) as f64);
            if let Some(height) = unserved_height {
                peer_data.height = peer_data.height.min(height.saturating_sub(1));
            }
        }
    }

    pub(crate) fn handle_addresses_from_peer(
        &mut self,
        peer: u32,
        addresses: Vec<AddrV2Message>,
    ) -> Result<(), WireError> {
        /// Don't allow addresses whose timestamp are more than 10 minutes into the future, or an
        /// attacker could make us drop all addresses from our address manager with their own.
        const ADDRESS_TIME_CUTOFF: Duration = Duration::from_secs(600); // 10 minutes

        debug!("Got {} addresses from peer {}", addresses.len(), peer);
        self.inflight.remove(&InflightRequests::GetAddresses);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("System clock isn't working");

        let cutoff = now + ADDRESS_TIME_CUTOFF;
        let good_addresses: Vec<_> = addresses
            .into_iter()
            .filter(|addr| u64::from(addr.time) < cutoff.as_secs())
            .map(|addr| addr.into())
            .collect();

        self.address_man.push_addresses(&good_addresses);

        // Addr-fetch peers are short-lived: after we receive their addresses,
        // we disconnect them.
        let Some(peer_data) = self.peers.get(&peer) else {
            return Ok(());
        };

        if matches!(peer_data.kind, ConnectionKind::AddrFetch) {
            debug!("Addr-fetch peer {peer} returned addresses; disconnecting");
            self.send_to_peer(peer, NodeRequest::Shutdown)?;
        }

        Ok(())
    }

    pub(crate) fn redo_inflight_request(
        &mut self,
        req: &InflightRequests,
    ) -> Result<(), WireError> {
        match req {
            InflightRequests::UtreexoProof(block_hash) => {
                if !self.has_utreexo_peers() {
                    return Ok(());
                }

                if !self.blocks.contains_key(block_hash) {
                    // If we don't have the block anymore, we can't ask for the proof
                    return Ok(());
                }

                if self.inflight.contains_key(req) {
                    // If we already have an inflight request for this block, we don't need to redo it
                    return Ok(());
                }

                let peer = self.send_to_fast_peer_at_height(
                    NodeRequest::GetBlockProof((*block_hash, Bitmap::new(), Bitmap::new())),
                    service_flags::UTREEXO.into(),
                    self.known_height(block_hash),
                )?;

                self.inflight.insert(
                    InflightRequests::UtreexoProof(*block_hash),
                    (peer, Instant::now()),
                );
            }

            InflightRequests::Blocks(block) => {
                self.request_blocks(vec![*block])?;
            }

            InflightRequests::Headers => {
                let locator = self.chain.get_block_locator()?;
                let peer =
                    self.send_to_fast_peer(NodeRequest::GetHeaders(locator), ServiceFlags::NONE)?;

                self.inflight
                    .insert(InflightRequests::Headers, (peer, Instant::now()));
            }

            InflightRequests::UtreexoState(_) => {
                let peer = self.send_to_fast_peer(
                    NodeRequest::GetUtreexoState((self.chain.get_block_hash(0).unwrap(), 0)),
                    service_flags::UTREEXO.into(),
                )?;
                self.inflight
                    .insert(InflightRequests::UtreexoState(peer), (peer, Instant::now()));
            }

            InflightRequests::Connect(_) | InflightRequests::GetAddresses => {
                // We don't need to do anything here
            }
        }

        Ok(())
    }

    pub(crate) fn save_peers(&self) -> Result<(), WireError> {
        self.address_man
            .dump_peers(&self.datadir)
            .map_err(WireError::Io)
    }

    /// Saves the utreexo peers to disk so we can reconnect with them later
    pub(crate) fn save_utreexo_peers(&self) -> Result<(), WireError> {
        let utreexo_peers: Vec<LocalAddress> = self
            .peers
            .values()
            .filter(|peer| {
                peer.state == PeerStatus::Ready && peer.services.has(service_flags::UTREEXO.into())
            })
            .map(|peer| peer.address.clone())
            .collect();
        if utreexo_peers.is_empty() {
            warn!("No connected Utreexo peers to save to disk");
            return Ok(());
        }
        info!("Saving utreexo peers to disk...");
        AddressMan::dump_utreexo_peers(&self.datadir, &utreexo_peers).map_err(WireError::Io)
    }

    // === METRICS AND HELPERS ===

    /// Records response latency for the peer currently assigned to the request.
    ///
    /// We need this information for two purposes:
    /// 1. To calculate the average time taken to respond to messages from peers, which we use
    ///    to select the fastest peer when sending requests.
    /// 2. If `metrics` feature is enabled, we record the time taken for all peers on a histogram,
    ///    and expose it as a prometheus metric.
    pub(crate) fn register_message_time(
        &mut self,
        notification: &PeerMessages,
        peer: PeerId,
        read_at: Instant,
    ) -> Option<()> {
        let inflight_sent_at = |request: InflightRequests| {
            let (request_peer, sent_at) = self.inflight.get(&request)?;
            // A late reply must not use another peer's retry timestamp.
            (*request_peer == peer).then_some(*sent_at)
        };

        let sent_at = match notification {
            PeerMessages::Block(block) => {
                inflight_sent_at(InflightRequests::Blocks(block.block_hash()))?
            }
            PeerMessages::Ready(_) => inflight_sent_at(InflightRequests::Connect(peer))?,
            PeerMessages::Headers(_) => inflight_sent_at(InflightRequests::Headers)?,

            // One sample per batch, taken on its first filter: the rest of the batch streams in
            // over seconds, and a batch queued behind others on the same peer only starts when
            // the previous one ends. Anything else makes serving us filters look like slowness.
            PeerMessages::BlockFilter((block_hash, _)) => self
                .inflight_user_requests
                .iter()
                .find_map(|(request, (request_peer, sent_at, _))| match request {
                    UserRequest::GetCFilters { block_hashes, .. }
                        if block_hashes.first() == Some(block_hash) && *request_peer == peer =>
                    {
                        let progress = self.last_filter_progress.get(&peer).copied();
                        Some(progress.map_or(*sent_at, |progress| progress.max(*sent_at)))
                    }
                    _ => None,
                })?,

            PeerMessages::CFHeaders(headers) => self.inflight_user_requests.iter().find_map(
                |(request, (request_peer, sent_at, _))| match request {
                    UserRequest::GetCFilterHeaders { stop_hash, .. }
                        if *stop_hash == headers.stop_hash && *request_peer == peer =>
                    {
                        Some(*sent_at)
                    }
                    _ => None,
                },
            )?,

            PeerMessages::CFCheckpt(checkpoint) => self.inflight_user_requests.iter().find_map(
                |(request, (request_peer, sent_at, _))| match request {
                    UserRequest::GetCFCheckpt { stop_hash }
                        if *stop_hash == checkpoint.stop_hash && *request_peer == peer =>
                    {
                        Some(*sent_at)
                    }
                    _ => None,
                },
            )?,

            PeerMessages::UtreexoState(_) => {
                inflight_sent_at(InflightRequests::UtreexoState(peer))?
            }

            _ => return None,
        };

        // A reply may be read just before a retry to the same peer, so `sent_at`
        // will be overridden with the retry instant, which makes `read_at < sent_at`.
        // Skip that stale sample instead of recording zero latency.
        let elapsed = read_at.checked_duration_since(sent_at)?.as_secs_f64();
        if let Some(peer) = self.peers.get_mut(&peer) {
            peer.message_times.add(elapsed * 1_000.0); // milliseconds
        }

        #[cfg(feature = "metrics")]
        {
            use floresta_metrics::get_metrics;
            let metrics = get_metrics();

            metrics.message_times.observe(elapsed);
        }

        Some(())
    }

    #[cfg(feature = "metrics")]
    pub(crate) fn update_peer_metrics(&self) {
        use floresta_metrics::get_metrics;

        let metrics = get_metrics();
        metrics.peer_count.set(self.peer_ids.len() as f64);
    }

    pub(crate) fn has_utreexo_peers(&self) -> bool {
        !self
            .peer_by_service
            .get(&service_flags::UTREEXO.into())
            .unwrap_or(&Vec::new())
            .is_empty()
    }

    pub(crate) fn has_compact_filters_peer(&self) -> bool {
        self.peer_by_service
            .get(&ServiceFlags::COMPACT_FILTERS)
            .map(|peers| !peers.is_empty())
            .unwrap_or(false)
    }

    pub(crate) fn get_peer_info(&self, peer_id: &u32) -> Option<PeerInfo> {
        let peer = self.peers.get(peer_id)?;
        Some(PeerInfo {
            id: *peer_id,
            address: peer.address.as_bitcoin_socket_addr().clone(),
            services: format!("{:016x}", peer.services.to_u64()),
            services_names: service_flags_strings(&peer.services),
            relay_txs: false,
            user_agent: peer.user_agent.clone(),
            inbound: false,
            bip152_hb_to: false,
            bip152_hb_from: false,
            initial_height: peer.height,
            time_offset: peer.time_offset,
            state: peer.state,
            kind: peer.kind,
            permissions: Vec::new(),
            transport_protocol: peer.transport_protocol,
        })
    }

    // === ADDNODE ===

    /// Handles addnode-RPC `Add` requests, adding a new peer to the `added_peers` list. This means
    /// the peer is marked as a "manually added peer". We then try to connect to it, or retry later.
    pub fn handle_addnode_add_peer(
        &mut self,
        peer_address: BitcoinSocketAddr,
        v2_transport: bool,
    ) -> Result<(), WireError> {
        // See https://github.com/bitcoin/bitcoin/blob/8309a9747a8df96517970841b3648937d05939a3/src/net.cpp#L3558

        // Add this address to our address manager for later
        // assume it has the bare-minimum services, otherwise `push_addresses` will ignore it
        let mut local_address = LocalAddress::from(peer_address.clone());
        debug!("Adding node {}", local_address);

        local_address.set_services(ServiceFlags::NETWORK_LIMITED | ServiceFlags::WITNESS);

        // Check if the peer already exists
        if self
            .added_peers
            .iter()
            .any(|peer_info| peer_address == peer_info.address)
        {
            return Err(WireError::PeerAlreadyExists(local_address));
        }

        self.address_man.push_addresses(&[local_address]);

        // Add a simple reference to the peer
        self.added_peers
            .push(AddedPeerInfo::new(peer_address, !v2_transport));

        // Implementation detail for `addnode`: on bitcoin-core, the node doesn't connect immediately
        // after adding a peer, it just adds it to the `added_peers` list. Here we do almost the same,
        // but we do an early connection attempt to the peer, so we can start communicating with.
        self.maybe_open_connection_with_added_peers()
    }

    /// Handles remove node requests, removing a peer from the node.
    ///
    /// Removes a node from the `added_peers` list but does not
    /// disconnect the node if it was already connected.  It only ensures
    /// that the node is no longer treated as a manually added node
    /// (i.e., it won't be reconnected if disconnected).
    ///
    /// If someone wants to remove a peer, it should be done using the
    /// `disconnectnode`.
    pub fn handle_addnode_remove_peer(&mut self, addr: BitcoinSocketAddr) -> Result<(), WireError> {
        debug!("Trying to remove peer {addr}");

        let index = self
            .added_peers
            .iter()
            .position(|info| addr == info.address)
            .ok_or(WireError::PeerNotFoundAtAddress(addr))?;

        self.added_peers.remove(index);

        Ok(())
    }

    /// Handles the node request for immediate disconnection from a peer.
    pub fn handle_disconnect_peer(&mut self, addr: BitcoinSocketAddr) -> Result<(), WireError> {
        // Get the peer's index in the [`AddressMan`]'s list, if it exists.
        let peer_id = self
            .peers
            .iter()
            .find_map(|(&id, peer)| (*peer.address.as_bitcoin_socket_addr() == addr).then_some(id))
            .ok_or(WireError::PeerNotFoundAtAddress(addr))?;

        self.send_to_peer(peer_id, NodeRequest::Shutdown)
    }

    /// Handles addnode onetry requests, connecting to the node and this will try to connect to the given address and port.
    /// If it's successful, it will add the node to the peers list, but not to the added_peers list (e.g., it won't be reconnected if disconnected).
    pub fn handle_addnode_onetry_peer(
        &mut self,
        peer_address: BitcoinSocketAddr,
        v2_transport: bool,
    ) -> Result<(), WireError> {
        let kind = ConnectionKind::Manual;

        // Add this address to our address manager for later
        // assume it has the bare-minimum services, otherwise `push_addresses` will ignore it
        let mut local_address = LocalAddress::from(peer_address.clone());
        debug!("Creating an one-try connection with {local_address}");

        // Check if the peer already exists
        if self
            .peers
            .iter()
            .any(|(_, peer_info)| *peer_info.address.as_bitcoin_socket_addr() == peer_address)
        {
            return Err(WireError::PeerAlreadyExists(local_address));
        }

        local_address.set_services(ServiceFlags::NETWORK_LIMITED | ServiceFlags::WITNESS);

        self.address_man.push_addresses(&[local_address.clone()]);
        // Return true if exists or false if anything fails during connection
        // We allow V1 fallback iff the `v2` flag is not set
        self.open_connection(kind, local_address, !v2_transport)
    }
}

#[cfg(test)]
mod added_peer_tests {
    use std::time::Duration;
    use std::time::Instant;

    use super::AddedPeerInfo;
    use crate::address_man::LocalAddress;

    #[test]
    fn an_added_peer_that_keeps_dropping_us_is_redialed_less_and_less_often() {
        let address = "127.0.0.1:8333".parse::<LocalAddress>().unwrap();
        let mut added = AddedPeerInfo::new(address.as_bitcoin_socket_addr().clone(), false);
        let start = Instant::now();
        assert!(added.due(start));

        let mut waits = Vec::new();
        for _ in 0..9 {
            added.note_attempt(start);
            let retry_after = added.retry_after.unwrap();
            assert!(added.due(retry_after));
            waits.push((retry_after - start).as_secs());
        }
        // The first redial is immediate, so a single drop costs nothing
        assert_eq!(waits, [0, 10, 20, 40, 80, 160, 320, 600, 600]);

        // A session that ended quickly keeps the backoff
        added.note_session_end(start + Duration::from_secs(5));
        assert!(!added.due(start));

        // A session that lasted makes it a fresh start
        added.note_session_end(start + AddedPeerInfo::STABLE_SESSION);
        assert!(added.due(start));
        added.note_attempt(start);
        assert!(added.due(start));
        added.note_attempt(start);
        assert_eq!(added.retry_after.unwrap() - start, Duration::from_secs(10));
    }
}
