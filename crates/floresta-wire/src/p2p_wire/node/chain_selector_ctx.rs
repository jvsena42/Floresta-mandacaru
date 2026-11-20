// SPDX-License-Identifier: MIT OR Apache-2.0

//! A module that connects with multiple peers and finds the best chain.
//!
//! # The theory
//!
//! In Bitcoin, the history of transactions processed by the network is defined by a sequence of
//! blocks, chainned by their cryptographic hash. A block commits the hash for the block right
//! before it. Therefore, if we pick any given block, there's exactly one history leading to the
//! very first block, that commits to no one. However, if you go in the other way, starting at the
//! first block and going up, there may not be only one history. Multiple blocks may commit to the
//! same parent. We need a way to pick just one such chain, among all others.
//!
//! To do that, we use the most work rule, sometimes called "Nakamoto Consensus" after Bitcoin's
//! creator, Satoshi Nakamoto. Every block has to solve a probabilistic challenge of finding a
//! combination of data that hashes to a value smaller than a network-agreed value. Because hash
//! functions are pseudorandom, one must make certain amount of hashes (on average) before finding a
//! valid one. If we define the amount of hashes needed to find a block as this block's "work",
//! by adding-up the work in each of a chain's blocks, we arrive with the `chainwork`. The Nakamoto
//! consensus consists in taking the chain with most work as the best one.
//!
//! This works because anyone in the network will compute the same amount of work and pick the same
//! one, regardless of where and when. Because work is a intrinsic and deterministic property of a
//! block, everyone comparing the same chain, be on earth, on mars; in 2020 or 2100, they will
//! choose the exact same chain, always.
//!
//! The most critical part of syncing-up a Bitcoin node is making sure you know about the most-work
//! chain. If someone can eclypse you, they can make you start following a chain that only you and
//! the attacker care about. If you get paid in this chain, you can't pay someone else outside this
//! chain, because they will be following other chains. Luckily, we only need one honest peer, to
//! find the best-work chain and avoid any attacker to fools us into accepting payments in a "fake
//! Bitcoin"
//!
//! # Implementation
//!
//! In Floresta, we try to pick a good balance between data downloaded and security. We could
//! simply download all chains from all peers and pick the most work one. But each header is
//! 80 bytes-long, with ~800k blocks, that's around 60 MBs. If we have 10 peers, that's 600MBs
//! (excluding overhead by the p2p messages). Moreover, it's very uncommon to actually have peers
//! in different chains. So we can optmistically download all headers from one random peer, and
//! then check with the others if they agree. If they have another chain for us, we download that
//! chain, and pick whichever has more work.
//!
//! Most likely we'll only download one chain and all peers will agree with it. Then we can start
//! downloading the actual blocks and validating them.

use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use bitcoin::Block;
use bitcoin::BlockHash;
use bitcoin::block::Header;
use bitcoin::network::Network;
use bitcoin::p2p::ServiceFlags;
use floresta_chain::BlockchainError;
use floresta_chain::ChainBackend;
use floresta_chain::CompactLeafData;
use floresta_chain::proof_util;
use floresta_chain::pruned_utreexo::IBDState;
use floresta_chain::pruned_utreexo::consensus::Consensus;
use floresta_common::service_flags;
use floresta_common::try_and_log;
use rand::rng;
use rand::seq::IndexedRandom;
use rustreexo::node_hash::BitcoinNodeHash;
use rustreexo::proof::Proof;
use rustreexo::stump::Stump;
use tokio::time;
use tokio::time::MissedTickBehavior;
use tokio::time::timeout;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::warn;

use crate::address_man::AddressState;
use crate::block_proof::Bitmap;
use crate::node::InflightBlock;
use crate::node::InflightRequests;
use crate::node::NodeNotification;
use crate::node::NodeRequest;
use crate::node::UtreexoNode;
use crate::node::WitnessMode;
use crate::node::periodic_job;
use crate::node_context::LoopControl;
use crate::node_context::NodeContext;
use crate::node_context::PeerId;
use crate::p2p_wire::error::WireError;
use crate::p2p_wire::peer::PeerMessages;

#[derive(Debug, Default, Clone)]
/// A p2p driver that attempts to connect with multiple peers, ask which chain are them following
/// and download and verify the headers, **not** the actual blocks. This is the first part of a
/// logger IBD pipeline.
/// The actual blocks should be downloaded by a SyncPeer.
pub struct ChainSelector {
    /// The state we are in
    state: ChainSelectorState,

    /// Peers that already sent us a message we are waiting for
    done_peers: HashSet<PeerId>,

    /// Keep track each peer's tip
    tip_cache: HashMap<PeerId, BlockHash>,

    /// First time we entered `LookingForForks` (preserved across the per-poke timer
    /// resets in `LookingForForks(Instant)`). Used as a watchdog: if some peer never
    /// responds to any of our pokes, force-close the all-done gate so an unresponsive
    /// peer cannot strand IBD indefinitely.
    looking_for_forks_first_entered: Option<Instant>,

    /// How many times the header download was resumed because the assume-utreexo block
    /// was missing from our header chain when every peer looked done.
    assume_utreexo_resumes: u32,

    /// The last peer that answered with headers we already had, if it did so since the
    /// last stall check.
    known_batch_since_stall_check: Option<PeerId>,

    /// Consecutive stall checks in which peers only sent headers we already had.
    stalls_with_only_known_batches: u32,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub enum ChainSelectorState {
    #[default]
    /// We are opening connection with some peers
    CreatingConnections,
    /// We are downloading headers from only one peer, assuming this peer is honest
    DownloadingHeaders,
    /// We've downloaded all headers, and now we are checking with our peers if they
    /// have an alternative tip with more PoW. Very unlikely, but we shouldn't trust
    /// only one peer...
    LookingForForks(Instant),
    /// We've downloaded all headers
    Done,
}

pub enum FindAccResult {
    Found(Vec<u8>),
    KeepLooking(Vec<(PeerId, Vec<u8>)>),
}

/// Helper enum to express the different possibilities under `find_who_is_lying`
pub enum PeerCheck {
    /// One peer is lying
    OneLying(PeerId),

    /// Both peers are lying
    BothLying,

    /// One peer is unresponsive
    UnresponsivePeer(PeerId),

    /// Both peers are unresponsive
    BothUnresponsivePeers,
}

impl ChainSelector {
    /// Watchdog: max seconds we'll wait in `LookingForForks` before treating any
    /// silent peer as done. `poke_peers` is fire-and-forget (no inflight tracking),
    /// so a peer with a half-open connection will never time out via the normal
    /// `check_for_timeout` path; without this fallback, one such peer can strand IBD.
    /// Three poke rounds at `REQUEST_TIMEOUT` (10s) is plenty for a healthy peer to
    /// respond, so 30s is safe.
    const LOOKING_FOR_FORKS_MAX_WAIT: u64 = 30;

    /// How many times we go back to downloading headers when the header phase ends
    /// without the assume-utreexo block in our chain. Bounded so a snapshot whose block
    /// no peer has can't keep the node in header sync forever.
    const MAX_ASSUME_UTREEXO_RESUMES: u32 = 5;

    /// How far behind our tip a peer's advertised height may be for its empty `headers`
    /// to still count as "nothing after ours". About a day of blocks.
    const PEER_BEHIND_MARGIN: u32 = 144;

    /// Stall checks in a row with only known headers coming in after which we take it
    /// that our peers have nothing past our tip, like an empty `headers`.
    const MAX_STALLS_WITH_ONLY_KNOWN_BATCHES: u32 = 3;
}

impl NodeContext for ChainSelector {
    const REQUEST_TIMEOUT: u64 = 10; // Detect stalled IBD peers quickly so we re-issue to a fresh fast peer

    // A 2,000-header batch can take over 10 s on a phone's cellular link; dropping every
    // peer that slow would churn the whole outbound set during header sync.
    const DISCONNECT_ON_TIMEOUT: bool = false;

    // Since we don't have any peers when chain selection starts, we use a more aggressive batch
    // size to make sure we get to our `MAX_OUTGOING_CONNECTIONS` ASAP
    const NEW_CONNECTIONS_BATCH_SIZE: usize = 12;
}

impl<Chain> UtreexoNode<Chain, ChainSelector>
where
    Chain: ChainBackend + 'static,
    WireError: From<Chain::Error>,
    Chain::Error: From<proof_util::UtreexoLeafError>,
{
    /// This function is called every time we get a `Headers` message from a peer.
    /// It will validate the headers and add them to our chain, if they are valid.
    /// If we get an empty headers message, we'll check what to do next, depending on
    /// our current state. We may poke our peers to see if they have an alternative tip,
    /// or we may just finish the IBD, if no one have an alternative tip.
    async fn handle_headers(
        &mut self,
        peer: PeerId,
        headers: Vec<Header>,
    ) -> Result<(), WireError> {
        if headers.is_empty() {
            self.empty_headers_message(peer).await?;
            return Ok(());
        }

        let tip_before = self.chain.get_best_block()?;
        let last = headers.last().unwrap().block_hash();
        let already_had_last = self.chain.get_block_header(&last).is_ok();

        info!(
            "Downloading headers from peer={peer} at height={} hash={}",
            tip_before.0 + 1,
            headers[0].block_hash()
        );

        for (i, header) in headers.iter().enumerate() {
            if let Err(e) = self.chain.accept_header(*header) {
                // Headers that don't connect to ours are usually a new block announced via
                // `sendheaders` while we're still behind. That isn't misbehavior, and
                // following it up would send a `getheaders` with an empty locator for a tip
                // we don't have, which some peers answer with an empty `headers` that ends
                // the download early. The download already in flight carries on.
                if i == 0 && matches!(e, BlockchainError::BlockNotPresent) {
                    debug!(
                        "Ignoring headers from peer={peer} that don't connect to our chain (first={})",
                        header.block_hash()
                    );
                    return Ok(());
                }

                error!("Error while downloading headers from peer={peer} err={e}");

                self.disconnect_and_ban(peer)?;

                let peer = self.peers.get(&peer).unwrap();
                self.common.address_man.update_set_state(
                    peer.address.id,
                    AddressState::Banned(ChainSelector::BAN_TIME),
                );
            }
        }

        self.context
            .tip_cache
            .entry(peer)
            .and_modify(|e| *e = last)
            .or_insert(last);

        self.last_tip_update = Instant::now();

        // In LookingForForks, if these headers didn't extend our tip the peer is on a
        // sibling fork at our height (or sent us a header we already had). Mark them
        // done and skip the recursive request_headers — otherwise competing-tip churn
        // produces a cascading getheaders fan-out that prevents the all-done gate from
        // ever closing.
        let tip_after = self.chain.get_best_block()?;
        if tip_after != tip_before {
            self.context.assume_utreexo_resumes = 0;
            self.context.stalls_with_only_known_batches = 0;
            self.context.known_batch_since_stall_check = None;
        }

        if matches!(self.context.state, ChainSelectorState::LookingForForks(_)) {
            if tip_after == tip_before {
                self.context.done_peers.insert(peer);
                self.maybe_finish_looking_for_forks().await?;
                return Ok(());
            }

            // A peer moved our tip, so the header download wasn't over: some peer told us
            // it had nothing more while the network is still ahead of us. Go back to
            // downloading instead of letting the all-done gate close at a short tip.
            info!(
                "peer={peer} extended our headers to height={} while looking for forks; resuming header download",
                tip_after.0
            );
            self.enter_downloading_headers();
        }

        if already_had_last && tip_after == tip_before {
            // A batch we already had is a duplicate answer to a re-issued or poked
            // `getheaders`, or the announcement of a block we already fetched. Neither says
            // where the chain ends, and following it up would run a second download of a
            // range we have. A peer far behind us answers our requests this way every time,
            // so it's dropped.
            let (our_height, _) = self.chain.get_best_block()?;
            if let Some(height) = self.non_manual_peer_height(peer)
                && Self::is_far_behind(height, our_height)
            {
                self.drop_peer_that_cannot_serve_headers(peer, height, our_height);
                return self.request_headers(tip_after.1);
            }
            self.context.known_batch_since_stall_check = Some(peer);
            return Ok(());
        }

        self.request_headers(last)
    }

    /// Called on each stall check. Whether peers answered only with headers we already
    /// had for `MAX_STALLS_WITH_ONLY_KNOWN_BATCHES` checks in a row. A stall where nobody
    /// answers resets the count: that's a slow peer, not the end of its chain.
    fn peers_only_send_known_headers(&mut self) -> bool {
        if self.context.known_batch_since_stall_check.is_none() {
            self.context.stalls_with_only_known_batches = 0;
            return false;
        }

        self.context.stalls_with_only_known_batches += 1;
        if self.context.stalls_with_only_known_batches
            < ChainSelector::MAX_STALLS_WITH_ONLY_KNOWN_BATCHES
        {
            self.context.known_batch_since_stall_check = None;
            return false;
        }

        self.context.stalls_with_only_known_batches = 0;
        true
    }

    fn enter_downloading_headers(&mut self) {
        self.context.state = ChainSelectorState::DownloadingHeaders;
        self.context.done_peers.clear();
        self.context.looking_for_forks_first_entered = None;
        self.last_tip_update = Instant::now();
    }

    /// Parses a serialized Utreexo accumulator into a [`Stump`].
    ///
    /// An empty slice yields [`Stump::default`]. Otherwise the payload must contain
    /// an 8-byte little-endian leaf count followed by `leaves.count_ones()` root
    /// hashes of 32 bytes each. All other lengths are rejected.
    fn parse_acc(acc: &[u8]) -> Result<Stump, WireError> {
        if acc.is_empty() {
            return Ok(Stump::default());
        }
        let Some((leaf_count, roots_bytes)) = acc.split_first_chunk::<8>() else {
            return Err(WireError::PeerMisbehaving);
        };
        let leaves = u64::from_le_bytes(*leaf_count);

        let expected_roots = leaves.count_ones() as usize;
        let expected_roots_len = expected_roots * 32;
        if roots_bytes.len() != expected_roots_len {
            return Err(WireError::PeerMisbehaving);
        }

        let mut roots = Vec::with_capacity(expected_roots);
        for chunk in roots_bytes.chunks_exact(32) {
            let mut root = [0u8; 32];
            root.copy_from_slice(chunk);
            roots.push(BitcoinNodeHash::from(root));
        }

        Ok(Stump { leaves, roots })
    }

    /// Sends a request to two peers and wait for their response
    ///
    /// This function will send a `GetUtreexoState` request to two peers and wait for their
    /// response. If both peers respond, it will return the accumulator from both peers.
    /// If only one peer responds, it will return the accumulator from that peer and `None`
    /// for the other. If no peer responds, it will return `None` for both.
    /// We use this during the cut-and-choose protocol, to find where they disagree.
    async fn grab_both_peers_version(
        &mut self,
        peer1: PeerId,
        peer2: PeerId,
        block_hash: BlockHash,
        block_height: u32,
    ) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>), WireError> {
        self.send_to_peer(
            peer1,
            NodeRequest::GetUtreexoState((block_hash, block_height)),
        )?;

        self.send_to_peer(
            peer2,
            NodeRequest::GetUtreexoState((block_hash, block_height)),
        )?;

        let mut peer1_version = None;
        let mut peer2_version = None;
        for _ in 0..2 {
            if let Ok(Some(NodeNotification::FromPeer(
                peer,
                PeerMessages::UtreexoState(state),
                _,
            ))) = timeout(Duration::from_secs(60), self.node_rx.recv()).await
            {
                if peer == peer1 {
                    peer1_version = Some(state);
                } else if peer == peer2 {
                    peer2_version = Some(state);
                }
            }
        }

        Ok((peer1_version, peer2_version))
    }

    /// Find which peer is lying about what the accumulator state is at a given point
    ///
    /// This function will ask peers their accumulator for a given block, and check whether
    /// they agree or not. If they don't, we cut the search in half and keep looking for the
    /// fork point. Once we find the last agreed accumulator, we ask for the block and proof
    /// that comes after it, update the accumulator from that point, and find who is lying.
    ///
    /// If successful returns the [PeerCheck] enum, representing whether peers are:
    ///
    /// - Lying
    /// - Unresponsive
    async fn find_who_is_lying(
        &mut self,
        peer1: PeerId,
        peer2: PeerId,
    ) -> Result<PeerCheck, WireError> {
        let (mut height, mut hash) = self.chain.get_best_block()?;
        let mut prev_height = 0;
        // we first narrow down the possible fork point to a couple of blocks, looking
        // for all blocks in a linear search would be too slow
        loop {
            // ask both peers for the utreexo state
            let (peer1_acc, peer2_acc) = self
                .grab_both_peers_version(peer1, peer2, hash, height)
                .await?;

            // if a peer is unresponsive, we opt for an early return
            let (peer1_acc, peer2_acc) = match (peer1_acc, peer2_acc) {
                (Some(acc1), Some(acc2)) => (acc1, acc2),
                (None, Some(_)) => return Ok(PeerCheck::UnresponsivePeer(peer1)),
                (Some(_), None) => return Ok(PeerCheck::UnresponsivePeer(peer2)),
                (None, None) => return Ok(PeerCheck::BothUnresponsivePeers),
            };

            // if we have different states, we need to keep looking until we find the
            // fork point
            let interval = height.abs_diff(prev_height);
            prev_height = height;

            if interval < 5 {
                break;
            }

            if peer1_acc == peer2_acc {
                // if they're equal, then the disagreement is in a newer block
                height += interval / 2;
            } else {
                // if they're different, then the disagreement is in an older block
                height -= interval / 2;
            }

            hash = self.chain.get_block_hash(height).unwrap();
        }
        info!("Fork point is around height={height} hash={hash}");
        // at the end, this variable should hold the last block where they agreed
        let mut fork = 0;

        // Getting the acc for the block on which we landed on
        let (peer1_acc, peer2_acc) = self
            .grab_both_peers_version(peer1, peer2, hash, height)
            .await?;

        // Initializing the agree bool for the block on which we landed on
        let agree = peer1_acc == peer2_acc;

        if agree {
            height += 1;
        } else {
            height -= 1;
        }

        loop {
            // keep asking blocks until we find the fork point
            let (peer1_acc, peer2_acc) = self
                .grab_both_peers_version(peer1, peer2, hash, height)
                .await?;

            // as we go, we'll approach the fork from two possible sides: we came from the side
            // they disagree, and therefore the point of inflection is the first block they agree.
            // on the other hand, if are agreeing, and we find they disagreeing, the last block
            // they've agreed on is the previous one (not the current one)
            match agree {
                true => {
                    // they agreed in the last block, so the fork is in the next one
                    if peer1_acc != peer2_acc {
                        fork = height - 1;
                    }
                }

                false => {
                    // they disagreed in the last block and now agree, the last block is the fork
                    if peer1_acc == peer2_acc {
                        fork = height;
                    }
                }
            }

            if fork != 0 {
                break;
            }

            // if we still don't know where the fork is, we need to keep looking
            if agree {
                // if they agree on this current block, we need to look in the next one
                height += 1;
            } else {
                // if they disagree on this current block, we need to look in the previous one
                height -= 1;
            }
            hash = self.chain.get_block_hash(height)?;
        }
        hash = self.chain.get_block_hash(fork)?;

        let acc = self
            .grab_both_peers_version(peer1, peer2, hash, fork)
            .await?;

        let agreed = match acc {
            (Some(acc1), Some(_)) => Self::parse_acc(&acc1)?,
            (Some(acc1), None) => Self::parse_acc(&acc1)?,
            (None, Some(acc2)) => Self::parse_acc(&acc2)?,
            (None, None) => return Ok(PeerCheck::BothUnresponsivePeers),
        };

        hash = self.chain.get_block_hash(fork + 1)?;

        // now we know where the fork is, we need to check who is lying
        let (peer1_acc, peer2_acc) = self
            .grab_both_peers_version(peer1, peer2, hash, fork + 1)
            .await?;

        // if a peer is unresponsive, we opt for an early return
        let (peer1_acc, peer2_acc) = match (peer1_acc, peer2_acc) {
            (Some(acc1), Some(acc2)) => (acc1, acc2),
            (None, Some(_)) => return Ok(PeerCheck::UnresponsivePeer(peer1)),
            (Some(_), None) => return Ok(PeerCheck::UnresponsivePeer(peer2)),
            (None, None) => return Ok(PeerCheck::BothUnresponsivePeers),
        };

        let block_hash = self.chain.get_block_hash(fork + 1)?;

        let inflight_block = match self.get_block_and_proof(peer1, block_hash).await {
            Err(WireError::PeerTimeout) => return Ok(PeerCheck::UnresponsivePeer(peer1)),
            res => res?,
        };

        let (leaf_data, proof, _) = inflight_block
            .aux_data
            .expect("Block proof and leaf data should be present");

        let acc1 = self.update_acc(agreed, &inflight_block.block, proof, &leaf_data, fork + 1)?;

        let peer1_acc = Self::parse_acc(&peer1_acc)?;
        let peer2_acc = Self::parse_acc(&peer2_acc)?;

        if peer1_acc != acc1 && peer2_acc != acc1 {
            return Ok(PeerCheck::BothLying);
        }

        if peer1_acc != acc1 {
            return Ok(PeerCheck::OneLying(peer1));
        }

        Ok(PeerCheck::OneLying(peer2))
    }

    /// Requests a block and its proof from a peer
    ///
    /// If you need to see a peer's version of a given block, you can use this method
    /// to request a block from a specific peer.
    async fn get_block_and_proof(
        &mut self,
        peer: PeerId,
        block_hash: BlockHash,
    ) -> Result<InflightBlock, WireError> {
        self.send_to_peer(
            peer,
            NodeRequest::GetBlock(vec![block_hash], WitnessMode::Full),
        )?;

        let timeout = Instant::now() + Duration::from_secs(60);
        let mut block = None;
        loop {
            if Instant::now() > timeout {
                return Err(WireError::PeerTimeout);
            }

            // TODO: Bound this receive by the deadline, even when no messages arrive.
            let Some(NodeNotification::FromPeer(id, message, _)) = self.node_rx.recv().await else {
                // Keep waiting until peer message is read or timeout
                continue;
            };

            if id != peer {
                continue;
            }

            match message {
                // STEP 1: Receive the block and ask for the proof
                PeerMessages::Block(recv_block) => {
                    if recv_block.block_hash() != block_hash {
                        error!("peer {peer} sent us a block we didn't request");
                        self.disconnect_and_ban(peer)?;
                        return Err(WireError::PeerMisbehaving);
                    }

                    // Check if the block was maliciously mutated by our peer
                    let is_mutated = Consensus::check_merkle_root(&recv_block).is_none()
                        || !recv_block.check_witness_commitment();

                    if is_mutated {
                        error!(
                            "Peer {peer} sent us a mutated block {}",
                            recv_block.block_hash()
                        );
                        self.disconnect_and_ban(peer)?;
                        return Err(WireError::PeerMisbehaving);
                    }

                    block = Some(recv_block);
                    // ask for the proof. Sending two empty bitmaps means we want the full
                    // proof and all leaf data
                    self.send_to_peer(
                        peer,
                        NodeRequest::GetBlockProof((block_hash, Bitmap::new(), Bitmap::new())),
                    )?;
                }

                // STEP 2: Receive the proof and return the `InflightBlock`
                PeerMessages::UtreexoProof(uproof) => {
                    let Some(block) = block else {
                        error!("peer {peer} sent us a proof without sending the block first");
                        self.disconnect_and_ban(peer)?;
                        return Err(WireError::PeerMisbehaving);
                    };

                    let proof = Proof {
                        hashes: uproof.proof_hashes,
                        targets: uproof.targets,
                    };

                    return Ok(InflightBlock {
                        peer,
                        block: Arc::new(block),
                        aux_data: Some((uproof.leaf_data, proof, peer)),
                        processing_since: None,
                    });
                }
                _ => {}
            }
        }
    }

    /// Updates a Stump, with the data from a block and its proof
    fn update_acc(
        &self,
        acc: Stump,
        block: &Block,
        proof: Proof,
        leaf_data: &[CompactLeafData],
        height: u32,
    ) -> Result<Stump, WireError> {
        let (del_hashes, _) = proof_util::process_proof(
            leaf_data,
            &block.txdata,
            height,
            |h| self.chain.get_block_hash(h),
            |h| self.chain.get_mtp_by_height(h),
        )?;

        Ok(self
            .chain
            .update_acc(acc, block, height, proof, del_hashes)?)
    }

    /// Finds the accumulator for one block
    ///
    /// This method will find what the accumulator looks like for a block with (height, hash).
    /// Check-out [this](https://blog.dlsouza.lol/2023/09/28/pow-fraud-proof.html) post
    /// to learn how the cut-and-choose protocol works
    async fn find_accumulator_for_block(
        &mut self,
        height: u32,
        hash: BlockHash,
    ) -> Result<Stump, WireError> {
        let mut candidate_accs = Vec::new();

        match self.find_accumulator_for_block_step(hash, height).await {
            Ok(FindAccResult::Found(acc)) => {
                // everyone agrees. Just parse the accumulator and finish-up
                let acc = Self::parse_acc(&acc)?;
                return Ok(acc);
            }
            Ok(FindAccResult::KeepLooking(mut accs)) => {
                accs.sort();
                accs.dedup();
                candidate_accs = accs;
            }
            _ => {}
        }

        let mut invalid_accs = HashSet::new();
        for peer in candidate_accs.windows(2) {
            if invalid_accs.contains(&peer[0].1) || invalid_accs.contains(&peer[1].1) {
                continue;
            }
            let (peer1, peer2) = (peer[0].0, peer[1].0);

            let liar_state = self.find_who_is_lying(peer1, peer2).await?;

            match liar_state {
                PeerCheck::OneLying(liar) => {
                    self.disconnect_and_ban(liar)?;
                    if liar == peer1 {
                        invalid_accs.insert(peer[0].1.clone());
                        continue;
                    }
                    invalid_accs.insert(peer[1].1.clone());
                }
                PeerCheck::UnresponsivePeer(dead_peer) => {
                    self.disconnect_and_ban(dead_peer)?;
                }
                PeerCheck::BothUnresponsivePeers => {
                    self.disconnect_and_ban(peer1)?;
                    self.disconnect_and_ban(peer2)?;
                }
                PeerCheck::BothLying => {
                    self.disconnect_and_ban(peer1)?;
                    self.disconnect_and_ban(peer2)?;

                    invalid_accs.insert(peer[0].1.clone());
                    invalid_accs.insert(peer[1].1.clone());
                }
            }
        }
        //filter out the invalid accs
        candidate_accs.retain(|acc| !invalid_accs.contains(&acc.1));
        //we should have only one candidate left
        assert_eq!(candidate_accs.len(), 1);

        Self::parse_acc(&candidate_accs.pop().unwrap().1)
    }

    /// If we get an empty `headers` message, our next action depends on which state are
    /// we in:
    ///   - If we are downloading headers for the first time, this means we've just
    ///     finished and should go to the next phase
    ///   - If we are checking with our peer if they have an alternative tip, this peer
    ///     has send all blocks they have. Once all peers have finished, we just pick the
    ///     most PoW chain among all chains that we got
    async fn empty_headers_message(&mut self, peer: PeerId) -> Result<(), WireError> {
        match self.context.state {
            ChainSelectorState::DownloadingHeaders => {
                if self.peer_cannot_serve_headers(peer)? {
                    return self.request_headers(self.chain.get_best_block()?.1);
                }

                info!("Finished downloading headers from peer={peer}, checking if our peers agree");
                self.poke_peers()?;
                self.context.state = ChainSelectorState::LookingForForks(Instant::now());
                self.context.looking_for_forks_first_entered = Some(Instant::now());
                self.context.done_peers.insert(peer);
            }
            ChainSelectorState::LookingForForks(_) => {
                self.context.done_peers.insert(peer);
                self.maybe_finish_looking_for_forks().await?;
            }
            _ => {}
        }

        Ok(())
    }

    /// Whether an empty `headers` from `peer` means it can't serve us headers, rather than
    /// that we reached the end of the chain. Such a peer is disconnected.
    ///
    /// Bitcoin Core answers `getheaders` with an empty `headers` while its own chain has
    /// less than the minimum chain work, i.e. while it's still in IBD, to tell us to go
    /// away. If the peer advertised a height above our tip, the chain doesn't end here.
    /// If it advertised one far below our tip, it's behind us and can't tell us where the
    /// chain ends either. An honest peer at the tip connected during header sync, usually
    /// minutes ago, so it's rarely more than `PEER_BEHIND_MARGIN` blocks behind; if it is,
    /// dropping it costs a reconnect, and the new connection advertises a fresh height.
    /// Manual peers are kept: with only them, ending the download is all we can do.
    fn peer_cannot_serve_headers(&mut self, peer: PeerId) -> Result<bool, WireError> {
        let Some(height) = self.non_manual_peer_height(peer) else {
            return Ok(false);
        };
        let (our_height, _) = self.chain.get_best_block()?;
        if height <= our_height && !Self::is_far_behind(height, our_height) {
            return Ok(false);
        }

        self.drop_peer_that_cannot_serve_headers(peer, height, our_height);
        Ok(true)
    }

    /// The height a peer advertised, unless it's a manual peer, which we never drop.
    fn non_manual_peer_height(&self, peer: PeerId) -> Option<u32> {
        let peer_data = self.peers.get(&peer)?;
        (!peer_data.kind.is_manual()).then_some(peer_data.height)
    }

    fn is_far_behind(peer_height: u32, our_height: u32) -> bool {
        peer_height.saturating_add(ChainSelector::PEER_BEHIND_MARGIN) < our_height
    }

    fn drop_peer_that_cannot_serve_headers(&mut self, peer: PeerId, height: u32, our_height: u32) {
        let Some(idx) = self.peers.get(&peer).map(|p| p.address.id) else {
            return;
        };
        info!(
            "peer={peer} advertised height={height} but sent no headers after ours (height={our_height}); disconnecting it and asking another peer"
        );
        let _ = self.send_to_peer(peer, NodeRequest::Shutdown);
        self.context.done_peers.remove(&peer);
        self.context.tip_cache.remove(&peer);
        if let Err(e) = self.handle_disconnection(peer, idx) {
            warn!("Failed to disconnect peer={peer} that can't serve headers: {e}");
        }

        // `handle_disconnection` records a peer that completed the handshake as a good
        // address; don't come back to one that can't serve headers right away.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_default();
        self.address_man
            .update_set_state(idx, AddressState::Failed(now));
    }

    /// Checks the all-peers-done gate while in `LookingForForks`. If every connected peer
    /// has reported (either via empty headers or by responding with non-extending headers
    /// that were absorbed without advancing our tip), transitions to `Done`, taking the
    /// assume-utreexo or pow-fraud-proofs path as configured.
    async fn maybe_finish_looking_for_forks(&mut self) -> Result<(), WireError> {
        for peer in self.common.peer_ids.iter() {
            // at least one peer haven't finished
            if !self.context.done_peers.contains(peer) {
                return Ok(());
            }
        }

        if let Some(assume_utreexo) = self.common.config.assume_utreexo.clone() {
            let validation_index = self.chain.get_validation_index().unwrap();
            // already assumed the chain
            if validation_index >= assume_utreexo.height {
                self.context.state = ChainSelectorState::Done;
                return Ok(());
            }

            let in_best_chain = self
                .chain
                .get_block_hash(assume_utreexo.height)
                .is_ok_and(|hash| hash == assume_utreexo.block_hash);

            if !in_best_chain {
                let (height, _) = self.chain.get_best_block()?;
                if self.context.assume_utreexo_resumes < ChainSelector::MAX_ASSUME_UTREEXO_RESUMES {
                    self.context.assume_utreexo_resumes += 1;
                    warn!(
                        "assume-utreexo block {} (height={}) is not in our best header chain (tip height={height}); resuming header download ({}/{})",
                        assume_utreexo.block_hash,
                        assume_utreexo.height,
                        self.context.assume_utreexo_resumes,
                        ChainSelector::MAX_ASSUME_UTREEXO_RESUMES,
                    );
                    self.enter_downloading_headers();
                    return self.request_headers(self.chain.get_best_block()?.1);
                }

                error!(
                    "assume-utreexo block {} (height={}) never showed up in our header chain (tip height={height}); validating from genesis without the snapshot",
                    assume_utreexo.block_hash, assume_utreexo.height,
                );
                self.context.state = ChainSelectorState::Done;
                return Ok(());
            }

            self.context.state = ChainSelectorState::Done;
            info!(
                "Assuming chain with height={} tip={}",
                assume_utreexo.height, assume_utreexo.block_hash
            );
            let acc = Stump {
                leaves: assume_utreexo.leaves,
                roots: assume_utreexo.roots,
            };
            self.chain
                .mark_chain_as_assumed(acc, assume_utreexo.block_hash)?;
            return Ok(());
        }

        let has_peers = self
            .peer_by_service
            .contains_key(&service_flags::UTREEXO_ARCHIVE.into());

        if self.config.pow_fraud_proofs && has_peers {
            self.check_tips().await?;
        }

        self.context.state = ChainSelectorState::Done;
        Ok(())
    }

    async fn is_our_chain_invalid(&mut self, other_tip: BlockHash) -> Result<(), WireError> {
        let fork = self.chain.get_fork_point(other_tip)?;
        let fork_height = self.chain.get_block_height(&fork)?.unwrap_or(0);

        let peers = self
            .peer_by_service
            .get(&service_flags::UTREEXO.into())
            .ok_or(WireError::NoPeersAvailable)?;

        let rand_peer = *peers
            .choose(&mut rng())
            .ok_or(WireError::NoPeersAvailable)?;

        let block = self.get_block_and_proof(rand_peer, fork).await?;
        let (leaf_data, proof, _) = block
            .aux_data
            .expect("Block proof and leaf data should be present");

        let (del_hashes, inputs) = proof_util::process_proof(
            &leaf_data,
            &block.block.txdata,
            fork_height,
            |h| self.chain.get_block_hash(h),
            |h| self.chain.get_mtp_by_height(h),
        )?;

        let acc = self.find_accumulator_for_block(fork_height, fork).await?;
        let is_valid = self
            .chain
            .validate_block(&block.block, proof, inputs, del_hashes, acc);

        if is_valid.is_err() {
            let best_block = self.chain.get_best_block()?.1;
            self.ban_peers_on_tip(best_block)?;

            self.chain.switch_chain(other_tip)?;
            self.chain.invalidate_block(fork)?;
            return Ok(());
        }

        // our chain's block is valid, therefore there's no reason for anyone be in this fork
        self.ban_peers_on_tip(other_tip)?;
        Ok(())
    }

    fn ban_peers_on_tip(&mut self, tip: BlockHash) -> Result<(), WireError> {
        for peer in self.common.peers.clone() {
            if self.context.tip_cache.get(&peer.0).copied().eq(&Some(tip)) {
                self.address_man.update_set_state(
                    peer.1.address.id,
                    AddressState::Banned(ChainSelector::BAN_TIME),
                );
                self.disconnect_and_ban(peer.0)?;
            }
        }

        Ok(())
    }

    async fn check_tips(&mut self) -> Result<(), WireError> {
        let (height, _) = self.chain.get_best_block()?;
        let validation_index = self.chain.get_validation_index()?;
        if (validation_index + 100) < height {
            let mut tips = self.chain.get_chain_tips()?;
            let (height, hash) = self.chain.get_best_block()?;
            let acc = self.find_accumulator_for_block(height, hash).await?;

            // only one tip, our peers are following the same chain
            if tips.len() == 1 {
                info!(
                    "Assuming chain with {} blocks",
                    self.chain.get_best_block()?.0
                );

                self.context.state = ChainSelectorState::Done;
                self.chain.mark_chain_as_assumed(acc, tips[0]).unwrap();
            }
            // if we have more than one tip, we need to check if our best chain has an invalid block
            tips.remove(0); // no need to check our best one
            for tip in tips {
                self.is_our_chain_invalid(tip).await?;
            }

            return Ok(());
        }

        info!("chain close enough to tip, not asking for utreexo state");
        self.context.state = ChainSelectorState::Done;
        Ok(())
    }

    /// Ask for headers, given a tip
    ///
    /// This function will send a `getheaders` request to our peers, assuming this
    /// peer is following a chain with `tip` inside it. We use this in case some of
    /// our peer is in a fork, so we can learn about all blocks in that fork and
    /// compare the candidate chains to pick the best one.
    fn request_headers(&mut self, tip: BlockHash) -> Result<(), WireError> {
        // A `tip` we don't have (from headers that failed to validate) has no locator. An
        // empty one gets an empty `headers` from some peers, which would end the download.
        let locator = match self.chain.get_block_locator_for_tip(tip) {
            Ok(locator) => locator,
            Err(_) => self.chain.get_block_locator()?,
        };

        let peer = self.send_to_fast_peer(NodeRequest::GetHeaders(locator), ServiceFlags::NONE)?;

        self.inflight
            .insert(InflightRequests::Headers, (peer, Instant::now()));

        Ok(())
    }

    /// Sends a `getheaders` to all our peers
    ///
    /// After we download all blocks from one peer, we ask our peers if they
    /// agree with our sync peer on what is the best chain. If they are in a fork,
    /// we'll download that fork and compare with our own chain. We should always pick
    /// the most PoW one.
    fn poke_peers(&self) -> Result<(), WireError> {
        let locator = self.chain.get_block_locator().unwrap();
        for peer in self.common.peer_ids.iter() {
            let get_headers = NodeRequest::GetHeaders(locator.clone());
            self.send_to_peer(*peer, get_headers)?;
        }

        Ok(())
    }

    pub async fn run(&mut self) -> Result<(), WireError> {
        info!("Starting IBD, selecting the best chain");

        let mut ticker = time::interval(ChainSelector::MAINTENANCE_TICK);
        // If we fall behind, don't "catch up" by running maintenance repeatedly
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                biased;

                // Maintenance runs only on tick but has priority
                _ = ticker.tick() => match self.maintenance_tick().await? {
                    LoopControl::Continue => {},
                    LoopControl::Break => break,
                },

                // Handle messages as soon as we find any, otherwise sleep until maintenance
                msg = self.node_rx.recv() => {
                    let Some(notification) = msg else {
                        break;
                    };
                    try_and_log!(self.handle_notification(notification).await);

                    // Drain all queued messages
                    while let Ok(notification) = self.node_rx.try_recv() {
                        try_and_log!(self.handle_notification(notification).await);
                    }
                }
            }
        }

        Ok(())
    }

    /// Whether we have enough peers to start downloading headers
    fn can_start_headers_sync(&self) -> bool {
        let connected_peers = self.connected_peers();
        if self.network == Network::Regtest && connected_peers >= 1 {
            return true;
        }

        if self.has_fixed_peers() {
            return connected_peers >= 1;
        }

        connected_peers >= ChainSelector::MAX_OUTGOING_PEERS
    }

    /// Re-requests headers when the download made no progress for `REQUEST_TIMEOUT`, or
    /// ends it when peers only keep sending headers we already have.
    async fn check_header_stall(&mut self) -> Result<(), WireError> {
        let elapsed = self.last_tip_update.elapsed().as_secs();
        let should_request = elapsed > ChainSelector::REQUEST_TIMEOUT
            && !self.inflight.contains_key(&InflightRequests::Headers);

        if should_request {
            let (height, _) = self.chain.get_best_block()?;
            if self.peers_only_send_known_headers() {
                let peer = self.context.known_batch_since_stall_check.take();
                if let Some(peer) = peer.filter(|p| self.peers.contains_key(p)) {
                    // A peer behind our stored headers (e.g. the only `--connect`
                    // peer after a restart) answers every request with headers we
                    // have. Without this the download would wait for it forever.
                    info!(
                        "Peers only sent headers we already have for {} stall checks at height={height}; treating it as the end of their chain",
                        ChainSelector::MAX_STALLS_WITH_ONLY_KNOWN_BATCHES
                    );
                    self.empty_headers_message(peer).await?;
                    return Ok(());
                }
            }

            info!(
                "Header IBD stalled for {elapsed}s at height={height}; re-requesting from a fresh peer"
            );
            self.request_headers(self.chain.get_best_block()?.1)?;
        }

        Ok(())
    }

    /// Performs the periodic maintenance tasks, including checking for the cancel signal, peer
    /// connections, and inflight request timeouts.
    ///
    /// Returns `LoopControl::Break` if we need to break the main `ChainSelector` loop, either
    /// because the kill signal was set or because the header chain is synced.
    async fn maintenance_tick(&mut self) -> Result<LoopControl, WireError> {
        if *self.kill_signal.read().await {
            return Ok(LoopControl::Break);
        }

        // Checks if we need to open a new connection
        periodic_job!(
            self.last_connection => self.maybe_open_connection(ServiceFlags::NONE),
            ChainSelector::TRY_NEW_CONNECTION,
            no_log,
        );

        // Open new feeler connection periodically
        periodic_job!(
            self.last_feeler => self.open_feeler_connection(),
            ChainSelector::FEELER_INTERVAL,
            no_log,
        );

        if let ChainSelectorState::LookingForForks(start) = self.context.state {
            if start.elapsed().as_secs() > ChainSelector::REQUEST_TIMEOUT {
                self.context.state = ChainSelectorState::LookingForForks(Instant::now());
                self.poke_peers()?;
            }

            // Watchdog: poke_peers is fire-and-forget (no inflight tracking), so a peer
            // with a half-open connection or one that ignores our locator never trips
            // check_for_timeout and is never added to done_peers. After enough poke
            // rounds, treat any silent peer as done so the gate can close.
            if let Some(first) = self.context.looking_for_forks_first_entered {
                let elapsed = first.elapsed().as_secs();
                if elapsed > ChainSelector::LOOKING_FOR_FORKS_MAX_WAIT {
                    let pending: Vec<PeerId> = self
                        .common
                        .peer_ids
                        .iter()
                        .filter(|p| !self.context.done_peers.contains(p))
                        .copied()
                        .collect();
                    if !pending.is_empty() {
                        warn!(
                            "ChainSelector: {} peers silent for {elapsed}s in LookingForForks; forcing done: {:?}",
                            pending.len(),
                            pending,
                        );
                        for p in pending {
                            self.context.done_peers.insert(p);
                        }
                        self.maybe_finish_looking_for_forks().await?;
                    }
                }
            }
        }

        if let ChainSelectorState::DownloadingHeaders = self.context.state {
            try_and_log!(self.check_header_stall().await);
        }

        if self.context.state == ChainSelectorState::CreatingConnections {
            // If we have enough peers, try to download headers
            if self.can_start_headers_sync() {
                try_and_log!(self.request_headers(self.chain.get_best_block()?.1));
                self.context.state = ChainSelectorState::DownloadingHeaders;
            }
        }

        // We downloaded all headers in the most-pow chain, and all our peers agree
        // this is the most-pow chain, we're done!
        if self.context.state == ChainSelectorState::Done {
            let (height, hash) = self.chain.get_best_block()?;
            info!("ChainSelector done: tip height={height} hash={hash}");
            self.chain.update_ibd(IBDState::ProofSync);
            try_and_log!(self.chain.flush());
            return Ok(LoopControl::Break);
        }

        try_and_log!(self.check_for_timeout());

        Ok(LoopControl::Continue)
    }

    async fn find_accumulator_for_block_step(
        &mut self,
        block: BlockHash,
        height: u32,
    ) -> Result<FindAccResult, WireError> {
        for peer_id in self.common.peer_ids.iter() {
            let peer = self.peers.get(peer_id).unwrap();
            if peer.services.has(service_flags::UTREEXO_ARCHIVE.into()) {
                self.send_to_peer(*peer_id, NodeRequest::GetUtreexoState((block, height)))?;
                self.common.inflight.insert(
                    InflightRequests::UtreexoState(*peer_id),
                    (*peer_id, Instant::now()),
                );
            }
        }

        if self.inflight.is_empty() {
            return Err(WireError::NoPeersAvailable);
        }

        let mut peer_accs = Vec::new();
        loop {
            // wait for all peers to respond or timeout after 1 minute
            if self.inflight.is_empty() {
                break;
            }

            if let Ok(Some(message)) = timeout(Duration::from_secs(60), self.node_rx.recv()).await {
                match message {
                    NodeNotification::DnsSeedAddresses(addresses) => {
                        self.address_man.push_addresses(&addresses);
                    }

                    NodeNotification::FromPeer(peer, message, _) => {
                        if let PeerMessages::UtreexoState(state) = message {
                            self.inflight.remove(&InflightRequests::UtreexoState(peer));
                            info!("got state {state:?}");
                            peer_accs.push((peer, state));
                        }
                    }

                    NodeNotification::FromUser(request, responder) => {
                        self.perform_user_request(request, responder).await;
                    }

                    msg @ NodeNotification::FromWorker { .. } => {
                        error!("Received a notification from the worker thread {msg:?}");
                    }
                }
            }

            for inflight in self.inflight.clone().iter() {
                if inflight.1.1.elapsed().as_secs() > 60 {
                    self.inflight.remove(inflight.0);
                }
            }
        }

        if peer_accs.len() == 1 {
            warn!("Only one peers with the UTREEXO_FILTER service flag");
            return Ok(FindAccResult::Found(peer_accs.pop().unwrap().1));
        }

        let mut accs = HashSet::new();
        for (_, acc) in peer_accs.iter() {
            accs.insert(acc);
        }

        // if all peers have the same state, we can assume it's the correct one
        if accs.len() == 1 {
            return Ok(FindAccResult::Found(peer_accs.pop().unwrap().1));
        }

        // if we have different states, we need to keep looking until we find the
        // fork point
        Ok(FindAccResult::KeepLooking(peer_accs))
    }

    async fn handle_notification(
        &mut self,
        notification: NodeNotification,
    ) -> Result<(), WireError> {
        match notification {
            NodeNotification::FromUser(request, responder) => {
                self.perform_user_request(request, responder).await;
            }

            NodeNotification::FromPeer(peer, notification, time) => {
                self.handle_peer_notification(notification, peer, time)
                    .await?;
            }

            NodeNotification::DnsSeedAddresses(addresses) => {
                self.address_man.push_addresses(&addresses);
            }

            msg @ NodeNotification::FromWorker { .. } => {
                error!("Received a notification from the worker thread {msg:?}");
            }
        }
        Ok(())
    }

    async fn handle_peer_notification(
        &mut self,
        notification: PeerMessages,
        peer: PeerId,
        time: Instant,
    ) -> Result<(), WireError> {
        self.register_message_time(&notification, peer, time);

        let Some(unhandled) = self.handle_peer_msg_common(notification, peer)? else {
            return Ok(());
        };

        match unhandled {
            PeerMessages::Headers(headers) => {
                self.inflight.remove(&InflightRequests::Headers);
                return self.handle_headers(peer, headers).await;
            }

            PeerMessages::Ready(version) => {
                self.handle_peer_ready(peer, version)?;
                if matches!(self.context.state, ChainSelectorState::LookingForForks(_)) {
                    let locator = self.chain.get_block_locator().unwrap();
                    self.send_to_peer(peer, NodeRequest::GetHeaders(locator))?;
                }
            }

            PeerMessages::Disconnected(idx) => {
                if self.peers.is_empty() {
                    self.context.state = ChainSelectorState::CreatingConnections;
                }
                // PeerId is reusable across reconnections, so drop any per-peer ChainSelector
                // state to keep a fresh peer from inheriting a stale "done" mark or alt-tip.
                self.context.done_peers.remove(&peer);
                self.context.tip_cache.remove(&peer);
                self.handle_disconnection(peer, idx)?;
            }

            // During chain selection we don't ask for blocks, unless it's an explicit
            // user request made through the node handle. If it isn't, we punish this
            // peer for sending an unrequested block.
            PeerMessages::Block(block) => {
                let block = self.check_is_user_block_and_reply(block)?;

                if block.is_some() {
                    error!("peer {peer} sent us a block we didn't request");
                    self.increase_banscore(peer, 5)?;
                }
            }

            _ => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use floresta_chain::AssumeUtreexoValue;
    use floresta_chain::BlockchainInterface;
    use floresta_chain::ChainState;
    use floresta_chain::FlatChainStore;
    use rustreexo::node_hash::BitcoinNodeHash;

    use super::*;
    use crate::node::ConnectionKind;
    use crate::node::PeerStatus;
    use crate::p2p_wire::tests::utils::PeerData;
    use crate::p2p_wire::tests::utils::SetupNodeArgs;
    use crate::p2p_wire::tests::utils::setup_node;
    use crate::p2p_wire::tests::utils::signet_blocks;
    use crate::p2p_wire::tests::utils::signet_headers;
    use crate::p2p_wire::tests::utils::signet_roots;

    type TestNode = UtreexoNode<Arc<ChainState<FlatChainStore>>, ChainSelector>;

    const KNOWN_HEADERS: usize = 60;

    fn header_sync_node() -> (TestNode, Vec<bitcoin::block::Header>) {
        header_sync_node_with(KNOWN_HEADERS)
    }

    /// A `ChainSelector` with signet headers up to `known_headers` and two simulated peers
    /// that never get their messages processed, so each test drives the handlers by hand.
    fn header_sync_node_with(known_headers: usize) -> (TestNode, Vec<bitcoin::block::Header>) {
        let headers = signet_headers();
        let peers = vec![
            PeerData::new(headers.clone(), signet_blocks(), signet_roots()),
            PeerData::new(headers.clone(), signet_blocks(), signet_roots()),
        ];
        let datadir = format!("./tmp-db/{}.chain_selector_ctx", rand::random::<u32>());
        let args = SetupNodeArgs::new(peers, false, Network::Signet, datadir, known_headers);
        let mut node = setup_node::<ChainSelector>(args);
        node.peer_ids = vec![0, 1];
        for peer in node.peers.values_mut() {
            peer.message_times.add(1.0);
        }
        (node, headers)
    }

    fn assume_utreexo_at(headers: &[bitcoin::block::Header], height: usize) -> AssumeUtreexoValue {
        AssumeUtreexoValue {
            block_hash: headers[height].block_hash(),
            height: height as u32,
            roots: Vec::new(),
            leaves: 0,
        }
    }

    #[tokio::test]
    async fn headers_that_extend_our_tip_while_looking_for_forks_resume_the_download() {
        let (mut node, headers) = header_sync_node();
        node.context.state = ChainSelectorState::LookingForForks(Instant::now());
        node.context.done_peers.insert(1);

        node.handle_headers(0, headers[KNOWN_HEADERS + 1..=KNOWN_HEADERS + 20].to_vec())
            .await
            .unwrap();

        assert_eq!(node.context.state, ChainSelectorState::DownloadingHeaders);
        assert!(node.context.done_peers.is_empty());
        assert!(node.inflight.contains_key(&InflightRequests::Headers));
        assert_eq!(
            node.chain.get_best_block().unwrap().0,
            KNOWN_HEADERS as u32 + 20
        );
    }

    #[tokio::test]
    async fn headers_we_already_had_while_looking_for_forks_mark_the_peer_done() {
        let (mut node, headers) = header_sync_node();
        node.context.state = ChainSelectorState::LookingForForks(Instant::now());

        node.handle_headers(0, headers[1..=20].to_vec())
            .await
            .unwrap();

        assert!(matches!(
            node.context.state,
            ChainSelectorState::LookingForForks(_)
        ));
        assert!(node.context.done_peers.contains(&0));
        assert!(!node.inflight.contains_key(&InflightRequests::Headers));
    }

    #[tokio::test]
    async fn a_manual_peer_behind_us_ends_the_download_after_three_stall_checks() {
        let (mut node, headers) = header_sync_node();
        node.context.state = ChainSelectorState::DownloadingHeaders;
        node.peers.get_mut(&0).unwrap().kind = ConnectionKind::Manual;
        let stalled = Instant::now() - Duration::from_secs(ChainSelector::REQUEST_TIMEOUT + 1);

        for check in 1..=ChainSelector::MAX_STALLS_WITH_ONLY_KNOWN_BATCHES {
            node.handle_headers(0, headers[1..=20].to_vec())
                .await
                .unwrap();
            node.last_tip_update = stalled;
            node.inflight.remove(&InflightRequests::Headers);
            node.check_header_stall().await.unwrap();

            if check < ChainSelector::MAX_STALLS_WITH_ONLY_KNOWN_BATCHES {
                assert_eq!(node.context.state, ChainSelectorState::DownloadingHeaders);
            }
        }

        assert!(matches!(
            node.context.state,
            ChainSelectorState::LookingForForks(_)
        ));
    }

    #[tokio::test]
    async fn a_stall_where_nobody_answers_does_not_end_the_download() {
        let (mut node, _) = header_sync_node();
        node.context.state = ChainSelectorState::DownloadingHeaders;
        let stalled = Instant::now() - Duration::from_secs(ChainSelector::REQUEST_TIMEOUT + 1);

        for _ in 0..=ChainSelector::MAX_STALLS_WITH_ONLY_KNOWN_BATCHES {
            node.last_tip_update = stalled;
            node.inflight.remove(&InflightRequests::Headers);
            node.check_header_stall().await.unwrap();
        }

        assert_eq!(node.context.state, ChainSelectorState::DownloadingHeaders);
        assert!(node.inflight.contains_key(&InflightRequests::Headers));
    }

    #[tokio::test]
    async fn a_batch_we_already_had_does_not_start_a_parallel_download() {
        let (mut node, headers) = header_sync_node();
        node.context.state = ChainSelectorState::DownloadingHeaders;

        node.handle_headers(0, headers[1..=KNOWN_HEADERS].to_vec())
            .await
            .unwrap();
        assert_eq!(node.context.state, ChainSelectorState::DownloadingHeaders);
        assert!(!node.inflight.contains_key(&InflightRequests::Headers));

        node.handle_headers(1, headers[KNOWN_HEADERS + 1..=KNOWN_HEADERS + 10].to_vec())
            .await
            .unwrap();
        assert!(node.inflight.contains_key(&InflightRequests::Headers));
    }

    #[tokio::test]
    async fn an_announcement_we_already_had_does_not_end_the_download() {
        let (mut node, headers) = header_sync_node();
        node.context.state = ChainSelectorState::DownloadingHeaders;
        node.peers.get_mut(&0).unwrap().kind = ConnectionKind::Manual;

        node.handle_headers(0, vec![headers[KNOWN_HEADERS]])
            .await
            .unwrap();

        assert_eq!(node.context.state, ChainSelectorState::DownloadingHeaders);
        assert!(node.context.done_peers.is_empty());
        assert!(node.peers.contains_key(&0));
    }

    #[tokio::test]
    async fn a_batch_we_already_had_from_a_peer_far_behind_us_drops_it() {
        let (mut node, headers) = header_sync_node_with(1_000);
        node.context.state = ChainSelectorState::DownloadingHeaders;
        node.peers.get_mut(&0).unwrap().height = 1_000 - ChainSelector::PEER_BEHIND_MARGIN - 1;

        node.handle_headers(0, headers[1..=100].to_vec())
            .await
            .unwrap();

        assert_eq!(node.context.state, ChainSelectorState::DownloadingHeaders);
        assert!(!node.peers.contains_key(&0));
        assert_eq!(
            node.inflight.get(&InflightRequests::Headers).map(|r| r.0),
            Some(1)
        );
    }

    #[tokio::test]
    async fn the_resume_budget_refills_when_headers_make_progress() {
        let (mut node, headers) = header_sync_node();
        node.config.assume_utreexo = Some(assume_utreexo_at(&headers, KNOWN_HEADERS + 50));
        node.context.assume_utreexo_resumes = ChainSelector::MAX_ASSUME_UTREEXO_RESUMES;
        node.context.state = ChainSelectorState::DownloadingHeaders;

        node.handle_headers(0, headers[KNOWN_HEADERS + 1..=KNOWN_HEADERS + 20].to_vec())
            .await
            .unwrap();

        assert_eq!(node.context.assume_utreexo_resumes, 0);
    }

    #[tokio::test]
    async fn header_phase_assumes_the_snapshot_once_its_block_is_in_the_best_chain() {
        let (mut node, headers) = header_sync_node();
        node.config.assume_utreexo = Some(assume_utreexo_at(&headers, KNOWN_HEADERS));
        node.context.state = ChainSelectorState::LookingForForks(Instant::now());
        node.context.done_peers.extend([0, 1]);

        node.maybe_finish_looking_for_forks().await.unwrap();

        assert_eq!(node.context.state, ChainSelectorState::Done);
        assert_eq!(
            node.chain.get_validation_index().unwrap(),
            KNOWN_HEADERS as u32
        );
    }

    #[tokio::test]
    async fn headers_that_do_not_connect_are_ignored_without_a_ban_or_follow_up() {
        let (mut node, headers) = header_sync_node();
        node.context.state = ChainSelectorState::DownloadingHeaders;

        node.handle_headers(0, vec![headers[KNOWN_HEADERS + 10]])
            .await
            .unwrap();

        assert_eq!(node.context.state, ChainSelectorState::DownloadingHeaders);
        assert!(!node.inflight.contains_key(&InflightRequests::Headers));
        assert_eq!(node.peers[&0].state, PeerStatus::Ready);
        assert!(!node.context.tip_cache.contains_key(&0));
    }

    #[tokio::test]
    async fn empty_headers_from_a_peer_that_claims_more_blocks_drop_it_and_keep_downloading() {
        let (mut node, _) = header_sync_node();
        node.context.state = ChainSelectorState::DownloadingHeaders;
        node.peers.get_mut(&0).unwrap().height = KNOWN_HEADERS as u32 + 1_000;

        node.empty_headers_message(0).await.unwrap();

        assert_eq!(node.context.state, ChainSelectorState::DownloadingHeaders);
        assert!(!node.peers.contains_key(&0));
        assert_eq!(
            node.inflight.get(&InflightRequests::Headers).map(|r| r.0),
            Some(1)
        );
    }

    #[tokio::test]
    async fn empty_headers_from_a_peer_far_behind_us_drop_it_and_keep_downloading() {
        let (mut node, _) = header_sync_node_with(1_000);
        node.context.state = ChainSelectorState::DownloadingHeaders;
        node.peers.get_mut(&0).unwrap().height = 1_000 - ChainSelector::PEER_BEHIND_MARGIN - 1;

        node.empty_headers_message(0).await.unwrap();

        assert_eq!(node.context.state, ChainSelectorState::DownloadingHeaders);
        assert!(!node.peers.contains_key(&0));
    }

    #[tokio::test]
    async fn empty_headers_from_a_manual_peer_end_the_download() {
        let (mut node, _) = header_sync_node();
        node.context.state = ChainSelectorState::DownloadingHeaders;
        let peer = node.peers.get_mut(&0).unwrap();
        peer.height = KNOWN_HEADERS as u32 + 1_000;
        peer.kind = ConnectionKind::Manual;

        node.empty_headers_message(0).await.unwrap();

        assert!(matches!(
            node.context.state,
            ChainSelectorState::LookingForForks(_)
        ));
        assert!(node.peers.contains_key(&0));
    }

    #[tokio::test]
    async fn empty_headers_from_a_peer_at_our_height_end_the_download() {
        let (mut node, _) = header_sync_node();
        node.context.state = ChainSelectorState::DownloadingHeaders;
        node.peers.get_mut(&0).unwrap().height = KNOWN_HEADERS as u32;

        node.empty_headers_message(0).await.unwrap();

        assert!(matches!(
            node.context.state,
            ChainSelectorState::LookingForForks(_)
        ));
        assert!(node.peers.contains_key(&0));
    }

    #[tokio::test]
    async fn header_phase_does_not_finish_without_the_assume_utreexo_block() {
        let (mut node, headers) = header_sync_node();
        node.config.assume_utreexo = Some(assume_utreexo_at(&headers, KNOWN_HEADERS + 50));
        node.context.state = ChainSelectorState::LookingForForks(Instant::now());
        node.context.done_peers.insert(1);

        node.empty_headers_message(0).await.unwrap();

        assert_eq!(node.context.state, ChainSelectorState::DownloadingHeaders);
        assert!(node.context.done_peers.is_empty());
        assert!(node.inflight.contains_key(&InflightRequests::Headers));
    }

    #[tokio::test]
    async fn header_phase_gives_up_on_an_assume_utreexo_block_no_peer_has() {
        let (mut node, headers) = header_sync_node();
        node.config.assume_utreexo = Some(assume_utreexo_at(&headers, KNOWN_HEADERS + 50));

        for _ in 0..ChainSelector::MAX_ASSUME_UTREEXO_RESUMES {
            node.context.state = ChainSelectorState::LookingForForks(Instant::now());
            node.context.done_peers.extend([0, 1]);
            node.maybe_finish_looking_for_forks().await.unwrap();
            assert_eq!(node.context.state, ChainSelectorState::DownloadingHeaders);
        }

        node.context.state = ChainSelectorState::LookingForForks(Instant::now());
        node.context.done_peers.extend([0, 1]);
        node.maybe_finish_looking_for_forks().await.unwrap();
        assert_eq!(node.context.state, ChainSelectorState::Done);
    }

    fn parse_acc(acc: &[u8]) -> Result<Stump, WireError> {
        TestNode::parse_acc(acc)
    }

    fn serialize_acc(leaves: u64, root_count: usize) -> Vec<u8> {
        let mut acc = leaves.to_le_bytes().to_vec();
        acc.extend(std::iter::repeat_n(0u8, 32 * root_count));
        acc
    }

    #[test]
    fn test_parse_acc() {
        let empty_wire = &[] as &[u8];
        let empty_stump = parse_acc(empty_wire).expect("empty wire should parse");
        assert_eq!(empty_stump, Stump::default());

        let zero_leaves_wire = [0u8; 8];
        let zero_leaves_stump =
            parse_acc(&zero_leaves_wire).expect("zero-leaves wire should parse");
        assert_eq!(zero_leaves_stump, Stump::default());

        let header_truncated_min_wire = vec![0u8; 1];
        let header_truncated_min = parse_acc(&header_truncated_min_wire);
        assert!(matches!(
            header_truncated_min,
            Err(WireError::PeerMisbehaving)
        ));

        let header_truncated_max_wire = vec![0u8; 7];
        let header_truncated_max = parse_acc(&header_truncated_max_wire);
        assert!(matches!(
            header_truncated_max,
            Err(WireError::PeerMisbehaving)
        ));

        let roots_missing_wire = 1u64.to_le_bytes().to_vec();
        let roots_missing = parse_acc(&roots_missing_wire);
        assert!(matches!(roots_missing, Err(WireError::PeerMisbehaving)));

        let mut roots_one_byte_short_wire = 1u64.to_le_bytes().to_vec();
        roots_one_byte_short_wire.extend([0u8; 31]);
        let roots_one_byte_short = parse_acc(&roots_one_byte_short_wire);
        assert!(matches!(
            roots_one_byte_short,
            Err(WireError::PeerMisbehaving)
        ));

        let roots_excess_count_wire = serialize_acc(8, 2);
        let roots_excess_count = parse_acc(&roots_excess_count_wire);
        assert!(matches!(
            roots_excess_count,
            Err(WireError::PeerMisbehaving)
        ));

        let mut roots_trailing_byte_wire = serialize_acc(1, 1);
        roots_trailing_byte_wire.push(0);
        let roots_trailing_byte = parse_acc(&roots_trailing_byte_wire);
        assert!(matches!(
            roots_trailing_byte,
            Err(WireError::PeerMisbehaving)
        ));

        let leaves_8_one_root_wire = serialize_acc(8, 1);
        let leaves_8_one_root_stump =
            parse_acc(&leaves_8_one_root_wire).expect("leaves=8 one-root wire should parse");
        assert_eq!(
            leaves_8_one_root_stump,
            Stump {
                leaves: 8,
                roots: vec![BitcoinNodeHash::from([0u8; 32])],
            },
        );

        let mut leaves_1_nonzero_root_wire = 1u64.to_le_bytes().to_vec();
        leaves_1_nonzero_root_wire.extend([1u8; 32]);
        let leaves_1_nonzero_root_stump = parse_acc(&leaves_1_nonzero_root_wire)
            .expect("leaves=1 nonzero root wire should parse");
        assert_eq!(
            leaves_1_nonzero_root_stump,
            Stump {
                leaves: 1,
                roots: vec![BitcoinNodeHash::from([1u8; 32])],
            },
        );

        let leaves_3_two_roots_wire = serialize_acc(3, 2);
        let leaves_3_two_roots_stump =
            parse_acc(&leaves_3_two_roots_wire).expect("leaves=3 two-root wire should parse");
        assert_eq!(
            leaves_3_two_roots_stump,
            Stump {
                leaves: 3,
                roots: vec![
                    BitcoinNodeHash::from([0u8; 32]),
                    BitcoinNodeHash::from([0u8; 32]),
                ],
            },
        );
    }
}
