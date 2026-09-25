// SPDX-License-Identifier: MIT OR Apache-2.0

//! Which peer a request goes to: peers that cannot have what we ask for (a bridge stuck
//! behind the block we need a proof for) are avoided, and a peer that lets a request time
//! out stops looking fast.

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;
    use std::time::Instant;

    use bitcoin::BlockHash;
    use bitcoin::Network;
    use bitcoin::hashes::Hash;
    use bitcoin::p2p::ServiceFlags;
    use floresta_chain::AssumeValidArg;
    use floresta_chain::ChainState;
    use floresta_chain::FlatChainStore;
    use floresta_chain::FlatChainStoreConfig;
    use floresta_chain::pruned_utreexo::UpdatableChainstate;
    use floresta_common::Ema;
    use floresta_common::service_flags;
    use floresta_mempool::Mempool;
    use tokio::sync::Mutex;
    use tokio::sync::RwLock;
    use tokio::sync::mpsc::UnboundedReceiver;
    use tokio::sync::mpsc::unbounded_channel;

    use crate::address_man::AddressMan;
    use crate::node::ConnectionKind;
    use crate::node::InflightRequests;
    use crate::node::LocalPeerView;
    use crate::node::NodeNotification;
    use crate::node::NodeRequest;
    use crate::node::PeerStatus;
    use crate::node::UtreexoNode;
    use crate::node::running_ctx::RunningNode;
    use crate::node::sync_ctx::SyncNode;
    use crate::node_context::NodeContext;
    use crate::p2p_wire::peer::PeerMessages;
    use crate::p2p_wire::peer::Version;
    use crate::p2p_wire::tests::utils::get_node_config;
    use crate::p2p_wire::tests::utils::signet_headers;
    use crate::p2p_wire::transport::TransportProtocol;

    type TestChain = Arc<ChainState<FlatChainStore>>;
    type TestNode = UtreexoNode<TestChain, SyncNode>;

    /// A node whose peers never run: requests pile up in each peer's channel, which is all
    /// these tests look at.
    fn idle_node<Context: NodeContext + Default + 'static>(
        datadir: &str,
    ) -> UtreexoNode<TestChain, Context> {
        let config = FlatChainStoreConfig::new(datadir);
        let chainstore = FlatChainStore::new(config).unwrap();
        let chain =
            ChainState::open(chainstore, Network::Signet, AssumeValidArg::Disabled).unwrap();

        UtreexoNode::new(
            get_node_config(datadir, Network::Signet, false),
            Arc::new(chain),
            Arc::new(Mutex::new(Mempool::new(1000))),
            Arc::new(RwLock::new(false)),
            AddressMan::new(None, &[]),
        )
        .unwrap()
    }

    /// Adds a ready utreexo peer that reported `height` and answered its handshake in
    /// `latency_ms`. Returns the receiving end of its request channel.
    fn add_peer<Context: NodeContext + Default + 'static>(
        node: &mut UtreexoNode<TestChain, Context>,
        id: u32,
        height: u32,
        latency_ms: f64,
    ) -> UnboundedReceiver<NodeRequest> {
        let (sender, receiver) = unbounded_channel();
        let services = ServiceFlags::NETWORK | service_flags::UTREEXO.into();
        let mut message_times = Ema::with_half_life_50();
        message_times.add(latency_ms);

        node.peers.insert(
            id,
            LocalPeerView {
                message_times,
                address: "127.0.0.1:8333".parse().unwrap(),
                services,
                user_agent: "/test/".to_string(),
                height,
                time_offset: 0,
                state: PeerStatus::Ready,
                channel: sender,
                kind: ConnectionKind::Regular(services),
                banscore: 0,
                _last_message: Instant::now(),
                transport_protocol: TransportProtocol::V2,
            },
        );
        for service in [service_flags::UTREEXO.into(), ServiceFlags::NETWORK] {
            node.peer_by_service.entry(service).or_default().push(id);
        }

        receiver
    }

    fn proof_request(hash: BlockHash) -> NodeRequest {
        NodeRequest::GetBlockProof((hash, Default::default(), Default::default()))
    }

    #[tokio::test]
    async fn peers_behind_the_requested_height_are_avoided() {
        let datadir = format!("./tmp-db/{}.peer_choice", rand::random::<u32>());
        let mut node: TestNode = idle_node(&datadir);

        // The stale bridge is by far the fastest peer: latency alone would pick it almost
        // every time.
        let mut stale_bridge = add_peer(&mut node, 1, 966_452, 10.0);
        let mut current_bridge = add_peer(&mut node, 2, 968_570, 1_000.0);

        let hash = BlockHash::all_zeros();
        for _ in 0..100 {
            let peer = node
                .send_to_fast_peer_at_height(
                    proof_request(hash),
                    service_flags::UTREEXO.into(),
                    Some(967_900),
                )
                .unwrap();
            assert_eq!(peer, 2, "a peer behind the block cannot serve its proof");
        }
        assert!(stale_bridge.try_recv().is_err());
        assert!(current_bridge.try_recv().is_ok());

        // A freshly mined block: nobody is known to have it yet, but the bridge that had the
        // tip when it connected is a far better bet than one 2,000 blocks behind.
        for _ in 0..100 {
            let peer = node
                .send_to_fast_peer_at_height(
                    proof_request(hash),
                    service_flags::UTREEXO.into(),
                    Some(968_600),
                )
                .unwrap();
            assert_eq!(
                peer, 2,
                "a peer that was recently at the tip is asked first"
            );
        }

        // With nobody anywhere near the block, any utreexo peer may be asked.
        let picked = (0..100)
            .map(|_| {
                node.send_to_fast_peer_at_height(
                    proof_request(hash),
                    service_flags::UTREEXO.into(),
                    Some(1_000_000),
                )
                .unwrap()
            })
            .collect::<std::collections::HashSet<_>>();
        assert!(picked.contains(&1), "the last resort still uses every peer");
    }

    #[tokio::test]
    async fn served_and_announced_blocks_raise_the_peer_height() {
        let datadir = format!("./tmp-db/{}.peer_choice", rand::random::<u32>());
        let mut node: TestNode = idle_node(&datadir);
        let _channel = add_peer(&mut node, 1, 100, 10.0);

        node.note_peer_height(1, 150);
        assert_eq!(node.peers[&1].height, 150);

        // Heights never go back: a peer that served block 150 has it whatever its
        // handshake said.
        node.note_peer_height(1, 120);
        assert_eq!(node.peers[&1].height, 150);
    }

    fn version(peer: u32, blocks: u32) -> Version {
        let services = ServiceFlags::NETWORK | service_flags::UTREEXO.into();
        Version {
            user_agent: "/test/".to_string(),
            protocol_version: 70016,
            blocks,
            id: peer,
            address_id: 0,
            services,
            time_offset: 0,
            kind: ConnectionKind::Regular(services),
            transport_protocol: TransportProtocol::V2,
        }
    }

    async fn deliver(
        node: &mut UtreexoNode<TestChain, RunningNode>,
        peer: u32,
        message: PeerMessages,
    ) {
        node.handle_notification(NodeNotification::FromPeer(peer, message, Instant::now()))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_header_that_becomes_the_tip_gets_its_block_requested() {
        let datadir = format!("./tmp-db/{}.running_node", rand::random::<u32>());
        let mut node: UtreexoNode<TestChain, RunningNode> = idle_node(&datadir);
        let headers = signet_headers();
        for header in &headers[1..=3] {
            node.chain.accept_header(*header).unwrap();
        }
        let mut peer = add_peer(&mut node, 1, 3, 10.0);

        deliver(&mut node, 1, PeerMessages::Headers(vec![headers[4]])).await;

        let block = headers[4].block_hash();
        match peer.try_recv() {
            Ok(NodeRequest::GetBlock(hashes)) => assert_eq!(hashes, vec![block]),
            other => panic!("expected the block to be requested, got {other:?}"),
        }
        assert!(node.inflight.contains_key(&InflightRequests::Blocks(block)));
        assert_eq!(
            node.peers[&1].height, 4,
            "the peer has the block it announced"
        );

        // The same header again is not a new tip: nothing more is requested
        deliver(&mut node, 1, PeerMessages::Headers(vec![headers[4]])).await;
        assert!(peer.try_recv().is_err());
    }

    #[tokio::test]
    async fn a_peer_with_more_blocks_than_us_is_asked_for_headers() {
        let datadir = format!("./tmp-db/{}.running_node", rand::random::<u32>());
        let mut node: UtreexoNode<TestChain, RunningNode> = idle_node(&datadir);
        let headers = signet_headers();
        for header in &headers[1..=3] {
            node.chain.accept_header(*header).unwrap();
        }
        let mut behind = add_peer(&mut node, 1, 0, 10.0);
        let mut ahead = add_peer(&mut node, 2, 0, 10.0);

        // The handshake sends housekeeping requests of its own; only headers matter here
        fn asked_for_headers(channel: &mut UnboundedReceiver<NodeRequest>) -> bool {
            let mut asked = false;
            while let Ok(request) = channel.try_recv() {
                asked |= matches!(request, NodeRequest::GetHeaders(_));
            }
            asked
        }

        deliver(&mut node, 1, PeerMessages::Ready(version(1, 3))).await;
        assert!(
            !asked_for_headers(&mut behind),
            "a peer at our height has nothing new"
        );
        assert!(!node.inflight.contains_key(&InflightRequests::Headers));

        deliver(&mut node, 2, PeerMessages::Ready(version(2, 10))).await;
        assert!(asked_for_headers(&mut ahead));
        assert!(node.inflight.contains_key(&InflightRequests::Headers));
    }

    #[tokio::test]
    async fn a_timed_out_block_lowers_the_peer_height() {
        let datadir = format!("./tmp-db/{}.peer_choice", rand::random::<u32>());
        let mut node: TestNode = idle_node(&datadir);
        let headers = signet_headers();
        for header in &headers[1..=3] {
            node.chain.accept_header(*header).unwrap();
        }
        // Claims the whole chain, cannot serve block 3
        let _liar = add_peer(&mut node, 1, u32::MAX, 10.0);

        let sent_at = Instant::now()
            .checked_sub(Duration::from_secs(SyncNode::REQUEST_TIMEOUT + 1))
            .unwrap();
        node.inflight.insert(
            InflightRequests::Blocks(headers[3].block_hash()),
            (1, sent_at),
        );

        node.check_for_timeout().unwrap();

        assert_eq!(node.peers[&1].height, 2);
    }

    #[tokio::test]
    async fn a_timed_out_request_stops_the_peer_looking_fast() {
        let datadir = format!("./tmp-db/{}.peer_choice", rand::random::<u32>());
        let mut node: TestNode = idle_node(&datadir);
        let _silent = add_peer(&mut node, 1, 968_570, 10.0);
        let _other = add_peer(&mut node, 2, 968_570, 500.0);

        let hash = BlockHash::from_byte_array([1u8; 32]);
        let sent_at = Instant::now()
            .checked_sub(Duration::from_secs(SyncNode::REQUEST_TIMEOUT + 1))
            .unwrap();
        node.inflight
            .insert(InflightRequests::UtreexoProof(hash), (1, sent_at));

        node.check_for_timeout().unwrap();

        assert!(
            !node
                .inflight
                .contains_key(&InflightRequests::UtreexoProof(hash))
        );
        let silent = node.peers[&1].message_times.value().unwrap();
        let other = node.peers[&2].message_times.value().unwrap();
        assert!(
            silent > other,
            "after a timeout the silent peer ({silent} ms) must rank below a slow one ({other} ms)"
        );
    }
}
