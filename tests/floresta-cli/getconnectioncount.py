# SPDX-License-Identifier: MIT OR Apache-2.0

"""
floresta_cli_getconnectioncount.py

This functional test exercises the `getconnectioncount` RPC by starting
a Floresta node and multiple bitcoind nodes, then verifying the connection
count as peers are progressively connected. Also compares behavior against
bitcoind's own `getconnectioncount` for parity.
"""

import pytest
from test_framework.node import NodeType


@pytest.mark.rpc
def test_get_connection_count(node_manager, florestad_node, bitcoind_node):
    """
    Test `getconnectioncount` by connecting multiple bitcoind peers
    and verifying the count increases accordingly. Also compares
    behavior against bitcoind's own `getconnectioncount`.
    """
    # Starts at 0
    assert florestad_node.rpc.get_connectioncount() == 0

    # Direct comparison — connect florestad to bitcoind, both should report 1
    node_manager.connect_nodes(florestad_node, bitcoind_node)

    floresta_count = florestad_node.rpc.get_connectioncount()
    bitcoind_count = bitcoind_node.rpc.get_connectioncount()

    assert floresta_count == bitcoind_count

    # Connect each peer and verify count increments by 1
    for i in range(5):
        peer = node_manager.add_node_default_args(variant=NodeType.BITCOIND)
        node_manager.run_node(peer)

        node_manager.connect_nodes(florestad_node, peer)

        assert florestad_node.rpc.get_connectioncount() == i + 2

    # Disconnect bitcoind and verify count decreases
    florestad_node.rpc.disconnectnode(bitcoind_node.p2p_url)

    node_manager.wait_for_peers_connections(
        florestad_node, bitcoind_node, is_connected=False
    )

    assert florestad_node.rpc.get_connectioncount() == 5
