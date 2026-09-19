# SPDX-License-Identifier: MIT OR Apache-2.0

"""
floresta_cli_getpeerinfo.py

This functional test cli utility to interact with a Floresta node with `getpeerinfo`
"""

import pytest
from test_framework.util import assert_bitcoind_service_fields


@pytest.mark.rpc
def test_peer_info(florestad_node, bitcoind_node, node_manager):
    """
    Test `getpeerinfo` with a fresh node and its initial state.
    """

    result = florestad_node.rpc.get_peerinfo()

    assert isinstance(result, list)
    assert len(result) == 0

    node_manager.connect_nodes(florestad_node, bitcoind_node)

    result = florestad_node.rpc.get_peerinfo()
    assert isinstance(result, list)
    assert len(result) == 1

    peer_info = result[0]
    assert_bitcoind_service_fields(peer_info)
    assert peer_info["relaytxes"] is False
    assert peer_info["inbound"] is False
    assert peer_info["bip152_hb_to"] is False
    assert peer_info["bip152_hb_from"] is False
    assert isinstance(peer_info["timeoffset"], int)
    assert abs(peer_info["timeoffset"]) < 60
    assert peer_info["permissions"] == []
