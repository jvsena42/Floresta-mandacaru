# SPDX-License-Identifier: MIT OR Apache-2.0

"""
floresta_cli_getpeerinfo.py

This functional test cli utility to interact with a Floresta node with `getpeerinfo`
"""

import pytest


@pytest.mark.rpc
def test_peer_info(florestad_node):
    """
    Test `getpeerinfo` with a fresh node and its initial state.
    """

    result = florestad_node.rpc.get_peerinfo()

    assert isinstance(result, list)
    assert len(result) == 0
