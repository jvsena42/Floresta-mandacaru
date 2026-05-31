# SPDX-License-Identifier: MIT OR Apache-2.0

"""
floresta_cli_getblockchainfo.py

This functional test cli utility to interact with a Floresta node with `getblockchaininfo`
"""

import pytest
from test_framework.constants import (
    GENESIS_BLOCK_HASH,
    GENESIS_BLOCK_DIFFICULTY_INT,
    GENESIS_BLOCK_HEIGHT,
)


@pytest.mark.rpc
def test_get_blockchain_info(florestad_node):
    """
    Test `getblockchaininfo` with a fresh node and its first block
    """

    response = florestad_node.rpc.get_blockchain_info()
    assert response["best_block"] == GENESIS_BLOCK_HASH
    assert response["difficulty"] == GENESIS_BLOCK_DIFFICULTY_INT
    assert response["height"] == GENESIS_BLOCK_HEIGHT
    assert response["ibd"] is True
    assert response["latest_block_time"] == 1296688602
    assert (
        response["latest_work"]
        == "0000000000000000000000000000000000000000000000000000000000000002"
    )
    assert response["leaf_count"] == 0
    assert response["progress"] == 0
    assert response["root_count"] == 0
    assert response["root_hashes"] == []
    assert response["validated"] == 0
