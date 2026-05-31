# SPDX-License-Identifier: MIT OR Apache-2.0

"""
utreexod.py

Example showing how to use the Floresta test framework to start and interact
with a utreexod node and validate standard blockchain RPC responses.

This file demonstrates:
- Using pytest fixtures from tests/conftest.py (for example `utreexod_node`)
  to create, configure and teardown a node instance.
- How to call RPC methods via `node.rpc` and assert returned values.
"""

import pytest

from test_framework.constants import (
    CHAIN_NAME,
    GENESIS_BLOCK_HASH,
    GENESIS_BLOCK_DIFFICULTY_INT,
)


@pytest.mark.example
def test_utreexod(utreexod_node):
    """
    This test demonstrates how to set up and run a utreexod node,
    and verifies that the blockchain information returned by the node's RPC
    matches the expected values for the test chain.
    """
    response = utreexod_node.rpc.get_blockchain_info()

    assert response["chain"] == CHAIN_NAME
    assert response["bestblockhash"] == GENESIS_BLOCK_HASH
    assert response["difficulty"] == GENESIS_BLOCK_DIFFICULTY_INT
