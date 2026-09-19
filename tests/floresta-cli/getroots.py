# SPDX-License-Identifier: MIT OR Apache-2.0

"""
floresta_cli_getroots.py

This functional test cli utility to interact with a Floresta node with `getroots`
"""

import pytest

BLOCKS_TO_MINE = 101


@pytest.mark.rpc
def test_get_roots(node_manager, florestad_utreexod):
    """
    Test the `get_roots` RPC method.
    """
    florestad, utreexod = florestad_utreexod
    vec_hashes = florestad.rpc.get_roots()
    assert len(vec_hashes) == 0

    utreexod.rpc.generate(BLOCKS_TO_MINE)
    node_manager.wait_for_sync_nodes()

    assert (
        florestad.rpc.get_roots()
        == utreexod.rpc.get_utreexo_roots(utreexod.rpc.get_bestblockhash())["roots"]
    ), "Roots from florestad and utreexod do not match"
