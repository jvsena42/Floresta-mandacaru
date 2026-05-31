# SPDX-License-Identifier: MIT OR Apache-2.0

"""
floresta_cli_getroots.py

This functional test cli utility to interact with a Floresta node with `getroots`
"""

import pytest


@pytest.mark.rpc
def test_get_roots(florestad_node):
    """
    Test the `get_roots` RPC method.
    """
    vec_hashes = florestad_node.rpc.get_roots()
    assert len(vec_hashes) == 0
