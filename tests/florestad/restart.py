# SPDX-License-Identifier: MIT OR Apache-2.0

"""
restart.py

A simple test that restarts a Floresta node and ensures that the node can
successfully restart using the same data directory.

The test verifies that the node can stop and restart without encountering
issues, such as data corruption or failure to initialize.
"""

import pytest


@pytest.mark.florestad
def test_restart(florestad_node):
    """
    Test restarting a Floresta node and ensuring data directory integrity.
    """

    florestad_node.stop()

    florestad_node.start()
    florestad_node.rpc.wait_on_socket(opened=True)

    response = florestad_node.rpc.get_blockchain_info()
    assert response is not None
