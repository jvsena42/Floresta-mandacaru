# SPDX-License-Identifier: MIT OR Apache-2.0

"""
floresta_cli_stop.py

This functional test cli utility to interact with a Floresta node with `stop`
"""

import pytest


@pytest.mark.rpc
def test_stop(florestad_node):
    """Test stopping a Floresta node using the rpc."""

    florestad_node.rpc.stop()
    florestad_node.daemon.process.wait(5)

    florestad_node.rpc.wait_on_socket(opened=False)
