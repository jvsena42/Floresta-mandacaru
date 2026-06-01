# SPDX-License-Identifier: MIT OR Apache-2.0

"""
floresta_cli_uptime.py

This functional test cli utility to interact with a Floresta node with `uptime`
"""

import time
import pytest

SLEEP_TIME = 5
# Tolerance margin for uptime to account for processing and response time
TIME_TOLERANCE_MARGIN = 2


@pytest.mark.rpc
def test_uptime(florestad_node):
    """Test uptime of a Floresta node using the rpc."""

    result = florestad_node.rpc.uptime()
    assert result is not None
    assert result >= 0

    expected_min_uptime = result + SLEEP_TIME
    expected_max_uptime = result + SLEEP_TIME + TIME_TOLERANCE_MARGIN

    time.sleep(SLEEP_TIME)

    result = florestad_node.rpc.uptime()
    assert result is not None
    assert expected_min_uptime <= result <= expected_max_uptime
