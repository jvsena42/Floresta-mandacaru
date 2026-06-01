# SPDX-License-Identifier: MIT OR Apache-2.0

"""
floresta_cli_getdifficulty.py

Functional test for the `getdifficulty` RPC. Verifies parity between
florestad and bitcoind at genesis for Bitcoin Core compliance.
"""

import math
import pytest

# Bitcoin Core and rust-bitcoin compute difficulty with slightly different
# float arithmetic, so allow a small relative tolerance on the parity check.
TOLERANCE = 1e-9


@pytest.mark.rpc
def test_get_difficulty(florestad_bitcoind):
    """
    Test `getdifficulty` by comparing florestad's response against bitcoind's.
    Both nodes start at the regtest genesis block and should report the same
    difficulty for that target.
    """
    florestad, bitcoind = florestad_bitcoind

    floresta_difficulty = florestad.rpc.get_difficulty()
    bitcoind_difficulty = bitcoind.rpc.get_difficulty()

    assert floresta_difficulty is not None
    assert floresta_difficulty > 0
    assert math.isclose(floresta_difficulty, bitcoind_difficulty, rel_tol=TOLERANCE)
