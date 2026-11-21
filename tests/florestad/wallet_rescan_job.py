# SPDX-License-Identifier: MIT OR Apache-2.0

"""
The wallet rescan a descriptor starts is kept until it finishes.

With no compact-filter peer the rescan can't get past the filter-header sync, so it is still
running when the node restarts. It must be running again after the restart, and find the
wallet's history once a peer serves filters. A second descriptor loaded meanwhile must not
cost a second pass over the range.
"""

import pytest
from requests.exceptions import HTTPError

from test_framework.compact_filters import add_cfilters_utreexod
from test_framework.constants import (
    WALLET_ADDRESS,
    WALLET_DESCRIPTOR_EXTERNAL,
    WALLET_DESCRIPTOR_INTERNAL,
)
from test_framework.node import NodeType
from test_framework.rpc.exceptions import JSONRPCError
from test_framework.util import wait_until

MINE_BLOCKS = 20
HISTORICAL_HEIGHT = 1


def _node_log(florestad):
    # pylint: disable=protected-access
    with open(florestad._log_path, encoding="utf-8") as log_file:
        return log_file.read()


def _rescan_in_progress(florestad):
    return florestad.rpc.get_blockchain_info()["rescan_in_progress"]


def _start_without_filters(utreexod, add_node_with_extra_args, node_manager):
    """A florestad synced with `utreexod`, which serves no compact filters."""
    utreexod.rpc.generate(MINE_BLOCKS)
    block_hash = utreexod.rpc.get_blockhash(HISTORICAL_HEIGHT)
    coinbase_txid = utreexod.rpc.get_block(block_hash)["tx"][0]

    florestad = add_node_with_extra_args(variant=NodeType.FLORESTAD, extra_args=[])
    node_manager.connect_nodes(florestad, utreexod)
    node_manager.wait_for_sync_nodes()
    return florestad, utreexod, coinbase_txid


def _serve_filters(add_node_with_extra_args, node_manager, florestad, utreexod):
    """Connect `florestad` to a utreexod that has the chain and serves compact filters."""
    cfilters = add_cfilters_utreexod(add_node_with_extra_args, [WALLET_ADDRESS])
    node_manager.connect_nodes(cfilters, utreexod)
    wait_until(
        lambda: cfilters.rpc.get_block_count() == utreexod.rpc.get_block_count(),
        error_msg="the compact-filter peer did not sync",
    )
    node_manager.connect_nodes(florestad, cfilters)


def _wait_for_transaction(florestad, txid):
    def cached():
        try:
            florestad.rpc.get_raw_transaction(txid, 1)
        except (HTTPError, JSONRPCError):
            return False
        return True

    wait_until(
        cached,
        timeout=90,
        interval=2,
        error_msg="the wallet rescan did not find the historical transaction",
    )


@pytest.mark.florestad
def test_rescan_survives_a_restart(
    utreexod_node, add_node_with_extra_args, node_manager, setup_logging
):
    """A `loaddescriptor` rescan interrupted by a restart runs again after it."""
    log = setup_logging
    florestad, utreexod, coinbase_txid = _start_without_filters(
        utreexod_node, add_node_with_extra_args, node_manager
    )

    log.info("Loading a descriptor while no peer serves compact filters")
    assert florestad.rpc.load_descriptor(WALLET_DESCRIPTOR_EXTERNAL)
    assert _rescan_in_progress(florestad)

    log.info("Restarting the node before the rescan could finish")
    florestad.stop()
    florestad.start()
    wait_until(
        lambda: _rescan_in_progress(florestad),
        error_msg="the unfinished rescan was not resumed after the restart",
    )

    log.info("Serving compact filters so the resumed rescan can finish")
    _serve_filters(add_node_with_extra_args, node_manager, florestad, utreexod)
    _wait_for_transaction(florestad, coinbase_txid)
    wait_until(
        lambda: not _rescan_in_progress(florestad),
        error_msg="the resumed rescan did not finish",
    )
    assert florestad.rpc.get_blockchain_info().get("rescan_error") is None

    log.info("Restarting again: the finished rescan must not run again")
    florestad.stop()
    florestad.start()
    assert not _rescan_in_progress(florestad)
    assert "resuming the unfinished wallet rescan" not in _node_log(florestad)


@pytest.mark.florestad
def test_second_descriptor_needs_no_second_pass(
    utreexod_node, add_node_with_extra_args, node_manager, setup_logging
):
    """A descriptor loaded while a rescan runs joins that rescan."""
    log = setup_logging
    florestad, utreexod, coinbase_txid = _start_without_filters(
        utreexod_node, add_node_with_extra_args, node_manager
    )

    # The coinbase pays the receive descriptor: finding it shows the second one was scanned
    log.info("Loading the change and the receive descriptors one after the other")
    assert florestad.rpc.load_descriptor(WALLET_DESCRIPTOR_INTERNAL)
    assert florestad.rpc.load_descriptor(WALLET_DESCRIPTOR_EXTERNAL)
    assert _rescan_in_progress(florestad)

    _serve_filters(add_node_with_extra_args, node_manager, florestad, utreexod)
    _wait_for_transaction(florestad, coinbase_txid)
    wait_until(
        lambda: not _rescan_in_progress(florestad),
        error_msg="the rescan did not finish",
    )

    passes = _node_log(florestad).count("rescan complete")
    assert passes == 1, f"expected one pass over the range, saw {passes}"
