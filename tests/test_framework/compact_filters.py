# SPDX-License-Identifier: MIT OR Apache-2.0

"""Node setup shared by the compact-filter rescan tests."""

from test_framework.node import NodeType
from test_framework.util import wait_until


def add_cfilters_utreexod(add_node_with_extra_args, mining_addresses):
    """Start a utreexod that serves compact filters and mines to `mining_addresses`."""
    return add_node_with_extra_args(
        variant=NodeType.UTREEXOD,
        extra_args=[
            *(f"--miningaddr={address}" for address in mining_addresses),
            "--utreexoproofindex",
            "--prune=0",
            "--cfilters",
        ],
    )


def add_florestad_synced_with(add_node_with_extra_args, node_manager, cfilters_peer):
    """Start a florestad, sync it with `cfilters_peer` and wait until it sees its filters."""
    florestad = add_node_with_extra_args(variant=NodeType.FLORESTAD, extra_args=[])
    node_manager.connect_nodes(florestad, cfilters_peer)
    node_manager.wait_for_sync_nodes()

    wait_until(
        lambda: any(
            "COMPACT_FILTERS" in peer["servicesnames"]
            for peer in florestad.rpc.get_peerinfo()
        ),
        error_msg="Floresta did not connect to a compact-filter peer",
    )
    return florestad
