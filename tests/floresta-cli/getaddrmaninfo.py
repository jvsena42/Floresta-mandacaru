# SPDX-License-Identifier: MIT OR Apache-2.0

"""
floresta_cli_getaddrmaninfo.py

This functional test verifies the `getaddrmaninfo` RPC method.

Note on test coverage: the address manager only tracks publicly routable
addresses (see ``AddressMan::push_addresses`` and ``LocalAddress::is_routable``
in ``address_man.rs``).  In regtest every peer runs on 127.0.0.1, which is
rejected by the routability filter, so connecting peers in this environment
does **not** change the addrman statistics.
"""

import pytest


@pytest.mark.rpc
def test_get_addrman_info(florestad_node):
    """
    Test `getaddrmaninfo` returns address manager statistics by network,
    including schema validation matching Bitcoin Core's response format.
    """
    info = florestad_node.rpc.get_addrman_info()
    assert info is not None

    # Verify structure has all expected network keys
    for key in ["all_networks", "ipv4", "ipv6", "onion", "i2p", "cjdns"]:
        assert key in info
        assert "total" in info[key]
        assert "new" in info[key]
        assert "tried" in info[key]
        assert isinstance(info[key]["total"], int)
        assert isinstance(info[key]["new"], int)
        assert isinstance(info[key]["tried"], int)
        # Invariant: total == new + tried
        assert info[key]["total"] == info[key]["new"] + info[key]["tried"]
