# Proxy Configuration

Floresta will make some connections with random nodes in the P2P network. You may want to use a proxy to hide your IP address. You can do this by
providing a SOCKS5 socket, with the `--proxy` flag. For example, if you’re running Tor on your local machine, you can start `florestad` with the Tor proxy like this:

```bash
# start the daemon with the Tor proxy
florestad --proxy 127.0.0.1:9050
```

This will route all your connections through the Tor network, effectively masking your IP address.

## Onion peers only

To also connect to Tor onion peers while every other peer keeps connecting directly, pass the proxy with `--onion-proxy` instead, like Bitcoin Core's `-onion`:

```bash
florestad --onion-proxy 127.0.0.1:9050
```

Only onion peers go through Tor, so your IP address stays visible to clearnet peers, but syncing is not slowed down. The node keeps at least one onion peer alongside its clearnet peers, and normally no more than two; it goes over that only to reach a peer service (Utreexo or compact filters) when no clearnet address offering it can be dialled right now. If both flags are set, onion peers use `--onion-proxy` and every other peer uses `--proxy`.

Without either flag, onion addresses are not stored or dialled, since they cannot be reached.
