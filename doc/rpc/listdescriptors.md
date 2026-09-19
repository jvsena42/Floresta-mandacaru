# `listdescriptors`

Returns a list of all descriptors currently loaded in the watch-only wallet.

## Usage

### Synopsis

```bash
floresta-cli listdescriptors
```

### Examples

```bash
floresta-cli listdescriptors
```

## Returns

Returns a JSON array of strings:
- (string) The wallet descriptor (including checksum).

Example:
```json
[
  "wpkh(tpubDDtyive2LqLWKzPZ8LZ9Ebi1JDoLcf1cEpn3Mshp6sxVfCupHZJRPQTozp2EpTF76vJcyQBN7VP7CjUntEJxeADnuTMNTYKoSWNae8soVyv/0/*)#7h6kdtnk"
]
```
