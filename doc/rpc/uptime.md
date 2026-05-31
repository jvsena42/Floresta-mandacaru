# `uptime`

Returns the total uptime of the node in seconds.

## Usage

### Synopsis

```bash
floresta-cli uptime
```

### Examples

```bash
# Get the server uptime
floresta-cli uptime
```

## Arguments

This command takes no arguments.

## Returns

### Ok Response

Returns a numeric value representing the number of seconds that the node has been running.

### Error Enum

This command typically does not return any specific logic errors under normal operation.

## Notes

- This RPC method has a direct equivalent in Bitcoin Core and functions identically by returning the server uptime in seconds.
