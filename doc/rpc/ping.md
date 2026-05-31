# `ping`

Sends a ping to all connected peers to check if they are still alive.

## Usage

### Synopsis

```bash
floresta-cli ping
```

### Examples

```bash
# Send a ping to all connected peers
floresta-cli ping
```

## Arguments

This command takes no arguments.

## Returns

### Ok Response

Returns `null` upon successful execution.

### Error Enum

* `JsonRpcError::Node` - If there is an internal node error preventing the ping from being sent.

## Notes

- This command is useful for diagnosing network connectivity and ensuring peers are still responsive.
