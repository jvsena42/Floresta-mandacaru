# `stop`

Requests a graceful shutdown of the Floresta node.

## Usage

### Synopsis

```bash
floresta-cli stop
```

### Examples

```bash
# Gracefully shutdown the node
floresta-cli stop
```

## Arguments

This command takes no arguments.

## Returns

### Ok Response

Returns the string `"Floresta stopping"` to indicate that the shutdown sequence has been initiated.

### Error Enum

This command typically does not return any specific logic errors under normal operation.

## Notes

- Use this command to safely terminate the `florestad` daemon, ensuring all state is flushed and saved to disk before exiting.
