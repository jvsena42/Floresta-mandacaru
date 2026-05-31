# `getroots`

Returns the hex-encoded roots of the current utreexo accumulator forest.

## Usage

### Synopsis

```bash
floresta-cli getroots
```

### Examples

```bash
# Get the roots of the utreexo accumulator
floresta-cli getroots
```

## Arguments

This command takes no arguments.

## Returns

### Ok Response

Returns a JSON array of strings representing the actual hex-encoded roots of the utreexo accumulator.

### Error Enum

This command typically does not return any specific logic errors under normal operation.

## Notes

- This command relates specifically to Utreexo. These are the roots of the current utreexo forest state maintained by the node.
