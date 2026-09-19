# getrpcinfo

Returns details about the JSON-RPC server, including active commands and the log file path.

## Usage

### Synopsis

```bash
floresta-cli getrpcinfo
```

### Examples

```bash
floresta-cli getrpcinfo
```

## Returns

Returns a JSON object:
- `active_commands` - (json array) A list of currently active RPC commands:
  - `method` - (string) The name of the RPC command.
  - `duration` - (numeric) The running time of the command in microseconds.
- `logpath` - (string) The complete absolute file path to the debug log.

Example:
```json
{
  "active_commands": [
    {
      "method": "getrpcinfo",
      "duration": 67
    }
  ],
  "logpath": "/home/x0/.floresta/regtest/debug.log"
}
```
