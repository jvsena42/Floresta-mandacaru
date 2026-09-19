# getmemoryinfo

Returns statistics about the node's memory usage.

## Usage

### Synopsis

```bash
floresta-cli getmemoryinfo [mode]
```

### Examples

```bash
# Get memory statistics (default mode = "stats")
floresta-cli getmemoryinfo

# Get XML-formatted malloc information (if supported by the allocator)
floresta-cli getmemoryinfo "mallocinfo"
```

## Arguments

- `mode` - (string, optional, default="stats") The information to retrieve.
  - `"stats"`: Returns general memory stats regarding the memory pool.
  - `"mallocinfo"`: Returns XML-formatted malloc information.

## Returns

### Ok Response (for mode = "stats")

Returns a JSON object:
- `locked` - (json object) Information about locked memory:
  - `used` - (numeric) Memory currently in use (in bytes).
  - `free` - (numeric) Memory currently free (in bytes).
  - `total` - (numeric) Total memory allocated (in bytes).
  - `locked` - (numeric) Total memory locked (in bytes).
  - `chunks_used` - (numeric) Number of memory chunks currently in use.
  - `chunks_free` - (numeric) Number of memory chunks currently free.

### Ok Response (for mode = "mallocinfo")

A string containing XML-formatted malloc information.

Example:
```xml
<malloc version="2.0">
  <heap nr="1">
    <allocated>28499968</allocated>
    <free>780560</free>
    <total>1636080</total>
    <locked>2416640</locked>
    <chunks nr="28499968">
      <used>21</used>
      <free>2</free>
    </chunks>
  </heap>
</malloc>
```

## Notes

- Floresta returns zeroed memory statistics for systems/runtimes that are not MacOS or Linux glibc-based.
