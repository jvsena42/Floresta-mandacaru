# floresta-common

[![crates.io][crates-io-badge]][crates-io-url]
[![docs.rs][docs-rs-badge]][docs-rs-url]

Common types, utility functions, and macros shared by the
[Floresta](https://github.com/getfloresta/Floresta) crates.

The crate includes Merkle tree utilities, a single-producer/single-consumer
channel, Bitcoin network helpers and a prelude for use with or without the
standard library. See the [API documentation](https://docs.rs/floresta-common)
for the available modules and types.

## Usage

Add the crate to your `Cargo.toml`:

```toml
[dependencies]
floresta-common = "=1.0.0"
```

The `std` feature is enabled by default. For `no_std` environments with an
allocator, disable default features:

```toml
[dependencies]
floresta-common = { version = "=1.0.0", default-features = false }
```

## License

Licensed under either of

- MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)
- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)

at your option.

[crates-io-badge]: https://img.shields.io/crates/v/floresta-common.svg
[crates-io-url]: https://crates.io/crates/floresta-common
[docs-rs-badge]: https://img.shields.io/badge/docs.rs-floresta-common--green
[docs-rs-url]: https://docs.rs/floresta-common
