// SPDX-License-Identifier: MIT OR Apache-2.0

//! A library for building and querying BIP-158 compact block filters locally
//!
//! This lib implements BIP-158 client-side Galomb-Rice block filters, without
//! relaying on p2p connections to retrieve them. We use this to speedup wallet
//! resyncs and allow arbitrary UTXO retrieving for lightning nodes.
//!
//! This module should receive blocks as we download them, it'll create a filter
//! for it. Therefore, you can't use this to speedup wallet sync **before** IBD,
//! since we wouldn't have the filter for all blocks yet.

// cargo docs customization
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(html_logo_url = "https://avatars.githubusercontent.com/u/249173822")]
#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/getfloresta/floresta-media/master/logo_png/Icon-Green(main).png"
)]
#![allow(clippy::manual_is_multiple_of)]

use core::error;
use core::fmt;
use core::fmt::Debug;
use core::fmt::Display;
use core::fmt::Formatter;
use std::io;
use std::sync::PoisonError;
use std::sync::RwLockWriteGuard;

use bitcoin::bip158;
use flat_filters_store::FlatFiltersStore;

pub mod flat_filters_store;
pub mod network_filters;

/// A database that stores our compact filters
pub trait BlockFilterStore: Send + Sync {
    /// Fetches a block filter
    fn get_filter(&self, block_height: u32) -> Option<bip158::BlockFilter>;
    /// Stores a new filter
    fn put_filter(&self, block_height: u32, block_filter: bip158::BlockFilter);
    /// Persists the height of the last filter we have
    fn put_height(&self, height: u32);
    /// Fetches the height of the last filter we have
    fn get_height(&self) -> Option<u32>;
}

/// Errors that can happen whilst interacting with the [`IterableFilterStore`].
#[derive(Debug)]
pub enum IterableFilterStoreError {
    /// An I/O error.
    ///
    /// See the inner error for more information.
    Io(io::Error),

    /// The reader reached the end of the file.
    Eof,

    /// The cache lock is poisoned.
    PoisonedLock,

    /// The filter is larger than [`MAX_FILTER_SIZE`](crate::flat_filters_store::MAX_FILTER_SIZE).
    OversizedBlockFilter,
}

impl Display for IterableFilterStoreError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            IterableFilterStoreError::Io(e) => write!(f, "IterableFilterStore I/O Error: {e:?}"),
            IterableFilterStoreError::Eof => write!(f, "The IterableFilterStore reached EOF"),
            IterableFilterStoreError::PoisonedLock => write!(f, "The lock is poisoned"),
            IterableFilterStoreError::OversizedBlockFilter => write!(f, "The filter is too large"),
        }
    }
}

impl error::Error for IterableFilterStoreError {}

impl From<io::Error> for IterableFilterStoreError {
    fn from(e: io::Error) -> Self {
        IterableFilterStoreError::Io(e)
    }
}

impl From<PoisonError<RwLockWriteGuard<'_, FlatFiltersStore>>> for IterableFilterStoreError {
    fn from(_: PoisonError<RwLockWriteGuard<'_, FlatFiltersStore>>) -> Self {
        IterableFilterStoreError::PoisonedLock
    }
}

pub trait IterableFilterStore:
    Send + Sync + IntoIterator<Item = (u32, bip158::BlockFilter)>
{
    type I: Iterator<Item = (u32, bip158::BlockFilter)>;
    /// Fetches the first filter and sets our internal cursor to the first filter,
    /// succeeding calls to [next()](std::iter::Iterator::next) will return the next filter until we reach the end
    fn iter(&self, start_height: Option<usize>) -> Result<Self::I, IterableFilterStoreError>;
    /// Writes a new filter to the store
    fn put_filter(
        &self,
        block_filter: bip158::BlockFilter,
        height: u32,
    ) -> Result<(), IterableFilterStoreError>;
    /// Persists the height of the last filter we have
    fn set_height(&self, height: u32) -> Result<(), IterableFilterStoreError>;
    /// Fetches the height of the last filter we have
    fn get_height(&self) -> Result<u32, IterableFilterStoreError>;
}
