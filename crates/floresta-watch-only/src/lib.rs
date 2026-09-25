// SPDX-License-Identifier: MIT OR Apache-2.0

// cargo docs customization
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(html_logo_url = "https://avatars.githubusercontent.com/u/249173822")]
#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/getfloresta/floresta-media/master/logo_png/Icon-Green(main).png"
)]
#![allow(clippy::manual_is_multiple_of)]

use core::cmp::Ordering;
use core::error::Error;
use core::fmt;
use core::fmt::Debug;
use core::fmt::Display;
use core::fmt::Formatter;

use bitcoin::Network;
use bitcoin::ScriptBuf;
use bitcoin::hashes::sha256;
use floresta_chain::BlockConsumer;
use floresta_chain::UtxoData;
pub use floresta_common::MerkleBackend;
use floresta_common::get_spk_hash;

pub mod descriptor;
pub mod kv_database;
#[cfg(any(test, feature = "memory-database"))]
pub mod memory_database;
pub mod merkle;

use bitcoin::Block;
use bitcoin::OutPoint;
use bitcoin::Transaction;
use bitcoin::TxOut;
use bitcoin::consensus::deserialize;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hash_types::Txid;
use bitcoin::hashes::Hash as HashTrait;
use bitcoin::hashes::hex::FromHex;
use bitcoin::hashes::sha256::Hash;
use floresta_common::prelude::*;
use merkle::MerkleProof;
use miniscript::Descriptor;
use miniscript::DescriptorPublicKey;
use serde::Deserialize;
use serde::Serialize;
use sync::RwLock;
use tracing::error;

use crate::descriptor::DescriptorError;
use crate::descriptor::derive_addresses_from_parsed_descriptor;
use crate::descriptor::parse_and_split_descriptor;
use crate::descriptor::parse_xpub;

/// How many addresses to derive from a descriptor each time.
const DERIVATION_COUNT: u32 = 100;

/// Initial index for address derivation.
const INDEX_INITIAL: u32 = 0;

/// How many unused addresses to keep derived past the highest one seen in a transaction
/// (BIP 44's gap limit). Wallets stop looking after this many unused addresses in a row, so
/// nothing can be found further out.
const GAP_LIMIT: u32 = 20;

#[derive(Debug)]
pub enum WatchOnlyError<DatabaseError: Debug> {
    WalletNotInitialized,
    TransactionNotFound,
    DatabaseError(DatabaseError),
    DuplicateDescriptor(String),
    InvalidDescriptor(DescriptorError),
}

impl<DatabaseError: Debug> Display for WatchOnlyError<DatabaseError> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::WalletNotInitialized => {
                write!(f, "Wallet isn't initialized")
            }
            Self::TransactionNotFound => {
                write!(f, "Transaction not found")
            }
            Self::DatabaseError(e) => {
                write!(f, "Database error: {e:?}")
            }
            Self::DuplicateDescriptor(desc) => {
                write!(f, "Descriptor is already cached: {desc}")
            }
            Self::InvalidDescriptor(e) => {
                write!(f, "Invalid descriptor: {e:?}")
            }
        }
    }
}

impl<DatabaseError: Debug> From<DatabaseError> for WatchOnlyError<DatabaseError> {
    fn from(e: DatabaseError) -> Self {
        Self::DatabaseError(e)
    }
}

impl<T: Debug> Error for WatchOnlyError<T> {}

/// Every address contains zero or more associated transactions, this struct defines what
/// data we store for those.
#[derive(Debug, Clone, Eq, Serialize, Deserialize)]
pub struct CachedTransaction {
    pub tx: Transaction,
    pub height: u32,
    pub merkle_block: Option<MerkleProof>,
    pub hash: Txid,
    pub position: u32,
}

impl Ord for CachedTransaction {
    fn cmp(&self, other: &Self) -> Ordering {
        self.height.cmp(&other.height)
    }
}

impl PartialOrd for CachedTransaction {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for CachedTransaction {
    fn eq(&self, other: &Self) -> bool {
        self.height == other.height
    }
}

impl Default for CachedTransaction {
    fn default() -> Self {
        Self {
            // A placeholder transaction with no input and no outputs, the bare-minimum to be
            // serializable
            tx: deserialize(&Vec::from_hex("010000000000ffffffff").unwrap()).unwrap(),
            height: 0,
            merkle_block: None,
            hash: Txid::all_zeros(),
            position: 0,
        }
    }
}

/// An address inside our cache, contains all information we need to satisfy electrum's requests
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedAddress {
    script_hash: Hash,
    balance: u64,
    script: ScriptBuf,
    transactions: Vec<Txid>,
    utxos: Vec<OutPoint>,
}

/// Holds some useful data about our wallet, like how many addresses we have, how many
/// transactions we have, etc.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Stats {
    pub address_count: usize,
    pub transaction_count: usize,
    pub utxo_count: usize,
    pub cache_height: u32,
    pub txo_count: usize,
    pub balance: u64,
    pub derivation_index: u32,
}

/// Public trait defining a common interface for databases to be used with our cache
pub trait AddressCacheDatabase {
    type Error: Debug + Send + Sync + 'static;
    /// Saves a new address to the database. If the address already exists, `update` should
    /// be used instead
    fn save(&self, address: &CachedAddress);
    /// Loads all addresses we have cached so far
    fn load(&self) -> Result<Vec<CachedAddress>, Self::Error>;
    /// Loads the data associated with our watch-only wallet.
    fn get_stats(&self) -> Result<Stats, Self::Error>;
    /// Saves the data associated with our watch-only wallet.
    fn save_stats(&self, stats: &Stats) -> Result<(), Self::Error>;
    /// Updates an address, probably because a new transaction arrived
    fn update(&self, address: &CachedAddress);
    /// TODO: Maybe turn this into another db
    /// Returns the height of the last block we filtered
    fn get_cache_height(&self) -> Result<u32, Self::Error>;
    /// Saves the height of the last block we filtered
    fn set_cache_height(&self, height: u32) -> Result<(), Self::Error>;
    /// Saves the descriptor of associated cache
    fn save_descriptor(&self, descriptor: &str) -> Result<(), Self::Error>;
    /// Get associated descriptors
    fn get_descriptors(&self) -> Result<Vec<String>, Self::Error>;
    /// Saves the addresses derived past the gap limit that still have to be rescanned,
    /// replacing the previous set
    fn save_pending_rescan(&self, addresses: &[ScriptBuf]) -> Result<(), Self::Error>;
    /// Loads the addresses that still have to be rescanned
    fn get_pending_rescan(&self) -> Result<Vec<ScriptBuf>, Self::Error>;
    /// Get a transaction from the database
    fn get_transaction(&self, txid: &Txid) -> Result<CachedTransaction, Self::Error>;
    /// Saves a transaction to the database
    fn save_transaction(&self, tx: &CachedTransaction) -> Result<(), Self::Error>;
    /// Returns all transaction we have cached so far
    fn list_transactions(&self) -> Result<Vec<Txid>, Self::Error>;
}

/// A single (non-multipath) descriptor and how far along its addresses are derived.
struct DescriptorWindow {
    descriptor: Descriptor<DescriptorPublicKey>,
    /// Addresses `0..next_index` are cached
    next_index: u32,
}

struct AddressCacheInner<D: AddressCacheDatabase> {
    /// A database that will be used to persist all needed to get our address history
    database: D,
    /// The descriptors we follow, split into single descriptors
    windows: Vec<DescriptorWindow>,
    /// Which descriptor window an address came from, and at which index
    script_origin: HashMap<Hash, (usize, u32)>,
    /// Addresses derived after the wallet was last scanned. Their history, if any, is still
    /// to be found: whoever runs the next rescan takes them.
    pending_rescan: Vec<ScriptBuf>,
    /// Maps a hash to a cached address struct, this is basically an in-memory version
    /// of our database, used for speeding up processing a block. This hash is the electrum's
    /// script hash
    address_map: HashMap<Hash, CachedAddress>,
    /// Holds all scripts we are interested in
    script_set: HashSet<sha256::Hash>,
    /// Keeps track of all utxos we own, and the script hash they belong to
    utxo_index: HashMap<OutPoint, Hash>,
}

impl<D: AddressCacheDatabase> AddressCacheInner<D> {
    /// Iterates through a block, finds transactions destined to ourselves.
    /// Returns all transactions we found.
    fn block_process(
        &mut self,
        block: &Block,
        height: u32,
        merkle: &dyn MerkleBackend,
    ) -> Vec<(Transaction, TxOut)> {
        let mut my_transactions = Vec::new();
        // Check if this transaction spends from one of our utxos
        for (position, transaction) in block.txdata.iter().enumerate() {
            for (vin, txin) in transaction.input.iter().enumerate() {
                if let Some(script) = self.utxo_index.get(&txin.previous_output) {
                    let script = self
                        .address_map
                        .get(script)
                        .expect("Can't cache a utxo for a address we don't have")
                        .to_owned();
                    let tx = self
                        .get_transaction(&txin.previous_output.txid)
                        .expect("We cached a utxo for a transaction we don't have");

                    let utxo = tx
                        .tx
                        .output
                        .get(txin.previous_output.vout as usize)
                        .expect("Did we cache an invalid utxo?");

                    // The spent output, so a subscriber to that address hears its balance changed
                    my_transactions.push((transaction.clone(), utxo.clone()));

                    let merkle_block = MerkleProof::from_block(block, position as u64, merkle);

                    self.cache_transaction(
                        transaction,
                        height,
                        utxo.value.to_sat(),
                        merkle_block,
                        position as u32,
                        vin,
                        true,
                        script.script_hash,
                    )
                }
            }
            // Checks if one of our addresses is the recipient of this transaction
            for (vout, output) in transaction.output.iter().enumerate() {
                let hash = get_spk_hash(&output.script_pubkey);
                if self.script_set.contains(&hash) {
                    my_transactions.push((transaction.clone(), output.clone()));

                    let merkle_block = MerkleProof::from_block(block, position as u64, merkle);

                    self.cache_transaction(
                        transaction,
                        height,
                        output.value.to_sat(),
                        merkle_block,
                        position as u32,
                        vout,
                        false,
                        hash,
                    );
                }
            }
        }
        my_transactions
    }

    fn new(database: D) -> Self {
        let scripts = database.load().expect("Could not load database");
        if database.get_stats().is_err() {
            database
                .save_stats(&Stats::default())
                .expect("Could not save stats");
        }
        let mut address_map = HashMap::new();
        let mut script_set = HashSet::new();
        let mut utxo_index = HashMap::new();
        for address in scripts {
            for utxo in address.utxos.iter() {
                utxo_index.insert(*utxo, address.script_hash);
            }
            script_set.insert(address.script_hash);
            address_map.insert(address.script_hash, address);
        }

        let mut inner = Self {
            database,
            address_map,
            script_set,
            utxo_index,
            windows: Vec::new(),
            script_origin: HashMap::new(),
            pending_rescan: Vec::new(),
        };

        // The addresses are persisted, how far each descriptor was derived is not: walk
        // each one until a whole batch is unknown.
        for descriptor in inner.database.get_descriptors().unwrap_or_default() {
            if let Err(error) = inner.track_descriptor(&descriptor) {
                error!("Could not derive addresses for descriptor {descriptor}: {error:?}");
            }
        }

        // Addresses derived before a shutdown whose rescan never ran
        inner.pending_rescan = inner.database.get_pending_rescan().unwrap_or_default();

        // History cached while the gap limit was not enforced (or by a rescan that ended
        // early) may sit near the end of a window: extend now, the queue takes the rest.
        let with_history: Vec<Hash> = inner
            .address_map
            .iter()
            .filter(|(_, address)| !address.transactions.is_empty())
            .map(|(hash, _)| *hash)
            .collect();
        for hash in with_history {
            inner.maybe_extend_window(&hash);
        }

        inner
    }

    /// Starts following a descriptor: derives its first addresses, or picks up where an
    /// earlier run left off when they are already cached. Returns every cached address of
    /// the descriptor.
    fn track_descriptor(&mut self, descriptor: &str) -> Result<Vec<ScriptBuf>, DescriptorError> {
        let mut addresses = Vec::new();

        for descriptor in parse_and_split_descriptor(descriptor)? {
            let window = self.windows.len();
            self.windows.push(DescriptorWindow {
                descriptor,
                next_index: INDEX_INITIAL,
            });

            let first = self.peek_batch(window)?;
            addresses.extend(self.cache_batch(window, first));
            loop {
                let next = self.peek_batch(window)?;
                // Batches are always cached whole, so one known address means the batch
                // was derived by an earlier run
                let known = next
                    .iter()
                    .all(|script| self.address_map.contains_key(&get_spk_hash(script)));
                if !known {
                    break;
                }
                addresses.extend(self.cache_batch(window, next));
            }
        }

        Ok(addresses)
    }

    /// The next [`DERIVATION_COUNT`] addresses of a descriptor window, not cached yet.
    fn peek_batch(&self, window: usize) -> Result<Vec<ScriptBuf>, DescriptorError> {
        let window = &self.windows[window];
        derive_addresses_from_parsed_descriptor(
            window.descriptor.clone(),
            window.next_index,
            DERIVATION_COUNT,
        )
    }

    /// Caches a batch from [`Self::peek_batch`] and moves the window past it.
    fn cache_batch(&mut self, window: usize, scripts: Vec<ScriptBuf>) -> Vec<ScriptBuf> {
        let start = self.windows[window].next_index;

        for (offset, script) in scripts.iter().enumerate() {
            self.cache_address(script.clone());
            self.script_origin
                .insert(get_spk_hash(script), (window, start + offset as u32));
        }
        self.windows[window].next_index = start + DERIVATION_COUNT;

        scripts
    }

    /// Keeps [`GAP_LIMIT`] unused addresses derived past the one that just saw a
    /// transaction. Newly derived addresses are queued for a rescan.
    fn maybe_extend_window(&mut self, script_hash: &Hash) {
        let Some(&(window, index)) = self.script_origin.get(script_hash) else {
            return;
        };

        let wanted = index.saturating_add(1).saturating_add(GAP_LIMIT);
        let mut extended = false;
        while self.windows[window].next_index < wanted {
            match self.peek_batch(window) {
                Ok(scripts) => {
                    let scripts = self.cache_batch(window, scripts);
                    self.pending_rescan.extend(scripts);
                    extended = true;
                }
                Err(error) => {
                    error!("Error deriving addresses: {error:?}");
                    break;
                }
            }
        }
        if extended {
            self.persist_pending_rescan();
        }
    }

    fn persist_pending_rescan(&self) {
        if let Err(error) = self.database.save_pending_rescan(&self.pending_rescan) {
            error!("Could not persist the addresses pending a rescan: {error:?}");
        }
    }

    fn get_address_utxos(&self, script_hash: &Hash) -> Option<Vec<(TxOut, OutPoint)>> {
        let address = self.address_map.get(script_hash)?;
        let utxos = &address.utxos;
        let mut address_utxos = Vec::new();
        for utxo in utxos {
            let tx = self.get_transaction(&utxo.txid)?;
            let txout = tx.tx.output.get(utxo.vout as usize)?;
            address_utxos.push((txout.clone(), *utxo));
        }

        Some(address_utxos)
    }

    fn get_transaction(&self, txid: &Txid) -> Option<CachedTransaction> {
        self.database.get_transaction(txid).ok()
    }

    /// Returns all transactions this address has, both input and outputs
    fn get_address_history(&self, script_hash: &Hash) -> Option<Vec<CachedTransaction>> {
        let cached_script = self.address_map.get(script_hash)?;
        let mut transactions: Vec<_> = cached_script
            .transactions
            .iter()
            .filter_map(|txid| self.get_transaction(txid))
            .collect();
        let mut unconfirmed = transactions.clone();

        transactions.retain(|tx| tx.height != 0);
        transactions.sort();
        unconfirmed.retain(|tx| tx.height == 0);
        transactions.extend(unconfirmed);
        Some(transactions)
    }

    /// Get [Merkle Proof]
    ///
    /// Returns none if a given Txid is an unconfirmed transaction or unrelated with your wallet, defined by the xpubs, descriptors and addresses in your `config.toml`.
    ///
    /// [Merkle Proof]: https://developer.bitcoin.org/devguide/block_chain.html#merkle-trees
    fn get_merkle_proof(&self, txid: &Txid) -> Option<MerkleProof> {
        // If a given transaction is cached, but the merkle tree doesn't exist, that means
        // it is an unconfirmed transaction.
        self.get_transaction(txid)?.clone().merkle_block
    }

    /// Adds a new address to track, should be called at wallet setup and every once in a while
    /// to cache new addresses, as we use the first ones. Only requires a script to cache.
    fn cache_address(&mut self, script_pk: ScriptBuf) {
        let hash = get_spk_hash(&script_pk);
        if self.address_map.contains_key(&hash) {
            return;
        }
        let new_address = CachedAddress {
            balance: 0,
            script: script_pk,
            script_hash: hash,
            transactions: Vec::new(),
            utxos: Vec::new(),
        };
        self.database.save(&new_address);

        self.address_map.insert(hash, new_address);
        self.script_set.insert(hash);
    }

    /// Setup is the first command that should be executed. In a new cache. It sets our wallet's
    /// state, like the height we should start scanning and the wallet's descriptor.
    fn setup(&self) -> Result<(), WatchOnlyError<D::Error>> {
        if self.database.get_descriptors().is_err() {
            self.database.set_cache_height(0)?;
        }
        Ok(())
    }

    fn find_unconfirmed(&self) -> Result<Vec<Transaction>, WatchOnlyError<D::Error>> {
        let transactions = self.database.list_transactions()?;
        let mut unconfirmed = Vec::new();

        for tx in transactions {
            let tx = self.database.get_transaction(&tx)?;
            if tx.height == 0 {
                unconfirmed.push(tx.tx);
            }
        }
        Ok(unconfirmed)
    }

    fn find_spend(&self, transaction: &Transaction) -> Vec<(usize, TxOut)> {
        let mut spends = Vec::new();
        for (idx, input) in transaction.input.iter().enumerate() {
            if self.utxo_index.contains_key(&input.previous_output) {
                let prev_tx = self.get_transaction(&input.previous_output.txid).unwrap();
                spends.push((
                    idx,
                    prev_tx.tx.output[input.previous_output.vout as usize].clone(),
                ));
            }
        }
        spends
    }

    fn cache_mempool_transaction(&mut self, transaction: &Transaction) -> Vec<TxOut> {
        let mut coins = self.find_spend(transaction);
        for (idx, spend) in coins.iter() {
            let script = self
                .address_map
                .get(&get_spk_hash(&spend.script_pubkey))
                .unwrap()
                .to_owned();
            self.cache_transaction(
                transaction,
                0,
                spend.value.to_sat(),
                MerkleProof::default(),
                0,
                *idx,
                true,
                script.script_hash,
            )
        }
        for (idx, out) in transaction.output.iter().enumerate() {
            let spk_hash = get_spk_hash(&out.script_pubkey);
            if self.script_set.contains(&spk_hash) {
                let script = self.address_map.get(&spk_hash).unwrap().to_owned();
                coins.push((idx, out.clone()));
                self.cache_transaction(
                    transaction,
                    0,
                    out.value.to_sat(),
                    MerkleProof::default(),
                    0,
                    idx,
                    true,
                    script.script_hash,
                )
            }
        }
        coins
            .iter()
            .cloned()
            .unzip::<usize, TxOut, Vec<usize>, Vec<TxOut>>()
            .1
    }

    fn save_mempool_tx(&mut self, hash: Hash, transaction_to_cache: CachedTransaction) {
        if let Some(address) = self.address_map.get_mut(&hash) {
            if !address.transactions.contains(&transaction_to_cache.hash) {
                address.transactions.push(transaction_to_cache.hash);
                self.database.update(address);
            }
        }
    }

    fn save_non_mempool_tx(
        &mut self,
        transaction: &Transaction,
        is_spend: bool,
        value: u64,
        index: usize,
        hash: Hash,
        transaction_to_cache: CachedTransaction,
    ) {
        if let Some(address) = self.address_map.get_mut(&hash) {
            // Whether the address changed and has to be written back. A transaction we already
            // list can still change it: one that spends from and pays to the same script, or
            // pays it twice, touches the address once per input and output.
            let mut changed = false;

            // This transaction is spending from this address, so we should remove the UTXO
            if is_spend {
                assert!(value <= address.balance);
                address.balance -= value;
                let input = transaction
                    .input
                    .get(index)
                    .expect("Malformed call, index is bigger than the output vector");
                let idx = address
                    .utxos
                    .iter()
                    .position(|utxo| *utxo == input.previous_output);
                if let Some(idx) = idx {
                    let utxo = address.utxos.remove(idx);
                    self.utxo_index.remove(&utxo);
                }
                changed = true;
            } else {
                // This transaction is creating a new utxo for this address
                let utxo = OutPoint {
                    txid: transaction.compute_txid(),
                    vout: index as u32,
                };
                // Guard against re-caching the same output (e.g. a block processed by
                // both forward sync and a rescan), which would duplicate the outpoint
                // and double-count the balance.
                if !address.utxos.contains(&utxo) {
                    address.utxos.push(utxo);
                    self.utxo_index.insert(utxo, hash);
                    address.balance += value;
                    changed = true;
                }
            }

            if !address.transactions.contains(&transaction_to_cache.hash) {
                address.transactions.push(transaction_to_cache.hash);
                changed = true;
            }
            if changed {
                self.database.update(address);
            }
        }
    }

    /// Caches a new transaction. This method may be called for addresses we don't follow yet,
    /// this automatically makes we follow this address.
    #[allow(clippy::too_many_arguments)]
    fn cache_transaction(
        &mut self,
        transaction: &Transaction,
        height: u32,
        value: u64,
        merkle_block: MerkleProof,
        position: u32,
        index: usize,
        is_spend: bool,
        hash: sha256::Hash,
    ) {
        let transaction_to_cache = CachedTransaction {
            height,
            merkle_block: Some(merkle_block),
            tx: transaction.clone(),
            hash: transaction.compute_txid(),
            position,
        };
        self.database
            .save_transaction(&transaction_to_cache)
            .expect("Database not working");

        if let Entry::Vacant(e) = self.address_map.entry(hash) {
            let script = transaction.output[index].script_pubkey.clone();
            // This means `cache_transaction` have been called with an address we don't
            // follow. This may be useful for caching new addresses without re-scanning.
            // We can track this address from now onwards, but the past history is only
            // available with full rescan
            let new_address = CachedAddress {
                balance: 0,
                script,
                script_hash: hash,
                transactions: Vec::new(),
                utxos: Vec::new(),
            };
            self.database.save(&new_address);

            e.insert(new_address);
            self.script_set.insert(hash);
        }
        self.maybe_extend_window(&hash);
        // Confirmed transaction
        if height > 0 {
            return self.save_non_mempool_tx(
                transaction,
                is_spend,
                value,
                index,
                hash,
                transaction_to_cache,
            );
        }
        // Unconfirmed transaction
        self.save_mempool_tx(hash, transaction_to_cache);
    }
}

/// Holds all addresses and associated transactions. We need a database with some basic
/// methods, to store all data
pub struct AddressCache<D: AddressCacheDatabase> {
    inner: RwLock<AddressCacheInner<D>>,
    merkle: Box<dyn MerkleBackend>,
}

impl<D: AddressCacheDatabase + Sync + Send + 'static> BlockConsumer for AddressCache<D> {
    fn wants_spent_utxos(&self) -> bool {
        false
    }

    fn on_block(
        &self,
        block: &Block,
        height: u32,
        _spent_utxos: Option<&HashMap<OutPoint, UtxoData>>,
    ) {
        self.block_process(block, height);
    }
}

impl<D: AddressCacheDatabase> AddressCache<D> {
    pub fn new(database: D, merkle: impl MerkleBackend + 'static) -> Self {
        Self {
            inner: RwLock::new(AddressCacheInner::new(database)),
            merkle: Box::new(merkle),
        }
    }

    pub fn get_utxo(&self, outpoint: &OutPoint) -> Option<TxOut> {
        let inner = self.inner.read().expect("poisoned lock");
        // a dirty way to check if the utxo is still unspent
        let _ = inner.utxo_index.get(outpoint)?;
        let tx = inner.get_transaction(&outpoint.txid)?;

        Some(tx.tx.output[outpoint.vout as usize].clone())
    }

    pub fn n_cached_addresses(&self) -> usize {
        let inner = self.inner.read().expect("poisoned lock");
        inner.address_map.len()
    }

    /// Returns the balance of this address, debts (spends) are taken in account
    pub fn get_address_balance(&self, script_hash: &Hash) -> Option<u64> {
        let inner = self.inner.read().expect("poisoned lock");

        Some(inner.address_map.get(script_hash)?.balance)
    }

    pub fn get_cached_addresses(&self) -> Vec<ScriptBuf> {
        let inner = self.inner.read().expect("poisoned lock");
        inner
            .address_map
            .values()
            .map(|address| address.script.clone())
            .collect()
    }

    pub fn bump_height(&self, height: u32) {
        let inner = self.inner.read().expect("poisoned lock");
        inner
            .database
            .set_cache_height(height)
            .expect("Database is not working");
    }

    pub fn get_cache_height(&self) -> u32 {
        let inner = self.inner.read().expect("poisoned lock");
        inner.database.get_cache_height().unwrap_or(0)
    }

    /// Tells whether or not a descriptor is already cached
    pub fn is_cached(&self, desc: &str) -> Result<bool, WatchOnlyError<D::Error>> {
        let inner = self.inner.read().expect("poisoned lock");
        let known_descs = inner.database.get_descriptors()?;
        Ok(known_descs.iter().any(|s| s == desc))
    }

    /// Tells whether an address is already cached
    pub fn is_address_cached(&self, script_hash: &Hash) -> bool {
        let inner = self.inner.read().expect("poisoned lock");
        inner.address_map.contains_key(script_hash)
    }

    /// Push a descriptor into the wallet checking whether it is already cached, returning an error if so
    pub fn push_descriptor(
        &self,
        descriptor: &str,
    ) -> Result<Vec<ScriptBuf>, WatchOnlyError<D::Error>> {
        if self.is_cached(descriptor)? {
            return Err(WatchOnlyError::DuplicateDescriptor(descriptor.to_string()));
        }

        let mut inner = self.inner.write().expect("poisoned lock");
        let addresses = inner
            .track_descriptor(descriptor)
            .map_err(WatchOnlyError::InvalidDescriptor)?;
        inner.database.save_descriptor(descriptor)?;

        Ok(addresses)
    }

    /// Addresses derived since the last call because a transaction landed near the end of a
    /// descriptor's derived range. They are followed from now on; their past history is only
    /// found by rescanning them.
    pub fn take_addresses_pending_rescan(&self) -> Vec<ScriptBuf> {
        let mut inner = self.inner.write().expect("poisoned lock");
        let addresses = core::mem::take(&mut inner.pending_rescan);
        if !addresses.is_empty() {
            inner.persist_pending_rescan();
        }
        addresses
    }

    /// Hands back addresses taken with [`Self::take_addresses_pending_rescan`] that could not
    /// be scanned after all.
    pub fn requeue_addresses_pending_rescan(&self, addresses: Vec<ScriptBuf>) {
        if addresses.is_empty() {
            return;
        }
        let mut inner = self.inner.write().expect("poisoned lock");
        inner.pending_rescan.extend(addresses);
        inner.persist_pending_rescan();
    }

    /// Adds an XPUB to the wallet, derives descriptors from it, saves these descriptors persistently,
    /// derives addresses, and caches them if they're not cached already.
    pub fn push_xpub(&self, xpub: &str, network: Network) -> Result<(), WatchOnlyError<D::Error>> {
        let descriptors = parse_xpub(xpub, network).map_err(WatchOnlyError::InvalidDescriptor)?;

        for descriptor in descriptors {
            self.push_descriptor(&descriptor)?;
        }

        Ok(())
    }

    pub fn get_position(&self, txid: &Txid) -> Option<u32> {
        let inner = self.inner.read().expect("poisoned lock");
        Some(inner.get_transaction(txid)?.position)
    }

    pub fn get_height(&self, txid: &Txid) -> Option<u32> {
        let inner = self.inner.read().expect("poisoned lock");
        Some(inner.get_transaction(txid)?.height)
    }

    pub fn get_cached_transaction(&self, txid: &Txid) -> Option<String> {
        let inner = self.inner.read().expect("poisoned lock");
        let tx = inner.get_transaction(txid)?;
        Some(serialize_hex(&tx.tx))
    }

    pub fn setup(&self) -> Result<(), WatchOnlyError<D::Error>> {
        let inner = self.inner.read().expect("poisoned lock");
        inner.setup()
    }

    pub fn block_process(&self, block: &Block, height: u32) -> Vec<(Transaction, TxOut)> {
        let mut inner = self.inner.write().expect("poisoned lock");
        inner.block_process(block, height, self.merkle.as_ref())
    }

    pub fn get_address_utxos(&self, script_hash: &Hash) -> Option<Vec<(TxOut, OutPoint)>> {
        let inner = self.inner.read().expect("poisoned lock");
        inner.get_address_utxos(script_hash)
    }

    pub fn get_transaction(&self, txid: &Txid) -> Option<CachedTransaction> {
        let inner = self.inner.read().expect("poisoned lock");
        inner.get_transaction(txid)
    }

    pub fn get_address_history(&self, script_hash: &Hash) -> Option<Vec<CachedTransaction>> {
        let inner = self.inner.read().expect("poisoned lock");
        inner.get_address_history(script_hash)
    }

    /// Returns the Merkle Proof for a given txid.
    ///
    /// Fails if a given Txid is an unconfirmed transaction.
    pub fn get_merkle_proof(&self, txid: &Txid) -> Option<MerkleProof> {
        let inner = self.inner.read().expect("poisoned lock");
        inner.get_merkle_proof(txid)
    }

    pub fn get_stats(&self) -> Result<Stats, WatchOnlyError<D::Error>> {
        let inner = self.inner.read().expect("poisoned lock");
        inner
            .database
            .get_stats()
            .map_err(WatchOnlyError::DatabaseError)
    }

    pub fn find_unconfirmed(&self) -> Result<Vec<Transaction>, WatchOnlyError<D::Error>> {
        let inner = self.inner.read().expect("poisoned lock");
        inner.find_unconfirmed()
    }

    pub fn cache_address(&self, script_pk: ScriptBuf) {
        let mut inner = self.inner.write().expect("poisoned lock");
        inner.cache_address(script_pk)
    }

    pub fn cache_mempool_transaction(&self, transaction: &Transaction) -> Vec<TxOut> {
        let mut inner = self.inner.write().expect("poisoned lock");
        inner.cache_mempool_transaction(transaction)
    }

    pub fn save_mempool_tx(&self, hash: Hash, transaction_to_cache: CachedTransaction) {
        let mut inner = self.inner.write().expect("poisoned lock");
        inner.save_mempool_tx(hash, transaction_to_cache)
    }

    pub fn save_non_mempool_tx(
        &self,
        transaction: &Transaction,
        is_spend: bool,
        value: u64,
        index: usize,
        hash: Hash,
        transaction_to_cache: CachedTransaction,
    ) {
        let mut inner = self.inner.write().expect("poisoned lock");
        inner.save_non_mempool_tx(
            transaction,
            is_spend,
            value,
            index,
            hash,
            transaction_to_cache,
        )
    }

    pub fn get_descriptors(&self) -> Result<Vec<String>, WatchOnlyError<D::Error>> {
        let inner = self.inner.read().expect("poisoned lock");
        inner
            .database
            .get_descriptors()
            .map_err(WatchOnlyError::DatabaseError)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn cache_transaction(
        &self,
        transaction: &Transaction,
        height: u32,
        value: u64,
        merkle_block: MerkleProof,
        position: u32,
        index: usize,
        is_spend: bool,
        hash: sha256::Hash,
    ) {
        let mut inner = self.inner.write().expect("poisoned lock");
        inner.cache_transaction(
            transaction,
            height,
            value,
            merkle_block,
            position,
            index,
            is_spend,
            hash,
        )
    }
}

#[cfg(test)]
mod test {
    use core::str::FromStr;

    use bitcoin::Address;
    use bitcoin::OutPoint;
    use bitcoin::ScriptBuf;
    use bitcoin::Transaction;
    use bitcoin::TxOut;
    use bitcoin::Txid;
    use bitcoin::address::NetworkChecked;
    use bitcoin::consensus::Decodable;
    use bitcoin::consensus::deserialize;
    use bitcoin::hashes::hex::FromHex;
    use bitcoin::hashes::sha256;
    use floresta_chain::pruned_utreexo::merkle::ConsensusMerkle;
    use floresta_common::get_spk_hash;
    use floresta_common::prelude::*;

    use super::AddressCache;
    use super::memory_database::MemoryDatabase;
    use crate::DERIVATION_COUNT;
    use crate::descriptor::derive_addresses_from_descriptor;
    use crate::descriptor::derive_addresses_from_parsed_descriptor;
    use crate::descriptor::parse_and_split_descriptor;
    use crate::merkle::MerkleProof;

    const BLOCK_FIRST_UTXO: &str = "00000020b4f594a390823c53557c5a449fa12413cbbae02be529c11c4eb320ff8e000000dd1211eb35ca09dc0ee519b0f79319fae6ed32c66f8bbf353c38513e2132c435474d81633c4b011e195a220002010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0403edce01feffffff028df2052a0100000016001481113cad52683679a83e76f76f84a4cfe36f75010000000000000000776a24aa21a9ed67863b4f356b7b9f3aab7a2037615989ef844a0917fb0a1dcd6c23a383ee346b4c4fecc7daa2490047304402203768ff10a948a2dd1825cc5a3b0d336d819ea68b5711add1390b290bf3b1cba202201d15e73791b2df4c0904fc3f7c7b2f22ab77762958e9bc76c625138ad3a04d290100012000000000000000000000000000000000000000000000000000000000000000000000000002000000000101be07b18750559a418d144f1530be380aa5f28a68a0269d6b2d0e6ff3ff25f3200000000000feffffff0240420f00000000001600142b6a2924aa9b1b115d1ac3098b0ba0e6ed510f2a326f55d94c060000160014c2ed86a626ee74d854a12c9bb6a9b72a80c0ddc50247304402204c47f6783800831bd2c75f44d8430bf4d962175349dc04d690a617de6c1eaed502200ffe70188a6e5ad89871b2acb4d0f732c2256c7ed641d2934c6e84069c792abc012103ba174d9c66078cf813d0ac54f5b19b5fe75104596bdd6c1731d9436ad8776f41ecce0100";
    const BLOCK_SPEND: &str = "000000203ea734fa2c8dee7d3194878c9eaf6e83a629f79b3076ec857793995e01010000eb99c679c0305a1ac0f5eb2a07a9f080616105e605b92b8c06129a2451899225ab5481633c4b011e0b26720102020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0403efce01feffffff026ef2052a01000000225120a1a1b1376d5165617a50a6d2f59abc984ead8a92df2b25f94b53dbc2151824730000000000000000776a24aa21a9ed1b4c48a7220572ff3ab3d2d1c9231854cb62542fbb1e0a4b21ebbbcde8d652bc4c4fecc7daa2490047304402204b37c41fce11918df010cea4151737868111575df07f7f2945d372e32a6d11dd02201658873a8228d7982df6bdbfff5d0cad1d6f07ee400e2179e8eaad8d115b7ed001000120000000000000000000000000000000000000000000000000000000000000000000000000020000000001017ca523c5e6df0c014e837279ab49be1676a9fe7571c3989aeba1e5d534f4054a0000000000fdffffff01d2410f00000000001600142b6a2924aa9b1b115d1ac3098b0ba0e6ed510f2a02473044022071b8583ba1f10531b68cb5bd269fb0e75714c20c5a8bce49d8a2307d27a082df022069a978dac00dd9d5761aa48c7acc881617fa4d2573476b11685596b17d437595012103b193d06bd0533d053f959b50e3132861527e5a7a49ad59c5e80a265ff6a77605eece0100";

    fn deserialize_from_str<T: Decodable>(thing: &str) -> T {
        let hex = Vec::from_hex(thing).unwrap();
        deserialize(&hex).unwrap()
    }

    fn get_test_cache() -> AddressCache<MemoryDatabase> {
        let database = MemoryDatabase::new();
        AddressCache::new(database, ConsensusMerkle)
    }

    fn get_test_address() -> (Address<NetworkChecked>, sha256::Hash) {
        let address = Address::from_str("tb1q9d4zjf92nvd3zhg6cvyckzaqumk4zre26x02q9")
            .unwrap()
            .assume_checked();
        let script_hash = get_spk_hash(&address.script_pubkey());
        (address, script_hash)
    }

    #[test]
    fn test_create() {
        let _ = get_test_cache();
    }

    #[test]
    fn test_cache_address() {
        let (address, script_hash) = get_test_address();
        let cache = get_test_cache();
        // Should have no address before caching
        assert_eq!(cache.n_cached_addresses(), 0);

        cache.cache_address(address.script_pubkey());
        // Assert we indeed have one cached address
        assert_eq!(cache.n_cached_addresses(), 1);
        assert_eq!(cache.get_address_balance(&script_hash), Some(0));
        assert_eq!(cache.get_address_history(&script_hash), Some(Vec::new()));
    }

    #[test]
    fn test_cache_transaction() {
        // Signet transaction with id 6bb0665122c7dcecc6e6c45b6384ee2bdce148aea097896e6f3e9e08070353ea
        // block hash 0000009298f9e75a91fa763c78b66d1555cb059d9ca9d45601eed2b95166a151.
        let transaction = "020000000001017ca523c5e6df0c014e837279ab49be1676a9fe7571c3989aeba1e5d534f4054a0000000000fdffffff01d2410f00000000001600142b6a2924aa9b1b115d1ac3098b0ba0e6ed510f2a02473044022071b8583ba1f10531b68cb5bd269fb0e75714c20c5a8bce49d8a2307d27a082df022069a978dac00dd9d5761aa48c7acc881617fa4d2573476b11685596b17d437595012103b193d06bd0533d053f959b50e3132861527e5a7a49ad59c5e80a265ff6a77605eece0100";
        let transaction = Vec::from_hex(transaction).unwrap();
        let transaction = deserialize(&transaction).unwrap();

        let merkle_block = "0100000000000000ea530307089e3e6f6e8997a0ae48e1dc2bee84635bc4e6c6ecdcc7225166b06b010000000000000034086ef398efcdec47b37241221c8f4613e02bc31026cc74d07ddb3092e6d6e7";
        let merkle_block = Vec::from_hex(merkle_block).unwrap();
        let merkle_block = deserialize(&merkle_block).unwrap();

        let (_, script_hash) = get_test_address();
        let cache = get_test_cache();

        cache.cache_transaction(
            &transaction,
            118511,
            transaction.output[0].value.to_sat(),
            merkle_block,
            1,
            0,
            false,
            get_spk_hash(&transaction.output[0].script_pubkey),
        );

        assert_eq!(
            script_hash,
            get_spk_hash(&transaction.output[0].script_pubkey)
        );

        let balance = cache.get_address_balance(&script_hash);
        let history = cache.get_address_history(&script_hash).unwrap();
        let cached_merkle_block = cache.get_merkle_proof(&transaction.compute_txid()).unwrap();
        assert_eq!(balance, Some(999890));
        assert_eq!(
            Ok(history[0].hash),
            Txid::from_str("6bb0665122c7dcecc6e6c45b6384ee2bdce148aea097896e6f3e9e08070353ea")
        );
        let expected_hashes = Vec::from([String::from(
            "e7d6e69230db7dd074cc2610c32be013468f1c224172b347eccdef98f36e0834",
        )]);

        assert_eq!(cached_merkle_block.pos, 1u64);
        assert_eq!(cached_merkle_block.to_string_array(), expected_hashes);

        // TESTS FOR SMALL, HELPER FUNCTIONS

        // [get_position]
        assert_eq!(cache.get_position(&transaction.compute_txid()).unwrap(), 1);

        // [get_height]
        assert_eq!(
            cache.get_height(&transaction.compute_txid()).unwrap(),
            118511
        );

        // [get_cached_transaction]
        assert!(
            cache
                .get_cached_transaction(&transaction.compute_txid())
                .is_some()
        );

        // [get_address_utxos]
        let tx_out = transaction.output[0].clone();
        let outpoint = OutPoint {
            txid: transaction.compute_txid(),
            vout: 0,
        };
        assert_eq!(
            cache.get_address_utxos(&script_hash).unwrap(),
            vec![(tx_out, outpoint)]
        );

        // [find_unconfirmed] Caching am unconfirmed transaction
        let transaction = "01000000010b7e3ac7e68944dc7a7115362391c3b7975d60f4fbe4af0ca924a172bfe7a7d9000000006b483045022100e0ff6984e5c2e16df6f309b759b75e04adf6930593b6043cd9134f87efb7e07c02206544a9f265f6041f0e3e2bd11a95ea75a112d3dc05647a9b01eca0d352feeb380121024f9c3deb05e81a3ddb17dadcf283fb132894aa70ab127395a03a3e9d382f13a3ffffffff022c92ae00000000001976a914ca9755ffb8f0e5aeca43478d8620e1a35b3baada88acc0894601000000001976a914b62ad08a3ffc469e9c0df75d1ceca49a88345fc888ac00000000";
        let transaction = Vec::from_hex(transaction).unwrap();
        let transaction = deserialize(&transaction).unwrap();

        cache.cache_transaction(
            &transaction,
            0,
            transaction.output[1].value.to_sat(),
            MerkleProof::default(),
            2,
            1,
            false,
            get_spk_hash(&transaction.output[1].script_pubkey),
        );

        assert_eq!(
            cache.find_unconfirmed().unwrap()[0].compute_txid(),
            transaction.compute_txid()
        );
    }

    #[test]
    fn test_process_block() {
        let (address, script_hash) = get_test_address();
        let cache = get_test_cache();
        cache.cache_address(address.script_pubkey());

        let block = "000000203ea734fa2c8dee7d3194878c9eaf6e83a629f79b3076ec857793995e01010000eb99c679c0305a1ac0f5eb2a07a9f080616105e605b92b8c06129a2451899225ab5481633c4b011e0b26720102020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0403efce01feffffff026ef2052a01000000225120a1a1b1376d5165617a50a6d2f59abc984ead8a92df2b25f94b53dbc2151824730000000000000000776a24aa21a9ed1b4c48a7220572ff3ab3d2d1c9231854cb62542fbb1e0a4b21ebbbcde8d652bc4c4fecc7daa2490047304402204b37c41fce11918df010cea4151737868111575df07f7f2945d372e32a6d11dd02201658873a8228d7982df6bdbfff5d0cad1d6f07ee400e2179e8eaad8d115b7ed001000120000000000000000000000000000000000000000000000000000000000000000000000000020000000001017ca523c5e6df0c014e837279ab49be1676a9fe7571c3989aeba1e5d534f4054a0000000000fdffffff01d2410f00000000001600142b6a2924aa9b1b115d1ac3098b0ba0e6ed510f2a02473044022071b8583ba1f10531b68cb5bd269fb0e75714c20c5a8bce49d8a2307d27a082df022069a978dac00dd9d5761aa48c7acc881617fa4d2573476b11685596b17d437595012103b193d06bd0533d053f959b50e3132861527e5a7a49ad59c5e80a265ff6a77605eece0100";
        let block = deserialize(&Vec::from_hex(block).unwrap()).unwrap();
        cache.block_process(&block, 118511);

        let balance = cache.get_address_balance(&script_hash);
        let history = cache.get_address_history(&script_hash).unwrap();
        let transaction_id =
            Txid::from_str("6bb0665122c7dcecc6e6c45b6384ee2bdce148aea097896e6f3e9e08070353ea")
                .unwrap();
        let cached_merkle_block = cache.get_merkle_proof(&transaction_id).unwrap();
        assert_eq!(balance, Some(999890));
        assert_eq!(
            history[0].hash,
            Txid::from_str("6bb0665122c7dcecc6e6c45b6384ee2bdce148aea097896e6f3e9e08070353ea")
                .unwrap()
        );
        let expected_hashes = Vec::from([String::from(
            "e7d6e69230db7dd074cc2610c32be013468f1c224172b347eccdef98f36e0834",
        )]);

        assert_eq!(cached_merkle_block.pos, 1u64);
        assert_eq!(cached_merkle_block.to_string_array(), expected_hashes);

        // TESTS FOR SMALL HELPER FUNCTIONS

        // [bump_height], [get_cache_height], [set_cache_height]
        cache.bump_height(118511);
        assert_eq!(cache.get_cache_height(), 118511);

        // [is_cached], [push_descriptor]
        let desc = "wsh(sortedmulti(1,[54ff5a12/48h/1h/0h/2h]tpubDDw6pwZA3hYxcSN32q7a5ynsKmWr4BbkBNHydHPKkM4BZwUfiK7tQ26h7USm8kA1E2FvCy7f7Er7QXKF8RNptATywydARtzgrxuPDwyYv4x/<0;1>/*,[bcf969c0/48h/1h/0h/2h]tpubDEFdgZdCPgQBTNtGj4h6AehK79Jm4LH54JrYBJjAtHMLEAth7LuY87awx9ZMiCURFzFWhxToRJK6xp39aqeJWrG5nuW3eBnXeMJcvDeDxfp/<0;1>/*))#fuw35j0q";
        let derived = cache.push_descriptor(desc).unwrap();
        assert!(cache.is_cached(desc).unwrap());

        // The receive and change chains each got their first batch
        assert_eq!(derived.len(), 2 * DERIVATION_COUNT as usize);
        assert_eq!(
            cache.n_cached_addresses(),
            1 + 2 * DERIVATION_COUNT as usize
        );
    }

    #[test]
    fn test_multiple_transaction() {
        let block1 = deserialize_from_str(BLOCK_FIRST_UTXO);
        let block2 = deserialize_from_str(BLOCK_SPEND);

        let spk = ScriptBuf::from_hex("00142b6a2924aa9b1b115d1ac3098b0ba0e6ed510f2a")
            .expect("Valid address");
        let script_hash = get_spk_hash(&spk);
        let cache = get_test_cache();

        cache.cache_address(spk);

        cache.block_process(&block1, 118511);
        cache.block_process(&block2, 118509);

        let address = cache.inner.read().unwrap();
        let address = address.address_map.get(&script_hash).unwrap();

        assert_eq!(address.transactions.len(), 2);
        assert_eq!(address.utxos.len(), 1);
    }

    #[test]
    fn test_redelivered_self_spend_is_persisted() {
        use bitcoin::Amount;
        use bitcoin::Block;
        use bitcoin::OutPoint;
        use bitcoin::Sequence;
        use bitcoin::Transaction;
        use bitcoin::TxIn;
        use bitcoin::TxOut;
        use bitcoin::Witness;
        use bitcoin::absolute::LockTime;
        use bitcoin::transaction::Version;

        let spk = ScriptBuf::from_hex("00142b6a2924aa9b1b115d1ac3098b0ba0e6ed510f2a")
            .expect("Valid address");
        let script_hash = get_spk_hash(&spk);
        let pay_to_us = |value| TxOut {
            value: Amount::from_sat(value),
            script_pubkey: spk.clone(),
        };
        let spending = |previous_output| TxIn {
            previous_output,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        };
        let transaction = |input, output| Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![input],
            output: vec![output],
        };
        let block_with = |tx| {
            let mut block: Block = deserialize_from_str(BLOCK_FIRST_UTXO);
            block.txdata = vec![tx];
            block
        };

        // `funding` pays us; `self_spend` spends that output and pays the change back to the
        // same script.
        let funding = transaction(spending(OutPoint::null()), pay_to_us(10_000));
        let funding_outpoint = OutPoint {
            txid: funding.compute_txid(),
            vout: 0,
        };
        let self_spend = transaction(spending(funding_outpoint), pay_to_us(9_000));
        let change_outpoint = OutPoint {
            txid: self_spend.compute_txid(),
            vout: 0,
        };

        let cache = get_test_cache();
        cache.cache_address(spk);

        // The spending block connects while a rescan is still on its way to the funding one,
        // so the spend goes unnoticed; the rescan then delivers both, in order.
        cache.block_process(&block_with(self_spend.clone()), 2);
        cache.block_process(&block_with(funding), 1);
        cache.block_process(&block_with(self_spend), 2);

        let inner = cache.inner.read().unwrap();
        let in_memory = inner.address_map.get(&script_hash).unwrap();
        assert_eq!(in_memory.utxos, vec![change_outpoint]);
        assert_eq!(in_memory.balance, 9_000);

        // What a restart would load. The spend was for a transaction the address already
        // listed (it received its change first), which used to skip the write.
        let persisted = crate::AddressCacheDatabase::load(&inner.database).unwrap();
        let persisted = persisted
            .iter()
            .find(|address| address.script_hash == script_hash)
            .unwrap();
        assert_eq!(persisted.utxos, vec![change_outpoint]);
        assert_eq!(persisted.balance, 9_000);
    }

    /// The public BIP 84 descriptor from the descriptor tests, receive chain only.
    const RECEIVE_DESCRIPTOR: &str = "wpkh(xpub6CbPqb3FCEjaF4LnfMwdEAUxKhC6ZP1sJzGiMMz3mfmcjXdFPM9LB9S8HSChXW593am685964YZk8Hng1ekynqNWGRZfpo8PpDaUmyvQqvY/0/*)";
    const MULTIPATH_DESCRIPTOR: &str = "wpkh(xpub6CbPqb3FCEjaF4LnfMwdEAUxKhC6ZP1sJzGiMMz3mfmcjXdFPM9LB9S8HSChXW593am685964YZk8Hng1ekynqNWGRZfpo8PpDaUmyvQqvY/<0;1>/*)";

    fn receive_script(index: u32) -> ScriptBuf {
        derive_addresses_from_descriptor(RECEIVE_DESCRIPTOR, index, 1)
            .unwrap()
            .remove(0)
    }

    /// A block whose only transaction pays `value` to `script` from nowhere in particular.
    fn block_paying(script: ScriptBuf, value: u64) -> bitcoin::Block {
        use bitcoin::Amount;
        use bitcoin::Sequence;
        use bitcoin::TxIn;
        use bitcoin::Witness;
        use bitcoin::absolute::LockTime;
        use bitcoin::transaction::Version;

        let mut block: bitcoin::Block = deserialize_from_str(BLOCK_FIRST_UTXO);
        block.txdata = vec![Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(value),
                script_pubkey: script,
            }],
        }];
        block
    }

    #[test]
    fn spent_outputs_are_reported_so_their_address_can_be_notified() {
        use bitcoin::Sequence;
        use bitcoin::TxIn;
        use bitcoin::Witness;

        let ours = receive_script(0);
        // A script we don't follow
        let theirs = receive_script(1);
        let cache = get_test_cache();
        cache.cache_address(ours.clone());

        let funding = block_paying(ours.clone(), 10_000);
        let funding_txid = funding.txdata[0].compute_txid();
        assert_eq!(cache.block_process(&funding, 1).len(), 1);

        // Spends our only coin, paying someone else: nothing is received, but the
        // address that lost its coin has to be told.
        let mut spend = block_paying(theirs.clone(), 9_000);
        spend.txdata[0].input = vec![TxIn {
            previous_output: OutPoint {
                txid: funding_txid,
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }];
        let touched = cache.block_process(&spend, 2);
        assert_eq!(touched.len(), 1);
        assert_eq!(touched[0].1.script_pubkey, ours);
        assert_eq!(touched[0].1.value.to_sat(), 10_000);
        assert_eq!(cache.get_address_balance(&get_spk_hash(&ours)), Some(0));
    }

    #[test]
    fn a_transaction_near_the_end_of_the_window_derives_more_addresses() {
        let cache = get_test_cache();
        let derived = cache.push_descriptor(MULTIPATH_DESCRIPTOR).unwrap();
        assert_eq!(derived.len(), 200);
        assert!(cache.take_addresses_pending_rescan().is_empty());

        // Well inside the window: nothing to do
        cache.block_process(&block_paying(receive_script(50), 1_000), 1);
        assert_eq!(cache.n_cached_addresses(), 200);
        assert!(cache.take_addresses_pending_rescan().is_empty());

        // Fewer than GAP_LIMIT unused addresses left past index 95: derive the next batch
        // of the receive chain, and queue it for a rescan.
        cache.block_process(&block_paying(receive_script(95), 1_000), 2);
        assert_eq!(cache.n_cached_addresses(), 300);
        let pending = cache.take_addresses_pending_rescan();
        assert_eq!(pending.len(), DERIVATION_COUNT as usize);
        assert!(pending.contains(&receive_script(150)));
        assert!(cache.is_address_cached(&get_spk_hash(&receive_script(199))));
        assert!(!cache.is_address_cached(&get_spk_hash(&receive_script(200))));

        // A hit far beyond the window keeps deriving until the gap is covered again
        cache.block_process(&block_paying(receive_script(199), 1_000), 3);
        assert_eq!(cache.take_addresses_pending_rescan().len(), 100);
        assert!(cache.is_address_cached(&get_spk_hash(&receive_script(299))));
    }

    #[test]
    fn derived_windows_are_rebuilt_from_the_database() {
        use crate::kv_database::KvDatabase;

        let datadir = format!("./tmp-db/{}.watch-only-windows/", rand::random::<u32>());
        {
            let cache = AddressCache::new(KvDatabase::new(&datadir).unwrap(), ConsensusMerkle);
            cache.push_descriptor(MULTIPATH_DESCRIPTOR).unwrap();
            cache.block_process(&block_paying(receive_script(95), 1_000), 1);
            assert_eq!(cache.n_cached_addresses(), 300);
            // The extension got its rescan before the restart
            assert_eq!(cache.take_addresses_pending_rescan().len(), 100);
        }

        let cache = AddressCache::new(KvDatabase::new(&datadir).unwrap(), ConsensusMerkle);
        assert_eq!(cache.n_cached_addresses(), 300);
        assert!(cache.take_addresses_pending_rescan().is_empty());

        // The receive chain window resumes at 200, not at 100
        cache.block_process(&block_paying(receive_script(150), 1_000), 2);
        assert_eq!(cache.n_cached_addresses(), 300);
        cache.block_process(&block_paying(receive_script(185), 1_000), 3);
        assert_eq!(cache.n_cached_addresses(), 400);
        assert_eq!(cache.take_addresses_pending_rescan().len(), 100);
    }

    #[test]
    fn addresses_pending_a_rescan_survive_a_restart() {
        use crate::kv_database::KvDatabase;

        let datadir = format!("./tmp-db/{}.watch-only-pending/", rand::random::<u32>());
        {
            let cache = AddressCache::new(KvDatabase::new(&datadir).unwrap(), ConsensusMerkle);
            cache.push_descriptor(MULTIPATH_DESCRIPTOR).unwrap();
            // Extends the receive chain, and the app is killed before anything rescans it
            cache.block_process(&block_paying(receive_script(95), 1_000), 1);
        }

        let cache = AddressCache::new(KvDatabase::new(&datadir).unwrap(), ConsensusMerkle);
        let pending = cache.take_addresses_pending_rescan();
        assert_eq!(pending.len(), DERIVATION_COUNT as usize);
        assert!(pending.contains(&receive_script(150)));
        assert!(cache.take_addresses_pending_rescan().is_empty());

        // Taken is taken, also across a restart
        drop(cache);
        let cache = AddressCache::new(KvDatabase::new(&datadir).unwrap(), ConsensusMerkle);
        assert!(cache.take_addresses_pending_rescan().is_empty());
    }

    #[test]
    fn history_near_the_end_of_a_window_extends_it_at_startup() {
        use crate::kv_database::KvDatabase;

        let datadir = format!("./tmp-db/{}.watch-only-upgrade/", rand::random::<u32>());
        {
            // A wallet written before the gap limit was enforced: the descriptor and the
            // first 100 addresses of each chain, with history at index 95 and nothing
            // derived past it.
            let cache = AddressCache::new(KvDatabase::new(&datadir).unwrap(), ConsensusMerkle);
            for descriptor in parse_and_split_descriptor(MULTIPATH_DESCRIPTOR).unwrap() {
                for script in
                    derive_addresses_from_parsed_descriptor(descriptor, 0, DERIVATION_COUNT)
                        .unwrap()
                {
                    cache.cache_address(script);
                }
            }
            cache.block_process(&block_paying(receive_script(95), 1_000), 1);
            assert_eq!(cache.n_cached_addresses(), 200);
            let inner = cache.inner.read().unwrap();
            crate::AddressCacheDatabase::save_descriptor(&inner.database, MULTIPATH_DESCRIPTOR)
                .unwrap();
        }

        let cache = AddressCache::new(KvDatabase::new(&datadir).unwrap(), ConsensusMerkle);
        assert!(cache.is_address_cached(&get_spk_hash(&receive_script(199))));
        let pending = cache.take_addresses_pending_rescan();
        assert_eq!(pending.len(), DERIVATION_COUNT as usize);
        assert!(pending.contains(&receive_script(100)));
    }

    #[test]
    fn test_reprocess_same_output_is_idempotent() {
        let block1 = deserialize_from_str(BLOCK_FIRST_UTXO);

        let spk = ScriptBuf::from_hex("00142b6a2924aa9b1b115d1ac3098b0ba0e6ed510f2a")
            .expect("Valid address");
        let script_hash = get_spk_hash(&spk);
        let cache = get_test_cache();

        cache.cache_address(spk);

        cache.block_process(&block1, 118511);
        let balance_once = cache.get_address_balance(&script_hash);

        // Reprocessing the same block (e.g. a rescan over an already-synced chain)
        // must not duplicate the UTXO or double-count the balance.
        cache.block_process(&block1, 118511);

        let address = cache.inner.read().unwrap();
        let address = address.address_map.get(&script_hash).unwrap();

        assert_eq!(address.utxos.len(), 1);
        assert_eq!(Some(address.balance), balance_once);
    }
}
