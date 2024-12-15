use bitcoin::hashes::Hash;
use bitcoin::Address;
use boomphf::Mphf;
use crossbeam::channel;
use hex;
use indicatif::{ParallelProgressIterator, ProgressBar};
use memmap2::{Mmap, MmapMut};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use rocksdb::{Options, DB};
use std::convert::TryInto;
use std::error::Error;
use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::BufWriter;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::thread;

use crate::crypto::{PKH, PKH_LENGTH};

/// Constants for the full SHA256 hash space.
const SHA256_FULL_RANGE_START: [u8; 32] = [0x00; 32];
const SHA256_FULL_RANGE_END: [u8; 32] = [0xFF; 32];

/// Compute the starting key for a partition.
fn compute_sha256_partition_key(partition_index: usize, n_partitions: usize) -> Vec<u8> {
    let start = u128::from_be_bytes(SHA256_FULL_RANGE_START[0..16].try_into().unwrap());
    let end = u128::from_be_bytes(SHA256_FULL_RANGE_END[0..16].try_into().unwrap());
    let range = end - start;

    let step = range / n_partitions as u128;
    let offset = step * partition_index as u128;

    let mut key = [0x00; 32];
    key[0..16].copy_from_slice(&(start + offset).to_be_bytes());
    key.to_vec()
}

/// Partition the SHA256 key space into start and end ranges.
fn compute_sha256_partitions(n_partitions: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
    (0..n_partitions)
        .map(|i| {
            let start = compute_sha256_partition_key(i, n_partitions);
            let end = if i == n_partitions - 1 {
                SHA256_FULL_RANGE_END.to_vec()
            } else {
                compute_sha256_partition_key(i + 1, n_partitions)
            };
            (start, end)
        })
        .collect()
}

/// Create staging files for each partition of the SHA256 key space using RocksDB.
pub fn create_staging_files(db_path: &Path, staging_dir: &Path, n_partitions: usize, pb: &ProgressBar) -> Result<(), Box<dyn Error>> {
    let partition_ranges = compute_sha256_partitions(n_partitions);
    pb.set_length(partition_ranges.len() as u64);

    let mut opts = Options::default();
    opts.create_if_missing(true);
    let db = DB::open(&opts, db_path)?;

    partition_ranges.into_par_iter().progress_with(pb.clone()).for_each(|(start, end)| {
        let staging_file_path = staging_dir.join(format!("staging_{}_{}.db", hex::encode(&start), hex::encode(&end)));
        let staging_file = File::create(&staging_file_path).unwrap();
        let mut writer = BufWriter::new(staging_file);

        let iterator = db.iterator(rocksdb::IteratorMode::From(&start, rocksdb::Direction::Forward));
        for result in iterator {
            let (key, value) = result.unwrap();
            if key.as_ref() >= end.as_slice() {
                break;
            }
            writer.write_all(&value).unwrap();
        }
        writer.flush().unwrap();
    });

    Ok(())
}

/// Iterator over addresses in a staging file.
pub struct StagingAddressIterator {
    mmap: Arc<Mmap>,
    remaining: usize,
    current_offset: usize,
}

impl StagingAddressIterator {
    pub fn new(file: File) -> std::io::Result<Self> {
        let mmap = Arc::new(unsafe { Mmap::map(&file)? });
        let file_size = mmap.len();
        let remaining = file_size / PKH_LENGTH;

        Ok(Self {
            mmap,
            remaining,
            current_offset: 0,
        })
    }
}

impl Clone for StagingAddressIterator {
    fn clone(&self) -> Self {
        Self {
            mmap: self.mmap.clone(),
            remaining: self.remaining,
            current_offset: self.current_offset,
        }
    }
}

impl Iterator for StagingAddressIterator {
    type Item = PKH;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }

        let start = self.current_offset;
        let end = start + PKH_LENGTH;
        self.current_offset = end;

        let mut buffer = PKH::default();
        buffer.copy_from_slice(&self.mmap[start..end]);
        self.remaining -= 1;
        Some(buffer)
    }

    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        if n >= self.remaining {
            self.remaining = 0;
            return None;
        }

        self.current_offset += n * PKH_LENGTH;
        self.remaining -= n;
        self.next()
    }
}

impl ExactSizeIterator for StagingAddressIterator {
    fn len(&self) -> usize {
        self.remaining
    }
}

/// Iterator over files containing addresses.
struct AddressFilesIterator {
    files: Vec<PathBuf>,
}

impl AddressFilesIterator {
    fn new(files: Vec<PathBuf>) -> Self {
        Self { files }
    }
}

impl<'a> IntoIterator for &'a AddressFilesIterator {
    type Item = StagingAddressIterator;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.files
            .iter()
            .map(|file_path| {
                let file = File::open(file_path).unwrap();
                StagingAddressIterator::new(file).expect("Could not create iterator")
            })
            .collect::<Vec<_>>()
            .into_iter()
    }
}

fn staging_dir_files(staging_dir: &Path) -> Vec<PathBuf> {
    fs::read_dir(staging_dir)
        .unwrap()
        .filter_map(|entry| {
            entry.ok().and_then(|e| {
                let path = e.path();
                if path.is_file() {
                    Some(path)
                } else {
                    None
                }
            })
        })
        .collect()
}

fn address_count_from_files(files: &Vec<PathBuf>) -> u64 {
    let total_bytes: u64 = files
        .iter()
        .filter_map(|file| fs::metadata(file).ok().map(|m| m.len()))
        .sum();

    assert_eq!(total_bytes % (PKH_LENGTH as u64), 0);
    total_bytes / (PKH_LENGTH as u64)
}

/// Creates a MPHF from staging files.
pub fn create_mphf(staging_dir: &Path, gamma: f64) -> Result<Mphf<PKH>, Box<dyn Error>> {
    let files = staging_dir_files(&staging_dir);
    let n = address_count_from_files(&files);
    let chunk_iterator = AddressFilesIterator::new(files);
    let num_threads = thread::available_parallelism()?;
    let mphf = Mphf::from_chunked_iterator_parallel(gamma, &chunk_iterator, None, n, usize::from(num_threads));
    Ok(mphf)
}

/// Serializes the MPHF to a file.
pub fn save_mphf(index_dir: &Path, mphf: &Mphf<PKH>) -> Result<(), Box<dyn Error>> {
    let mut file = File::create(index_dir.join("mphf.bin"))?;
    bincode::serialize_into(&mut file, mphf)?;
    Ok(())
}

fn load_mphf(index_dir: &Path) -> Result<Mphf<PKH>, Box<dyn Error>> {
    let file = File::open(index_dir.join("mphf.bin"))?;
    let mphf = bincode::deserialize_from(file)?;
    Ok(mphf)
}

/// Uses a MPHF to build an index file where each address is stored at the hashed offset.
pub fn create_index(
    mphf: &Mphf<PKH>,
    staging_dir: &Path,
    index_dir: &Path,
    pb: &ProgressBar,
) -> Result<(), Box<dyn Error>> {
    // Determine the size of the output index file
    let files = staging_dir_files(&staging_dir);
    let n = address_count_from_files(&files);
    let index_file_path = index_dir.join("index.bin");
    let file_size = n as u64 * PKH_LENGTH as u64;

    // Create and memory-map the output file
    let index_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&index_file_path)?;
    index_file.set_len(file_size)?;
    let mut mmap = unsafe { MmapMut::map_mut(&index_file)? };

    // Create a channel for worker threads to send (offset, address) tuples
    let (tx, rx) = channel::bounded::<(usize, PKH)>(1024);

    // Spawn worker threads to process staging files
    let worker_handles: Vec<_> = files
        .into_iter()
        .map(|file_path| {
            let tx = tx.clone();
            let mphf = mphf.clone(); // Clone Arc-wrapped MPHF for thread-safe sharing
            thread::spawn(move || {
                let file = File::open(file_path).unwrap();
                let mut address_iterator = StagingAddressIterator::new(file).unwrap();

                // Iterate over addresses in the file
                while let Some(address) = address_iterator.next() {
                    if let Some(index) = mphf.try_hash(&address) {
                        tx.send((index as usize, address)).unwrap();
                    }
                }
            })
        })
        .collect();

    // Drop the sender to signal the main thread when workers are done
    drop(tx);

    // Process received (offset, address) tuples and write them to the mmap
    pb.set_length(n);
    for (offset, address) in rx {
        mmap[offset * PKH_LENGTH..(offset + 1) * PKH_LENGTH]
            .copy_from_slice(&address);
        pb.inc(1);
    }

    // Ensure all writes are flushed
    mmap.flush()?;

    // Wait for all worker threads to finish
    for handle in worker_handles {
        handle.join().expect("Worker thread panicked");
    }

    Ok(())
}

/// Address Index with O(1) lookups.
pub struct AddressIndex {
    mphf: Mphf<PKH>,
    mmap: Mmap,
}

impl AddressIndex {
    /// Creates a new `AddressIndex` from a given `index_dir`.
    pub fn new(index_dir: &Path) -> Result<Self, Box<dyn Error>> {
        let mphf = load_mphf(index_dir)?;
        let index_file_path = index_dir.join("index.bin");
        let index_file = OpenOptions::new()
            .read(true)
            .write(false)
            .create(false)
            .open(&index_file_path)?;
        let mmap = unsafe { Mmap::map(&index_file)? };

        Ok(Self { mphf, mmap })
    }

    /// Check if the index contains a given "hex formatted" bitcoin p2pkh address
    pub fn contains_address_str(&self, formatted_address: &str) -> bool {
        let addr = Address::from_str(formatted_address).unwrap().assume_checked();
        assert!(addr.address_type() == Some(bitcoin::AddressType::P2pkh));
        let address: PKH = addr.pubkey_hash().unwrap().to_byte_array();
        self.contains_address_hash(&address)
    }

    /// Check if the index contains a given p2pkh address (bytes)
    pub fn contains_address_hash(&self, address: &PKH) -> bool {
        match self.mphf.try_hash(address) {
            Some(hash) => {
                let mut found_address = PKH::default();
                let (start, end) = (hash as usize * PKH_LENGTH, (hash as usize + 1) * PKH_LENGTH);
                found_address.copy_from_slice(&self.mmap[start..end]);
                found_address == *address
            }
            None => false,
        }
    }
}
