use bitcoin::hashes::Hash;
use bitcoin::{consensus::deserialize, Address, Block, Network, TxOut};
use indicatif::{ParallelProgressIterator, ProgressBar};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use rocksdb::{Options, WriteBatch, DB};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::{read_dir, File};
use std::io::{BufReader, Read};
use std::path::Path;

use crate::crypto::PKH;

/// Extract Bitcoin addresses from transaction outputs (TxOut).
fn extract_addresses_from_txout(txout: &TxOut, network: Network) -> Option<PKH> {
    match Address::from_script(&txout.script_pubkey, network).ok() {
        Some(address) => {
            match address.address_type() {
                Some(bitcoin::AddressType::P2pkh) => {
                    let address_hash = address.pubkey_hash()?.to_byte_array();
                    // println!("Address: {:#}", address);
                    Some(address_hash)
                }
                Some(bitcoin::AddressType::P2wpkh) => {
                    if let Some(witness_program) = address.witness_program() {
                        let program = witness_program.program();
                        if program.len() == 20 {
                            let mut pkh = [0u8; 20];
                            pkh.copy_from_slice(&program.as_bytes());
                            Some(pkh)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                }
                _ => None,
            }
        }
        None => None,
    }
}

/// Extract all addresses from transactions in a block.
fn extract_addresses_from_block(block: &Block, network: Network) -> HashSet<PKH> {
    let mut addresses = HashSet::new();

    for tx in &block.txdata {
        for output in &tx.output {
            if let Some(address) = extract_addresses_from_txout(output, network) {
                addresses.insert(address);
            }
        }
    }

    addresses
}

/// Parse a blk*.dat file and extract all unique addresses.
fn extract_addresses_from_block_file(path: String) -> Result<HashSet<PKH>, Box<dyn std::error::Error>> {
    let network = Network::Bitcoin;
    let mut addresses = HashSet::new();

    let file = File::open(path)?;
    let mut reader = BufReader::new(file);

    const MAINNET_MAGIC: [u8; 4] = [0xF9, 0xBE, 0xB4, 0xD9];
    loop {
        // Read the 4-byte magic number
        let mut magic = [0u8; 4];
        if reader.read_exact(&mut magic).is_err() {
            break; // End of file
        }
        if magic == [0, 0, 0, 0] {
            break; // Padding or EOF marker
        }

        // Verify magic number
        if magic != MAINNET_MAGIC {
            return Err(format!("Invalid magic number: {:x?}", magic).into());
        }

        // Read the 4-byte block size
        let mut block_size_bytes = [0u8; 4];
        reader.read_exact(&mut block_size_bytes)?;
        let block_size = u32::from_le_bytes(block_size_bytes);

        // Read the block data
        let mut block_data = vec![0u8; block_size as usize];
        reader.read_exact(&mut block_data)?;

        // Deserialize the block
        let block: Block = deserialize(&block_data)?;

        // Extract addresses from the block and add to the set
        addresses.extend(extract_addresses_from_block(&block, network));
    }

    Ok(addresses)
}

/// Process all `blk*.dat` files in a folder
pub fn load_unique_addresses_into_database(
    block_dir: &str,
    db_path: &Path,
    pb: &ProgressBar,
) -> Result<(), Box<dyn std::error::Error>> {
    // Open RocksDB with default options
    let mut opts = Options::default();
    opts.create_if_missing(true);
    let db = DB::open(&opts, db_path)?;

    // Get all files in the folder
    let paths = read_dir(block_dir)?
        .filter_map(|entry| entry.ok()) // Ignore errors
        .filter(|entry| {
            // Only include files with names starting with "blk" and ending in ".dat"
            if let Some(file_name) = entry.file_name().to_str() {
                file_name.starts_with("blk") && file_name.ends_with(".dat")
            } else {
                false
            }
        })
        .map(|entry| entry.path().to_string_lossy().to_string()) // Convert paths to strings
        .collect::<Vec<String>>();

    pb.set_length(paths.len() as u64);

    // Process files in parallel
    paths.par_iter().progress_with(pb.clone()).for_each(|path| {
        match extract_addresses_from_block_file(path.to_string()) {
            Ok(addresses) => {
                let mut batch = WriteBatch::default();
                for address in addresses {
                    let hash = Sha256::digest(&address);
                    batch.put(hash.as_slice(), &address);
                }
                db.write(batch).unwrap();
            }
            Err(err) => {
                eprintln!("Error processing file: {}", err);
            }
        }
    });

    Ok(())
}
