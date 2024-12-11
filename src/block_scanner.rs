use bitcoin::{consensus::deserialize, Block, TxOut, Network, Address};
use std::fs;
use std::fs::File;
use std::io::{BufReader, Read};
use std::collections::HashSet;
use indicatif::ProgressBar;
use std::time::Instant;
use indicatif::ParallelProgressIterator;
use rayon::iter::{ParallelIterator, IntoParallelRefIterator};

/// Extract Bitcoin addresses from transaction outputs (TxOut).
fn extract_addresses_from_txout(txout: &TxOut, network: Network) -> Option<Address> {
    Address::from_script(&txout.script_pubkey, network).ok()
}

/// Extract all addresses from transactions in a block.
fn extract_addresses_from_block(block: &Block, network: Network) -> HashSet<Address> {
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
fn extract_addresses_from_block_file(path: String) -> Result<HashSet<Address>, Box<dyn std::error::Error>> {
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

/// Process all `blk*.dat` files in a folder and return unique addresses.
pub fn extract_addresses_from_folder(
    folder_path: &str,
) -> Result<HashSet<Address>, Box<dyn std::error::Error>> {
    let pb = ProgressBar::new_spinner();
    let start = Instant::now();

    // Get all files in the folder
    let paths = fs::read_dir(folder_path)?
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

    // Process files in parallel
    pb.set_message("Scanning block files");
    let global_addresses: HashSet<Address> = paths
        .par_iter()
        .progress_count(paths.len() as u64)
        .map(|path| {
            // Process each file and extract addresses
            extract_addresses_from_block_file(path.clone()).unwrap_or_else(|_| HashSet::new())
        })
        .reduce(HashSet::new, |mut acc, addresses| {
            acc.extend(addresses);
            acc
        });
    let duration = start.elapsed();
    pb.finish_with_message(format!("Scanned {} files in {:.2?}", paths.len(), duration));

    Ok(global_addresses)
}
