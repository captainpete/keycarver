use bitcoin::{consensus::deserialize, Block, TxOut, Network, Address};
use std::fs;
use std::fs::File;
use std::io::{BufReader, Read};
use std::collections::HashSet;
use indicatif::ProgressBar;
use std::sync::{Arc, Mutex};
use crossbeam::channel::bounded;
use crossbeam::scope;

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

    let pb = ProgressBar::new(paths.len() as u64);
    let file_queue = Arc::new(Mutex::new(paths));
    // let (tx, rx) = mpsc::channel::<HashSet<Address>>();
    let (tx, rx) = bounded::<HashSet<Address>>(10);

    // Spawn worker threads
    let num_workers = std::thread::available_parallelism()?;
    scope(|s| {
        for _ in 0..num_workers.into() {
            let file_queue = Arc::clone(&file_queue);
            let tx = tx.clone();
            s.spawn(move |_| {
                while let Some(path) = {
                    let mut queue = file_queue.lock().unwrap();
                    queue.pop()
                } {
                    match extract_addresses_from_block_file(path) {
                        Ok(addresses) => {
                            tx.send(addresses).unwrap();
                        }
                        Err(err) => {
                            eprintln!("Error processing file: {}", err);
                        }
                    }
                }
            });
        }

        drop(tx);

        let mut addresses = HashSet::new();
        for batch in rx {
            addresses.extend(batch);
            pb.inc(1);
        }

        Ok(addresses)
    }).unwrap()
}
