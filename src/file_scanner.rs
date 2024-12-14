use std::error::Error;
use std::fs::File;
use std::path::Path;
use std::sync::Arc;

use crossbeam::channel;
use indicatif::{ProgressBar, ProgressStyle};
use memmap2::Mmap;
use std::collections::HashSet;
use hex;

use crate::address_index::AddressIndex;
use crate::crypto::{SK, PKH, sk_to_pk_hash, pkh_to_bitcoin_address};

/// Check if the 32-byte slice represents a private key corresponding to an address in the index.
fn check_bytes(bytes: &SK, index: &AddressIndex) -> Option<[u8; 20]> {
    if let Some(pkh) = sk_to_pk_hash(bytes) {
        if index.contains_address_hash(&pkh) {
            Some(pkh)
        } else {
            None
        }
    } else {
        None
    }
}

/// Scan a file for potential private keys and count matches against the index.
pub fn scan(file_path: &Path, index_dir: &Path) -> Result<u64, Box<dyn Error>> {
    let index = Arc::new(AddressIndex::new(index_dir)?);

    // Memory-map the file
    let file = File::open(file_path)?;
    let mmap = Arc::new(unsafe { Mmap::map(&file)? });
    let file_size = mmap.len();

    let pb = Arc::new(ProgressBar::new(file_size as u64).with_style(
        ProgressStyle::default_bar()
            .template("{msg} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({percent}%)")
            .unwrap()
            .progress_chars("#>-"),
    ));
    pb.set_message("Scanning");

    // Channels for matched keys
    let (key_tx, key_rx) = channel::bounded::<(SK, PKH)>(1024);

    // Spawn worker threads
    let num_workers = rayon::current_num_threads();
    let workers: Vec<_> = (0..num_workers)
        .map(|worker_id| {
            let key_tx = key_tx.clone();
            let index = Arc::clone(&index);
            let mmap = Arc::clone(&mmap);
            let pb = Arc::clone(&pb);

            std::thread::spawn(move || {
                let mut buffer = [0u8; 32];

                // Each worker starts at its own offset and steps by the number of workers
                for offset in (worker_id..file_size.saturating_sub(31)).step_by(num_workers) {
                    buffer.copy_from_slice(&mmap[offset..offset + 32]);

                    if let Some(pkh) = check_bytes(&buffer, &index) {
                        key_tx.send((buffer, pkh)).unwrap();
                    }

                    pb.inc(1);
                }
            })
        })
        .collect();

    // Main thread processes keys from the key channel
    let mut recovered: HashSet<SK> = HashSet::new();
    let key_processing_thread = std::thread::spawn(move || {
        while let Ok((sk, pkh)) = key_rx.recv() {
            if !recovered.contains(&sk) {
                let bitcoin_address = pkh_to_bitcoin_address(&pkh);
                println!(
                    "priv: {}, pkh: {}, addr: {}",
                    hex::encode(&sk),
                    hex::encode(&pkh),
                    bitcoin_address
                );
                recovered.insert(sk);
            }
        }
        recovered.len()
    });

    // Drop the sender to signal workers when done
    drop(key_tx);

    // Wait for all workers to finish
    for worker in workers {
        worker.join().expect("Worker thread panicked");
    }

    // Wait for the main thread to finish processing keys
    let final_count = key_processing_thread.join().expect("Key processing thread panicked");

    pb.finish_with_message("Scan complete");
    Ok(final_count as u64)
}
