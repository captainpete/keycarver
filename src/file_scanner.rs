use std::error::Error;
use std::fs::File;
use std::path::Path;
use std::sync::Arc;

use crossbeam::channel;
use indicatif::{ProgressBar, ProgressStyle};
use memmap2::Mmap;
use std::collections::HashSet;
use hex;
use quick_cache::sync::Cache;

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
    let mmap = unsafe { Mmap::map(&file)? };
    let file_size = mmap.len();

    let pb = Arc::new(ProgressBar::new(file_size as u64).with_style(
        ProgressStyle::default_bar()
            .template("{msg} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({percent}%)")
            .unwrap()
            .progress_chars("#>-"),
    ));
    pb.set_message("Scanning");

    // Channels for work distribution and matched keys
    let (work_tx, work_rx) = channel::bounded::<SK>(1024);
    let (key_tx, key_rx) = channel::bounded::<(SK, PKH)>(1024);

    // Spawn worker threads
    let num_workers = rayon::current_num_threads();
    let workers: Vec<_> = (0..num_workers)
        .map(|_| {
            let work_rx = work_rx.clone();
            let key_tx = key_tx.clone();
            let index = Arc::clone(&index);

            std::thread::spawn(move || {
                while let Ok(sk) = work_rx.recv() {
                    if let Some(pkh) = check_bytes(&sk, &index) {
                        key_tx.send((sk, pkh)).unwrap();
                    }
                }
            })
        })
        .collect();

    // Reader thread to push keys into the work channel
    let reader_thread = {
        let work_tx = work_tx.clone();
        let pb = Arc::clone(&pb);
        let cache = Cache::<SK, ()>::new(1024usize);

        std::thread::spawn(move || {
            let mut buffer = [0u8; 32];
            for offset in 0..file_size.saturating_sub(31) {
                buffer.copy_from_slice(&mmap[offset..offset + 32]);
                let _ = cache.get_or_insert_with(&buffer, || {
                    work_tx.send(buffer).unwrap();
                    Ok::<(), ()>(())
                });
                pb.inc(1);
            }
            drop(work_tx);
            println!("Scan complete. cache hits = {}, cache_misses = {}", cache.hits(), cache.misses());
        })
    };

    // Main thread processes keys from the key channel
    let mut recovered: HashSet<SK> = HashSet::new();
    let key_processing_thread = std::thread::spawn(move || {
        while let Ok((sk, pkh)) = key_rx.recv() {
            if !recovered.contains(&sk) {
                let bitcoin_address = pkh_to_bitcoin_address(&pkh);
                println!("priv: {}, pkh: {}, addr: {}", hex::encode(&sk), hex::encode(&pkh), bitcoin_address);
                recovered.insert(sk);
            }
        }
        recovered.len()
    });

    // Wait for the reader to finish
    reader_thread.join().expect("Reader thread panicked");

    // Drop the sender to signal workers when done
    drop(work_tx);
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
