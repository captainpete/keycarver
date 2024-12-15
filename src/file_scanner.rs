use crate::address_index::AddressIndex;
use crate::crypto::{pkh_to_bitcoin_address, sk_to_pk_hash, PKH, SK, SK_LENGTH};
use crossbeam::channel;
use hex;
use indicatif::{ProgressBar, ProgressStyle};
use memmap2::Mmap;
use quick_cache::sync::Cache;
use std::collections::HashSet;
use std::error::Error;
use std::fs::File;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Statistics for tracking processing progress
#[derive(Default)]
struct Stats {
    sk_candidate_count: AtomicUsize,
    sk_validated_count: AtomicUsize,
    sk_validated_unique_count: AtomicUsize,
    cache_hits: AtomicUsize,
    cache_misses: AtomicUsize,
}


/// Check if the byte slice represents a private key corresponding to an address in the index.
fn check_bytes(sk: SK, index: &AddressIndex, stats: &Stats) -> Option<(SK, PKH)> {
    if let Some(pkh) = sk_to_pk_hash(&sk) {
        stats.sk_candidate_count.fetch_add(1, Ordering::Relaxed);
        if index.contains_address_hash(&pkh) {
            stats.sk_validated_count.fetch_add(1, Ordering::Relaxed);
            return Some((sk, pkh));
        }
    }
    None
}

/// Scan a file for potential private keys and count matches against the index.
pub fn scan(file_path: &Path, index_dir: &Path) -> Result<u64, Box<dyn Error>> {
    // Load index
    let index = Arc::new(AddressIndex::new(index_dir)?);

    // Start tracking time after index load
    let start_time = Instant::now();

    // Memory-map the file
    let file = File::open(file_path)?;
    let mmap = unsafe { Mmap::map(&file)? };
    let file_size = mmap.len();

    let stats = Arc::new(Stats::default());

    let pb = Arc::new(ProgressBar::new(file_size as u64).with_style(
        ProgressStyle::default_bar()
            .template("[{bar:40.cyan/blue}] {bytes}/{total_bytes} ({percent}%) - {msg}")
            .unwrap()
            .progress_chars("#>-"),
    ));

    // Thread to update progress bar counts
    let stats_clone = Arc::clone(&stats);
    let pb_clone = Arc::clone(&pb);
    thread::spawn(move || loop {
        let key_count = stats_clone.sk_candidate_count.load(Ordering::Relaxed);
        let elapsed = start_time.elapsed().as_secs_f64();
        let mkps = key_count as f64 / elapsed / 1e6;

        pb_clone.set_message(format!(
            "SK candidates: {} ({:.3} Mk/s), SKs validated: {} ({} unique), cache hits: {}, cache misses: {}",
            key_count,
            mkps,
            stats_clone.sk_validated_count.load(Ordering::Relaxed),
            stats_clone.sk_validated_unique_count.load(Ordering::Relaxed),
            stats_clone.cache_hits.load(Ordering::Relaxed),
            stats_clone.cache_misses.load(Ordering::Relaxed),
        ));
        thread::sleep(Duration::from_millis(10));
    });

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
            let stats = Arc::clone(&stats);

            std::thread::spawn(move || {
                while let Ok(sk) = work_rx.recv() {
                    if let Some((sk, pkh)) = check_bytes(sk, &index, &stats) {
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
        let cache = Cache::<SK, ()>::new((1024 * 1024) as usize);
        let stats = Arc::clone(&stats);

        std::thread::spawn(move || {
            let mut buffer = [0u8; SK_LENGTH];

            for offset in 0..file_size {
                let remaining = file_size - offset;

                if remaining < SK_LENGTH {
                    // Handle end-of-file: zero-fill the remaining buffer
                    buffer[..remaining].copy_from_slice(&mmap[offset..]);
                    buffer[remaining..].fill(0); // Fill the rest with zeros
                } else {
                    // Normal case: copy full slice
                    buffer.copy_from_slice(&mmap[offset..offset + SK_LENGTH]);
                }

                if cache.get_or_insert_with(&buffer, || {
                    work_tx.send(buffer).unwrap();
                    stats.cache_misses.fetch_add(1, Ordering::Relaxed);
                    Ok::<(), ()>(())
                }).is_ok() {
                    stats.cache_hits.fetch_add(1, Ordering::Relaxed);
                }

                pb.inc(1);
            }

            drop(work_tx);
        })
    };

    // Main thread processes keys from the key channel
    let mut recovered: HashSet<SK> = HashSet::new();
    let stats_clone = Arc::clone(&stats);
    let key_processing_thread = std::thread::spawn(move || {
        while let Ok((sk, pkh)) = key_rx.recv() {
            if !recovered.contains(&sk) {
                stats_clone.sk_validated_unique_count.fetch_add(1, Ordering::Relaxed);
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

    // Final statistics
    pb.finish_with_message(format!(
        "Scan complete. SK Candidates: {}, SKs Validated: {} ({} unique), Cache Hits: {}, Cache Misses: {}",
        stats.sk_candidate_count.load(Ordering::Relaxed),
        stats.sk_validated_count.load(Ordering::Relaxed),
        stats.sk_validated_unique_count.load(Ordering::Relaxed),
        stats.cache_hits.load(Ordering::Relaxed),
        stats.cache_misses.load(Ordering::Relaxed),
    ));

    Ok(final_count as u64)
}
