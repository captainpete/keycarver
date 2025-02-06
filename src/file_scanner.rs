use crate::address_index::AddressIndex;
use crate::crypto::{pkh_to_bitcoin_address, sk_to_pk_hash, PKH, SK, SK_LENGTH};
use crossbeam::channel;
use crossbeam::channel::TryRecvError;
use hex;
use indicatif::{ProgressBar, ProgressStyle};
use memmap2::Mmap;
use quick_cache::sync::Cache;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::process::exit;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

/// Statistics for tracking processing progress
#[derive(Default, Serialize, Deserialize)]
struct Stats {
    sk_candidate_count: AtomicUsize,
    sk_validated_count: AtomicUsize,
    sk_validated_unique_count: AtomicUsize,
    cache_hits: AtomicUsize,
    cache_misses: AtomicUsize,
    offset: AtomicUsize,
}

impl Stats {
    fn snapshot(&self) -> Stats {
        Stats {
            sk_candidate_count: self.sk_candidate_count.load(Ordering::Relaxed).into(),
            sk_validated_count: self.sk_validated_count.load(Ordering::Relaxed).into(),
            sk_validated_unique_count: self
                .sk_validated_unique_count
                .load(Ordering::Relaxed)
                .into(),
            cache_hits: self.cache_hits.load(Ordering::Relaxed).into(),
            cache_misses: self.cache_misses.load(Ordering::Relaxed).into(),
            offset: self.offset.load(Ordering::Relaxed).into(),
        }
    }
}

/// Structs for keeping progress and making things idempotent
#[derive(Serialize, Deserialize, Clone)]
struct RecoveredKey {
    sk: SK,
    pkh: PKH,
    addr: String,
    offset: usize,
}
#[derive(Default, Serialize, Deserialize)]
struct Checkpoint {
    stats: Stats,
    results: Vec<RecoveredKey>,
    file_size: usize,
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

/// Prints the recovered key to stdout
fn print_result(recovered_key: RecoveredKey) {
    println!(
        "priv: {}, pkh: {}, addr: {}, offset: {}",
        hex::encode(&recovered_key.sk),
        hex::encode(&recovered_key.pkh),
        &recovered_key.addr,
        recovered_key.offset,
    );
}

/// Scan a file for potential private keys and count matches against the index.
pub fn scan_raw(
    file_path: &Path,
    checkpoint_file: &Path,
    index_dir: &Path,
) -> Result<u64, Box<dyn Error>> {
    // Memory-map the file
    let file = File::open(file_path)?;
    let mmap = unsafe { Mmap::map(&file)? };
    let file_size = mmap.len();

    // Load/create checkpoint
    let checkpoint = Arc::new(Mutex::new({
        let mut checkpoint = Checkpoint::default();
        if checkpoint_file.exists() {
            let file = File::open(checkpoint_file)?;
            let mut state_reader = std::io::BufReader::new(file);
            let mut state_str = String::new();
            state_reader.read_to_string(&mut state_str)?;
            checkpoint = serde_json::from_str(&state_str)?;
            if checkpoint.file_size != file_size {
                eprintln!(
                    "error: File size in checkpoint file {} doesn't match file size of {}.",
                    checkpoint.file_size, file_size
                );
                exit(1);
            }
        } else {
            checkpoint.file_size = file_size;
        }
        checkpoint
    }));
    let stats = Arc::new(checkpoint.lock().unwrap().stats.snapshot());

    // Load index
    let index = Arc::new(AddressIndex::new(index_dir)?);

    // Start tracking time after index load
    let start_time = Instant::now();

    // Set up progress bar
    let pb = Arc::new(
        ProgressBar::new(file_size as u64).with_style(
            ProgressStyle::default_bar()
                .template("[{bar:40.cyan/blue}] {bytes}/{total_bytes} ({percent}%) - {msg}")
                .unwrap()
                .progress_chars("#>-"),
        ),
    );

    // Message types
    struct WorkMessage {
        sk: SK,
        offset: usize,
    }
    struct KeyMessage {
        sk: SK,
        pkh: PKH,
        offset: usize,
    }

    // Channels
    let (work_tx, work_rx) = channel::bounded::<WorkMessage>(1024);
    let (key_tx, key_rx) = channel::bounded::<KeyMessage>(1024);
    let (progress_tx, progress_rx) = channel::bounded::<()>(1);
    let (progress_trigger_tx, progress_trigger_rx) = channel::bounded::<()>(1);
    let (checkpoint_tx, checkpoint_rx) = channel::bounded::<()>(1);
    let (checkpoint_trigger_tx, checkpoint_trigger_rx) = channel::bounded::<()>(1);

    // Thread to update progress bar counts
    let progress_thread = {
        let stats = Arc::clone(&stats);
        let pb = Arc::clone(&pb);

        thread::spawn(move || {
            while progress_rx.recv().is_ok() {
                pb.set_position(stats.offset.load(Ordering::Relaxed) as u64);

                let key_count = stats.sk_candidate_count.load(Ordering::Relaxed);
                let elapsed = start_time.elapsed().as_secs_f64();
                let mkps = key_count as f64 / elapsed / 1e6;

                pb.set_message(format!(
                    "SK candidates: {} ({:.3} Mk/s), SKs validated: {} ({} unique), cache hits: {}, cache misses: {}",
                    key_count,
                    mkps,
                    stats.sk_validated_count.load(Ordering::Relaxed),
                    stats.sk_validated_unique_count.load(Ordering::Relaxed),
                    stats.cache_hits.load(Ordering::Relaxed),
                    stats.cache_misses.load(Ordering::Relaxed),
                ));
            }
        })
    };
    let progress_trigger_thread = {
        let progress_tx = progress_tx.clone();
        thread::spawn(move || loop {
            match progress_trigger_rx.try_recv() {
                Err(TryRecvError::Disconnected) => break,
                Ok(_) | Err(TryRecvError::Empty) => {
                    progress_tx.send(()).unwrap();
                    thread::sleep(Duration::from_millis(10));
                }
            }
        })
    };

    // Spawn worker threads
    let num_workers = rayon::current_num_threads();
    let workers: Vec<_> = (0..num_workers)
        .map(|_| {
            let work_rx = work_rx.clone();
            let key_tx = key_tx.clone();
            let index = Arc::clone(&index);
            let stats = Arc::clone(&stats);

            std::thread::spawn(move || {
                while let Ok(work_message) = work_rx.recv() {
                    if let Some((sk, pkh)) = check_bytes(work_message.sk, &index, &stats) {
                        let key_message = KeyMessage {
                            sk: sk,
                            pkh: pkh,
                            offset: work_message.offset,
                        };
                        key_tx.send(key_message).unwrap();
                    }
                }
            })
        })
        .collect();

    // Reader thread to push keys into the work channel
    let reader_thread = {
        let work_tx = work_tx.clone();
        let cache = Cache::<SK, ()>::new((1024 * 1024) as usize);
        let stats = Arc::clone(&stats);

        std::thread::spawn(move || {
            let mut buffer = [0u8; SK_LENGTH];

            let starting_offset = stats.offset.load(Ordering::Relaxed);
            for offset in starting_offset..file_size {
                let remaining = file_size - offset;
                if remaining < SK_LENGTH {
                    // Handle end-of-file: zero-fill the remaining buffer
                    buffer[..remaining].copy_from_slice(&mmap[offset..]);
                    buffer[remaining..].fill(0); // Fill the rest with zeros
                } else {
                    // Normal case: copy full slice
                    buffer.copy_from_slice(&mmap[offset..offset + SK_LENGTH]);
                }

                if cache
                    .get_or_insert_with(&buffer, || {
                        let work_message = WorkMessage {
                            sk: buffer,
                            offset: offset,
                        };
                        work_tx.send(work_message).unwrap();
                        stats.cache_misses.fetch_add(1, Ordering::Relaxed);
                        Ok::<(), ()>(())
                    })
                    .is_ok()
                {
                    stats.cache_hits.fetch_add(1, Ordering::Relaxed);
                }

                stats.offset.store(offset, Ordering::Relaxed);
            }
        })
    };

    // Results processing thread
    let key_processing_thread = {
        let stats = Arc::clone(&stats);
        let checkpoint = Arc::clone(&checkpoint);

        let mut recovered: HashSet<SK> = HashSet::new();
        for recovered_key in checkpoint.lock().unwrap().results.clone() {
            recovered.insert(recovered_key.sk);
        }

        std::thread::spawn(move || {
            while let Ok(key_message) = key_rx.recv() {
                let sk = key_message.sk;
                if !recovered.contains(&sk) {
                    stats
                        .sk_validated_unique_count
                        .fetch_add(1, Ordering::Relaxed);
                    let pkh = key_message.pkh;
                    let bitcoin_address = pkh_to_bitcoin_address(&pkh);

                    // add the recovered key to the state collection
                    let recovered_key = RecoveredKey {
                        sk: sk.clone(),
                        pkh: pkh.clone(),
                        addr: bitcoin_address.clone(),
                        offset: key_message.offset,
                    };
                    checkpoint.lock().unwrap().results.push(recovered_key);

                    // print the key to stdout
                    let recovered_key = RecoveredKey {
                        sk: sk.clone(),
                        pkh: pkh.clone(),
                        addr: bitcoin_address.clone(),
                        offset: key_message.offset,
                    };
                    print_result(recovered_key);

                    // add the SK to the duplicates lookup
                    recovered.insert(sk);
                }
            }
            recovered.len()
        })
    };

    // Checkpointing thread, saves a checkpoint every second
    let checkpoint_thread = {
        let stats = Arc::clone(&stats);
        let checkpoint = Arc::clone(&checkpoint);
        let checkpoint_file = checkpoint_file.to_path_buf();

        std::thread::spawn(move || {
            while checkpoint_rx.recv().is_ok() {
                // update the checkpoint stats with a snapshot of the live stats
                checkpoint.lock().unwrap().stats = stats.snapshot();
                // serialize to the checkpoint file
                let file = File::create(&checkpoint_file).unwrap();
                let mut checkpoint_writer = std::io::BufWriter::new(file);
                let checkpoint_json = serde_json::to_string(&*checkpoint.lock().unwrap()).unwrap();
                checkpoint_writer
                    .write_all(checkpoint_json.as_bytes())
                    .unwrap();
            }
        })
    };
    let checkpoint_trigger_thread = {
        let checkpoint_tx = checkpoint_tx.clone();
        thread::spawn(move || loop {
            match checkpoint_trigger_rx.try_recv() {
                Err(TryRecvError::Disconnected) => break,
                Ok(_) | Err(TryRecvError::Empty) => {
                    checkpoint_tx.send(()).unwrap();
                    thread::sleep(Duration::from_millis(1000));
                }
            }
        })
    };

    // Wait for the reader to finish
    reader_thread.join().expect("Reader thread panicked");

    // Drop the sender to signal workers when done
    drop(work_tx);
    drop(key_tx);

    // Flush progress updates, stop the progress thread
    progress_tx.send(()).unwrap();
    drop(progress_trigger_tx);
    progress_trigger_thread.join().unwrap();
    drop(progress_tx);
    progress_thread.join().unwrap();

    // Flush checkpoint updates, stop the checkpoint thread
    checkpoint_tx.send(()).unwrap();
    drop(checkpoint_trigger_tx);
    checkpoint_trigger_thread.join().unwrap();
    drop(checkpoint_tx);
    checkpoint_thread.join().unwrap();

    // Wait for all workers to finish
    for worker in workers {
        worker.join().expect("Worker thread panicked");
    }

    // Wait for the main thread to finish processing keys
    let final_count = key_processing_thread
        .join()
        .expect("Key processing thread panicked");

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
