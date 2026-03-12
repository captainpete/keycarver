use std::collections::HashSet;
use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::process::exit;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use indicatif::{ProgressBar, ProgressStyle};
use memmap2::{Advice, Mmap, UncheckedAdvice};
use std::ffi::c_void;

use crate::address_index::AddressIndex;
use crate::crypto::{pkh_to_bitcoin_address, pkh_to_p2wpkh_address, SK};
use crate::scanner_common::{Checkpoint, RecoveredKey};

/// Rust-side field element matching CUDA `fe { uint32_t d[8]; }` (little-endian u32 limbs)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FieldElement(pub [u32; 8]);

/// Rust-side Jacobian point matching CUDA `JacobianPoint { fe x, y, z; }`
#[repr(C)]
#[derive(Clone, Copy)]
pub struct JacobianPoint {
    pub x: FieldElement,
    pub y: FieldElement,
    pub z: FieldElement,
}

/// Convert 32 big-endian bytes to a FieldElement (8 little-endian u32 limbs)
fn fe_from_be_bytes(bytes: &[u8]) -> FieldElement {
    let mut limbs = [0u32; 8];
    for i in 0..8 {
        let b = &bytes[i * 4..(i + 1) * 4];
        // bytes[0..4] = most significant word => limbs[7]
        limbs[7 - i] = u32::from_be_bytes(b.try_into().unwrap());
    }
    FieldElement(limbs)
}

fn fe_one() -> FieldElement {
    let mut limbs = [0u32; 8];
    limbs[0] = 1;
    FieldElement(limbs)
}

/// Generate precomputed table: g_powers[i] = 2^i * G, i in 0..256
pub fn generate_g_powers() -> Vec<JacobianPoint> {
    use secp256k1::{PublicKey, SecretKey, SECP256K1};

    let mut powers = Vec::with_capacity(256);
    for i in 0..256usize {
        let mut sk_bytes = [0u8; 32];
        // scalar = 2^i: bit i from LSB (byte[31] = bits 0-7)
        sk_bytes[31 - (i / 8)] = 1u8 << (i % 8);
        let sk = SecretKey::from_slice(&sk_bytes).unwrap();
        let pk = PublicKey::from_secret_key(&*SECP256K1, &sk);
        let serialized = pk.serialize_uncompressed(); // 65 bytes: 04 | x(32) | y(32)

        let x = fe_from_be_bytes(&serialized[1..33]);
        let y = fe_from_be_bytes(&serialized[33..65]);
        let z = fe_one();
        powers.push(JacobianPoint { x, y, z });
    }
    powers
}

fn print_result(rk: &RecoveredKey) {
    let p2wpkh = pkh_to_p2wpkh_address(&rk.pkh);
    println!(
        "priv: {}, pkh: {}, p2pkh: {}, p2wpkh: {}, offset: {}",
        hex::encode(&rk.sk),
        hex::encode(&rk.pkh),
        &rk.addr,
        p2wpkh,
        rk.offset,
    );
}

#[cfg(feature = "cuda")]
mod gpu {
    use super::*;
    use cudarc::driver::*;
    use cudarc::nvrtc::Ptx;
    use rayon::prelude::*;

    // Make JacobianPoint usable as a CUDA device type
    unsafe impl DeviceRepr for FieldElement {}
    unsafe impl DeviceRepr for JacobianPoint {}

    /// Regular pinned (page-locked) host memory with flags=0.
    ///
    /// `ctx.alloc_pinned()` uses `CU_MEMHOSTALLOC_WRITECOMBINED` which makes CPU reads
    /// uncached and ~10× slower — terrible for the MPHF lookup after D→H. This wrapper
    /// uses flags=0 (regular pinned), giving fast cached CPU reads AND async DMA from GPU.
    struct PinnedReadBuf {
        ptr: *mut u8,
        len: usize,
    }
    unsafe impl Send for PinnedReadBuf {}

    impl PinnedReadBuf {
        fn new(len: usize) -> Result<Self, Box<dyn Error>> {
            let ptr = unsafe { cudarc::driver::result::malloc_host(len, 0) }? as *mut u8;
            Ok(PinnedReadBuf { ptr, len })
        }
        fn as_mut_slice(&mut self) -> &mut [u8] {
            unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
        }
        fn as_slice(&self) -> &[u8] {
            unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
        }
    }

    impl Drop for PinnedReadBuf {
        fn drop(&mut self) {
            unsafe { cudarc::driver::result::free_host(self.ptr as *mut c_void).ok() };
        }
    }

    pub struct GpuContext {
        #[allow(dead_code)]
        ctx: Arc<CudaContext>,
        stream: Arc<CudaStream>,
        func: CudaFunction,
        g_powers_dev: CudaSlice<JacobianPoint>,
    }

    impl GpuContext {
        pub fn new() -> Result<Self, Box<dyn Error>> {
            let ptx_path = env!("SECP256K1_PTX_PATH");
            let ctx = CudaContext::new(0)?;
            let stream = ctx.default_stream();

            // Load PTX from the file path (baked in at compile time)
            let ptx = Ptx::from_file(ptx_path);
            let module = ctx.load_module(ptx)?;
            let func = module.load_function("sk_to_pkh_kernel")?;

            // Generate and upload G powers table
            let g_powers_host = generate_g_powers();
            let g_powers_dev = stream.clone_htod(&g_powers_host)?;
            stream.synchronize()?;

            Ok(GpuContext {
                ctx,
                stream,
                func,
                g_powers_dev,
            })
        }

        pub fn process_chunk(&self, chunk: &[u8]) -> Result<Vec<[u8; 20]>, Box<dyn Error>> {
            let chunk_len = chunk.len();
            if chunk_len == 0 {
                return Ok(vec![]);
            }

            // Upload chunk bytes to device
            let chunk_dev = self.stream.clone_htod(chunk)?;

            // Allocate output buffer (chunk_len * 20 bytes)
            let mut out_dev = self.stream.alloc_zeros::<u8>(chunk_len * 20)?;

            let block_size = 256u32;
            let n = chunk_len as u32;
            let grid_size = (n + block_size - 1) / block_size;

            let cfg = LaunchConfig {
                grid_dim: (grid_size, 1, 1),
                block_dim: (block_size, 1, 1),
                shared_mem_bytes: 0,
            };

            unsafe {
                self.stream
                    .launch_builder(&self.func)
                    .arg(&chunk_dev)
                    .arg(&n)
                    .arg(&mut out_dev)
                    .arg(&self.g_powers_dev)
                    .launch(cfg)?
            };

            self.stream.synchronize()?;

            let out_host = self.stream.clone_dtoh(&out_dev)?;

            let mut pkhs = Vec::with_capacity(chunk_len);
            for i in 0..chunk_len {
                let mut pkh = [0u8; 20];
                pkh.copy_from_slice(&out_host[i * 20..(i + 1) * 20]);
                pkhs.push(pkh);
            }
            Ok(pkhs)
        }
    }

    /// Pre-allocated buffers for one pipeline slot (device + host).
    struct Slot {
        stream: Arc<CudaStream>,
        d_chunk: CudaSlice<u8>,    // capacity: chunk_size + 31
        d_pkhs: CudaSlice<u8>,     // capacity: (chunk_size + 31) * 20
        h_pkhs: PinnedReadBuf,     // regular pinned host: (chunk_size + 31) * 20
        capacity: usize,           // chunk_size + 31
    }

    impl Slot {
        fn new(ctx: &Arc<CudaContext>, capacity: usize) -> Result<Self, Box<dyn Error>> {
            let stream = ctx.new_stream()?;
            let d_chunk = stream.alloc_zeros::<u8>(capacity)?;
            let d_pkhs = stream.alloc_zeros::<u8>(capacity * 20)?;
            stream.synchronize()?;
            // Regular pinned memory (flags=0): CPU reads are L1/L2 cached (fast MPHF),
            // and DMA is page-locked so D→H is truly async (double-buffer overlap works).
            // ctx.alloc_pinned() uses CU_MEMHOSTALLOC_WRITECOMBINED — CPU reads uncached.
            let h_pkhs = PinnedReadBuf::new(capacity * 20)?;
            Ok(Slot {
                stream,
                d_chunk,
                d_pkhs,
                h_pkhs,
                capacity,
            })
        }

        /// Enqueue H→D copy, kernel launch, and D→H copy on this slot's stream.
        /// Returns immediately (all ops async); call `sync()` to wait for completion.
        fn submit(
            &mut self,
            chunk: &[u8],
            func: &CudaFunction,
            g_powers_dev: &CudaSlice<JacobianPoint>,
        ) -> Result<(), Box<dyn Error>> {
            let n = chunk.len();
            debug_assert!(n <= self.capacity, "chunk too large for slot capacity");

            let n_u32 = n as u32;
            let block_size = 256u32;
            let grid_size = (n_u32 + block_size - 1) / block_size;
            let cfg = LaunchConfig {
                grid_dim: (grid_size, 1, 1),
                block_dim: (block_size, 1, 1),
                shared_mem_bytes: 0,
            };

            // H→D: copy chunk bytes into pre-allocated device buffer
            {
                let mut dst = self.d_chunk.slice_mut(0..n);
                self.stream.memcpy_htod(chunk, &mut dst)?;
            }

            // Kernel: compute PKHs for every byte offset in chunk
            {
                let src = self.d_chunk.slice(0..n);
                let mut dst = self.d_pkhs.slice_mut(0..n * 20);
                unsafe {
                    self.stream
                        .launch_builder(func)
                        .arg(&src)
                        .arg(&n_u32)
                        .arg(&mut dst)
                        .arg(g_powers_dev)
                        .launch(cfg)?
                };
            }

            // D→H: async copy all PKH results to pinned host buffer.
            // Copies full capacity*20 bytes; positions n..capacity are zeroed (alloc_zeros),
            // harmless since MPHF only reads h_pkhs[0..n*20]. Lengths match (both capacity*20).
            self.stream.memcpy_dtoh(&self.d_pkhs, self.h_pkhs.as_mut_slice())?;

            Ok(())
        }

        fn sync(&self) -> Result<(), Box<dyn Error>> {
            self.stream.synchronize()?;
            Ok(())
        }
    }

    fn save_checkpoint(
        checkpoint: &Arc<Mutex<Checkpoint>>,
        stats: &crate::scanner_common::Stats,
        checkpoint_file: &Path,
    ) -> Result<(), Box<dyn Error>> {
        checkpoint.lock().unwrap().stats = stats.snapshot();
        let cp_file = File::create(checkpoint_file)?;
        let mut w = std::io::BufWriter::new(cp_file);
        let json = serde_json::to_string(&*checkpoint.lock().unwrap())?;
        w.write_all(json.as_bytes())?;
        Ok(())
    }

    pub fn scan_raw_gpu_inner(
        file_path: &Path,
        checkpoint_file: &Path,
        index_dir: &Path,
        chunk_size: usize,
    ) -> Result<u64, Box<dyn Error>> {
        // Memory-map the file
        let file = File::open(file_path)?;
        let mmap = unsafe { Mmap::map(&file)? };
        let file_size = mmap.len();
        mmap.advise(Advice::Sequential).ok();

        // Load/create checkpoint
        let checkpoint = Arc::new(Mutex::new({
            let mut cp = Checkpoint::default();
            if checkpoint_file.exists() {
                let f = File::open(checkpoint_file)?;
                let mut reader = std::io::BufReader::new(f);
                let mut s = String::new();
                reader.read_to_string(&mut s)?;
                cp = serde_json::from_str(&s)?;
                if cp.file_size != file_size {
                    eprintln!(
                        "error: File size in checkpoint {} doesn't match file size {}",
                        cp.file_size, file_size
                    );
                    exit(1);
                }
            } else {
                cp.file_size = file_size;
            }
            cp
        }));

        let stats = Arc::new(checkpoint.lock().unwrap().stats.snapshot());
        let session_start = stats.sk_candidate_count.load(Ordering::Relaxed);

        // Load the address index
        let index = Arc::new(AddressIndex::new(index_dir)?);

        let start_time = Instant::now();

        // Progress bar
        let pb = ProgressBar::new(file_size as u64).with_style(
            ProgressStyle::default_bar()
                .template("[{bar:40.cyan/blue}] {bytes}/{total_bytes} ({percent}%) - {msg}")
                .unwrap()
                .progress_chars("#>-"),
        );

        // Build recovered set from checkpoint
        let mut recovered: HashSet<SK> = HashSet::new();
        for rk in checkpoint.lock().unwrap().results.clone() {
            recovered.insert(rk.sk);
        }

        // Initialize GPU
        let ptx_path = env!("SECP256K1_PTX_PATH");
        let ctx = CudaContext::new(0)?;
        let ptx = Ptx::from_file(ptx_path);
        let module = ctx.load_module(ptx)?;
        let func = module.load_function("sk_to_pkh_kernel")?;
        let default_stream = ctx.default_stream();
        let g_powers_dev = default_stream.clone_htod(&generate_g_powers())?;
        default_stream.synchronize()?;

        // Two pipeline slots: one GPU is processing, one CPU is reading results from
        let padded = chunk_size + 31;
        let mut slots = [Slot::new(&ctx, padded)?, Slot::new(&ctx, padded)?];

        // Per-slot metadata for the chunk currently in flight
        struct Work {
            chunk_start: usize,
            positions: usize,
        }
        let mut pending: [Option<Work>; 2] = [None, None];

        let start_offset = {
            let off = stats.offset.load(Ordering::Relaxed);
            off.saturating_sub(chunk_size)
        };
        let mut offset = start_offset;
        let mut iter = 0usize;
        let mut last_checkpoint = Instant::now();

        loop {
            let slot = iter % 2;
            let prev = 1 - slot;

            // Step 1: Submit next chunk to GPU (starts async H→D + kernel + D→H immediately).
            // This is done BEFORE waiting for the previous slot so the GPU starts working
            // as soon as possible, overlapping with the CPU MPHF work below.
            if offset < file_size {
                let end = (offset + chunk_size).min(file_size);
                // Extend by 31 bytes so the kernel can read full 32-byte SKs at boundary
                let read_end = (end + 31).min(file_size);
                let positions = end - offset;
                slots[slot].submit(&mmap[offset..read_end], &func, &g_powers_dev)?;
                pending[slot] = Some(Work {
                    chunk_start: offset,
                    positions,
                });
                offset = end;
            }

            // Step 2: Wait for the previous slot's D→H to complete, then do parallel MPHF.
            // The GPU is already working on `slot` above while we process `prev` here.
            if let Some(work) = pending[prev].take() {
                slots[prev].sync()?;

                // Access pinned host buffer after stream sync.
                let pkhs = &slots[prev].h_pkhs.as_slice()[..work.positions * 20];

                // Parallel MPHF lookup across all CPU cores (rayon).
                // The sk_candidate_count atomic is NOT incremented inside the closure:
                // doing so with 64 concurrent threads on the same cache line causes severe
                // contention (~200× slowdown). Count non-zero PKHs in a single batch add.
                let hits: Vec<(usize, [u8; 20])> = pkhs
                    .par_chunks(20)
                    .enumerate()
                    .filter_map(|(i, raw)| {
                        if raw.iter().all(|&b| b == 0) {
                            return None;
                        }
                        let pkh: [u8; 20] = raw.try_into().unwrap();
                        if index.contains_address_hash(&pkh) {
                            Some((work.chunk_start + i, pkh))
                        } else {
                            None
                        }
                    })
                    .collect();

                // Count non-zero PKHs with one atomic add instead of N contended adds.
                let n_candidates = pkhs.par_chunks(20)
                    .filter(|c| c.iter().any(|&b| b != 0))
                    .count() as u64;
                stats.sk_candidate_count.fetch_add(n_candidates as usize, Ordering::Relaxed);

                for (hit_offset, pkh) in hits {
                    stats.sk_validated_count.fetch_add(1, Ordering::Relaxed);

                    let sk_start = hit_offset;
                    let sk_end = (sk_start + 32).min(file_size);
                    let mut sk = [0u8; 32];
                    let copy_len = sk_end - sk_start;
                    sk[..copy_len].copy_from_slice(&mmap[sk_start..sk_end]);

                    if !recovered.contains(&sk) {
                        stats.sk_validated_unique_count.fetch_add(1, Ordering::Relaxed);
                        let addr = pkh_to_bitcoin_address(&pkh);
                        let rk = RecoveredKey {
                            sk,
                            pkh,
                            addr,
                            offset: sk_start,
                        };
                        print_result(&rk);
                        checkpoint.lock().unwrap().results.push(rk.clone());
                        recovered.insert(sk);
                    }
                }

                // Release drive image pages for this chunk: prevents the 160GB sequential
                // read from evicting the 17GB index from page cache.
                unsafe { mmap.unchecked_advise_range(UncheckedAdvice::DontNeed, work.chunk_start, work.positions).ok() };

                // Update progress
                let processed = work.chunk_start + work.positions;
                stats.offset.store(processed, Ordering::Relaxed);
                pb.set_position(processed as u64);
                let total = stats.sk_candidate_count.load(Ordering::Relaxed);
                let session_cands = total.saturating_sub(session_start);
                let elapsed = start_time.elapsed().as_secs_f64().max(1e-9);
                let mkps = session_cands as f64 / elapsed / 1e6;
                pb.set_message(format!(
                    "{:.3} Mk/s, validated: {}, unique: {}",
                    mkps,
                    stats.sk_validated_count.load(Ordering::Relaxed),
                    stats.sk_validated_unique_count.load(Ordering::Relaxed),
                ));

                if last_checkpoint.elapsed() >= Duration::from_secs(1) {
                    save_checkpoint(&checkpoint, &stats, checkpoint_file)?;
                    last_checkpoint = Instant::now();
                }
            }

            if offset >= file_size && pending[0].is_none() && pending[1].is_none() {
                break;
            }

            iter += 1;
        }

        // Final checkpoint
        save_checkpoint(&checkpoint, &stats, checkpoint_file)?;

        let unique = stats.sk_validated_unique_count.load(Ordering::Relaxed);
        pb.finish_with_message(format!(
            "GPU scan complete. Candidates: {}, Validated: {} ({} unique)",
            stats.sk_candidate_count.load(Ordering::Relaxed),
            stats.sk_validated_count.load(Ordering::Relaxed),
            unique,
        ));

        Ok(unique as u64)
    }
}

#[cfg(all(test, feature = "cuda"))]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_gpu_matches_cpu_single() {
        // SK=0x08 → PKH=9652d86bedf43ad264362e6e6eba6eb764508127
        let gpu_ctx = gpu::GpuContext::new().expect("GPU context");
        let mut chunk = [0u8; 64];
        chunk[31] = 0x08; // offset 0: sk = [0;31, 8]
        let pkhs = gpu_ctx.process_chunk(&chunk).expect("process_chunk");
        assert_eq!(pkhs[0], hex!("9652d86bedf43ad264362e6e6eba6eb764508127"));
    }

    #[test]
    fn test_gpu_sk3_single() {
        // SK=3 requires point_add(G, 2G), verifies point_add is correct
        use crate::crypto::sk_to_pk_hash;
        let gpu_ctx = gpu::GpuContext::new().expect("GPU context");
        let mut chunk = [0u8; 64];
        chunk[31] = 0x03;
        let pkhs = gpu_ctx.process_chunk(&chunk).expect("process_chunk");
        let mut sk = [0u8; 32];
        sk[31] = 3;
        let expected = sk_to_pk_hash(&sk).expect("valid SK");
        assert_eq!(pkhs[0], expected, "SK=3 mismatch (tests point_add)");
    }

    #[test]
    fn test_gpu_invalid_sk_zeros() {
        let gpu_ctx = gpu::GpuContext::new().expect("GPU context");
        let chunk = [0u8; 64];
        let pkhs = gpu_ctx.process_chunk(&chunk).expect("process_chunk");
        // All-zero SK is invalid → zero output
        assert_eq!(pkhs[0], [0u8; 20]);
    }

    #[test]
    fn test_gpu_batch_matches_cpu() {
        use crate::crypto::sk_to_pk_hash;
        let gpu_ctx = gpu::GpuContext::new().expect("GPU context");

        // Place each SK at offset i*64 so SK reads don't interfere (stride 64 > 32)
        // SK at offset i*64: chunk[i*64..i*64+32] = [0;31, i+1]
        let n = 32usize;
        let stride = 64usize;
        let mut chunk = vec![0u8; n * stride + 32]; // +32 so last SK read doesn't go OOB
        for i in 0..n {
            chunk[i * stride + 31] = (i + 1) as u8;
        }

        let pkhs = gpu_ctx.process_chunk(&chunk).expect("process_chunk");

        for i in 0..n {
            let mut sk = [0u8; 32];
            sk[31] = (i + 1) as u8;
            let expected = sk_to_pk_hash(&sk).expect("valid SK");
            assert_eq!(pkhs[i * stride], expected, "mismatch at offset {}", i * stride);
        }
    }
}

/// GPU scan entry point (public API)
pub fn scan_raw_gpu(
    file_path: &Path,
    checkpoint_file: &Path,
    index_dir: &Path,
    chunk_size: usize,
) -> Result<u64, Box<dyn Error>> {
    #[cfg(feature = "cuda")]
    return gpu::scan_raw_gpu_inner(file_path, checkpoint_file, index_dir, chunk_size);

    #[cfg(not(feature = "cuda"))]
    {
        let _ = (file_path, checkpoint_file, index_dir, chunk_size);
        Err("Binary not compiled with CUDA feature".into())
    }
}
