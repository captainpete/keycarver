use crate::crypto::{PKH, SK};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicUsize, Ordering};

/// Statistics for tracking processing progress
#[derive(Default, Serialize, Deserialize)]
pub struct Stats {
    pub sk_candidate_count: AtomicUsize,
    pub sk_validated_count: AtomicUsize,
    pub sk_validated_unique_count: AtomicUsize,
    pub cache_hits: AtomicUsize,
    pub cache_misses: AtomicUsize,
    pub offset: AtomicUsize,
}

impl Stats {
    pub fn snapshot(&self) -> Stats {
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
pub struct RecoveredKey {
    pub sk: SK,
    pub pkh: PKH,
    pub addr: String,
    pub offset: usize,
}

#[derive(Default, Serialize, Deserialize)]
pub struct Checkpoint {
    pub stats: Stats,
    pub results: Vec<RecoveredKey>,
    pub file_size: usize,
}
