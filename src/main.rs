mod address_index;
mod block_scanner;
mod file_scanner;
mod crypto;

use clap::{Parser, Subcommand};
use std::time::Instant;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::path::Path;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Build an address index from a directory of block files
    BuildIndex {
        /// Location of block files
        #[arg(long)]
        block_dir: String,
        /// Intended folder for database files
        #[arg(long)]
        index_dir: String,
        /// Optional factor, recommended 1.7 - 8.0
        #[arg(long, default_value = "1.7")]
        factor: f64,
    },
    /// Query the address index for a BitCoin p2pkh address
    QueryAddress {
        /// Address to check
        #[arg(long)]
        address: String,
        /// Path to the address index folder
        #[arg(long)]
        index_dir: String,
    },
    /// Scan a file for keys using an address index for confirmation
    Scan {
        /// File to scan
        #[arg(long)]
        file: String,
        /// Path to the address index folder
        #[arg(long)]
        index_dir: String,
    },
}

fn build_index(block_dir: &str, index_dir: &str, gamma: f64) -> Result<(), Box<dyn std::error::Error>> {
    let index_dir = Path::new(index_dir);
    let multi_progress = MultiProgress::new();
    let bar_style = ProgressStyle::default_bar()
        .template("{msg} [{bar:40.cyan/blue}] {pos}/{len} ({percent}%)")
        .unwrap()
        .progress_chars("#>-");
    let spinner_style = ProgressStyle::default_spinner()
        .template("{msg} {spinner:.cyan/blue}")
        .unwrap();

    // Step 1: Create a sled database, populate with unique addresses
    let db_dir = index_dir.join("rocksdb");
    std::fs::create_dir_all(&db_dir)?;

    let step1_pb = multi_progress.add(ProgressBar::new(0).with_style(bar_style.clone()));
    step1_pb.set_message("Step 1: Scanning block files and populating database");
    let start = Instant::now();
    block_scanner::load_unique_addresses_into_database(block_dir, &db_dir, &step1_pb)?;
    step1_pb.finish_with_message(format!("Step 1: Done in {:.2?}", start.elapsed()));

    // Step 2: Create staging files
    let staging_dir = index_dir.join("staging");
    std::fs::create_dir_all(&staging_dir)?;

    let step2_pb = multi_progress.add(ProgressBar::new(0).with_style(bar_style.clone()));
    step2_pb.set_message("Step 2: Creating staging files");
    let start = Instant::now();
    address_index::create_staging_files(&db_dir, &staging_dir, 64usize, &step2_pb)?;
    step2_pb.finish_with_message(format!("Step 2: Done in {:.2?}", start.elapsed()));

    // Step 3: Create MPHF
    let step3_pb = multi_progress.add(ProgressBar::new_spinner().with_style(spinner_style.clone()));
    step3_pb.enable_steady_tick(std::time::Duration::from_millis(100));
    step3_pb.set_message("Step 3: Creating MPHF");
    let start = Instant::now();
    let mphf = address_index::create_mphf(&staging_dir, gamma)?;
    address_index::save_mphf(&index_dir, &mphf)?;
    step3_pb.finish_with_message(format!("Step 3: Done in {:.2?}", start.elapsed()));

    // Step 4: Create the final index
    let step4_pb = multi_progress.add(ProgressBar::new(0).with_style(bar_style.clone()));
    step4_pb.set_message("Step 4: Creating final index");
    let start = Instant::now();
    address_index::create_index(&mphf, &staging_dir, &index_dir, &step4_pb)?;
    step4_pb.finish_with_message(format!("Step 4: Done in {:.2?}", start.elapsed()));

    // Step 5: Clean up temporary directories
    std::fs::remove_dir_all(staging_dir)?;
    std::fs::remove_dir_all(db_dir)?;

    Ok(())
}

fn query_index(formatted_address: &str, index_dir: &str) -> Result<(), Box<dyn std::error::Error>> {
    // For testing:
    //      14YhipytTEvpBaSX5hRnC1QoRUCpn5b9M2 randomly generated, should not be found
    //      1A1Q3o2N9kAJsbXhtyDU6AZxV5XkZP8iR7 should be present in blk02507.dat

    eprintln!("Querying index {} for address {}", index_dir, formatted_address);
    let index = address_index::AddressIndex::new(&Path::new(&index_dir))?;
    let start = Instant::now();
    let result = index.contains_address_str(formatted_address);
    let duration = start.elapsed();
    if result {
        println!("Found address in {:?}", duration);
    } else {
        println!("Address not found {:?}", duration);
    }

    Ok(())
}

fn scan(file_path: &str, index_dir: &str) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("Scanning {} using {}", file_path, index_dir);
    let start = Instant::now();
    let n_found = file_scanner::scan(&Path::new(&file_path), &Path::new(&index_dir))?;
    eprintln!("Found {} key/s in {:?}", n_found, start.elapsed());
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::parse();

    match args.command {
        Commands::BuildIndex { block_dir, index_dir, factor } =>
            build_index(block_dir.as_str(), index_dir.as_str(), factor)?,
        Commands::QueryAddress { address, index_dir } =>
            query_index(address.as_str(), index_dir.as_str())?,
        Commands::Scan { file, index_dir } =>
            scan(file.as_str(), index_dir.as_str())?
    }

    Ok(())
}
