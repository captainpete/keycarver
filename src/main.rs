mod address_index;
mod block_scanner;
use clap::{Parser, Subcommand};
use std::time::Instant;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
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
    QueryAddress {
        /// Address to check
        #[arg(long)]
        address: String,
        /// Path to the address index folder
        #[arg(long)]
        index_dir: String,
    },
}

fn build_index(block_dir: &str, index_dir: &str, factor: f64) -> Result<(), Box<dyn std::error::Error>> {
    let addresses = block_scanner::extract_addresses_from_folder(block_dir)?;
    address_index::AddressIndex::create(
        std::path::Path::new(&index_dir),
        &addresses,
        factor
    )?;

    Ok(())
}

fn query_index(formatted_address: &str, index_dir: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("Querying index {} for address {}", index_dir, formatted_address);

    let index = address_index::AddressIndex::load(&std::path::Path::new(&index_dir))?;

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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::parse();

    match args.command {
        Commands::BuildIndex { block_dir, index_dir, factor } =>
            build_index(block_dir.as_str(), index_dir.as_str(), factor)?,
        Commands::QueryAddress { address, index_dir } =>
            query_index(address.as_str(), index_dir.as_str())?,
    }

    Ok(())
}

// TODO:
// 3. Write a public key generator that uses big-endian bytes from files as private keys - move into module
// 4. For each public key, generate the addresses associated (check out https://docs.rs/bitcoin/latest/src/bitcoin/address/mod.rs.html#631-639)
// 5. For each of these addresses, check if they're in the index
// 6. Parallelize the whole thing using rayon
