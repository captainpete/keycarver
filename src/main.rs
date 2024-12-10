mod address_index;
mod scanner;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    BuildIndex {
        /// Block file path
        #[arg(long)]
        folder: String,
        /// Path to the target address index file
        #[arg(long)]
        index_file: String,
        /// Optional factor, recommended 1.7 - 8.0
        #[arg(long, default_value = "1.7")]
        factor: f64,
    },
    QueryAddress {
        /// Address to check
        #[arg(long)]
        address: String,
        /// Path to the address index file
        #[arg(long)]
        index_file: String,
    },
}

fn build_index(folder: &str, index_file: &str, factor: f64) -> Result<(), Box<dyn std::error::Error>> {
    let addresses = scanner::extract_addresses_from_folder(folder)?;
    let index = address_index::build_index(&addresses, factor);
    index.save(std::path::Path::new(&index_file))?;

    // for address in addresses {
    //     println!("{}", address);
    // }
    // 1JaChwLni9MsK^C3P92RahWgj4vX4DhYTW9QRezjsEZ7pPQFn
    // 185AVLjTpLjXDpMTungGgoFsTrteixGNWB
    // bc1qla25lharlzckesmfru8efdyd65jzy979svzq0ek09vasv23pn5rqp9rvvf

    Ok(())
}

fn query_index(formatted_address: &str, index_file: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("Querying index {} for address {}", index_file, formatted_address);
    let index_path = std::path::Path::new(&index_file);
    let index = address_index::load_index(index_path).expect("Failed to load index");
    match index.contains(formatted_address) {
        true => println!("Found!"),
        false => println!("Not found"),
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::parse();

    match args.command {
        Commands::BuildIndex { folder, index_file, factor } => build_index(folder.as_str(), index_file.as_str(), factor)?,
        Commands::QueryAddress { address, index_file } => query_index(address.as_str(), index_file.as_str())?,
    }

    Ok(())
}

// TODO:
// 1. Finish writing block parser that outputs addresses - move into a module
// 2. Build an index using the addresses - move into the index module
// 3. Write a public key generator that uses big-endian bytes from files as private keys - move into module
// 4. For each public key, generate the addresses associated (check out https://docs.rs/bitcoin/latest/src/bitcoin/address/mod.rs.html#631-639)
// 5. For each of these addresses, check if they're in the index
// 6. Parallelize the whole thing using rayon
