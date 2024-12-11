use bitcoin::address::NetworkUnchecked;
use bitcoin::Address;
use boomphf::Mphf;
use heed::{Env, EnvOpenOptions, Database, types::*, byteorder, RoTxn};
use indicatif::{ProgressBar, ProgressIterator};
use std::collections::HashSet;
use std::fs;
use std::fs::File;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;
use std::io::Write;
use std::error::Error;

pub struct AddressIndex {
    mphf: Mphf<Address<NetworkUnchecked>>,
    env: Env,
}

impl AddressIndex {

    fn env_open(dir: &Path) -> Result<Env, Box<dyn Error>> {
        unsafe {
            let env = EnvOpenOptions::new()
                .map_size(10 * 1024 * 1024 * 1024) // 10 GiB
                .open(dir)?;
            Ok(env)
        }
    }

    /// Create a new `AddressIndex` with a given MPHF and a set of addresses.
    pub fn create(
        dir: &Path,
        addresses: &HashSet<Address>,
        mphf_load_factor: f64,
    ) -> Result<(), Box<dyn Error>> {
        // Build the MPHF
        let pb = ProgressBar::new_spinner();
        pb.enable_steady_tick(Duration::from_millis(100));
        pb.set_message("Constructing MPHF");
        let addresses_unchecked: Vec<Address<NetworkUnchecked>> =
            addresses.iter().map(|a| a.clone().into_unchecked()).collect();
        let mphf = Mphf::new_parallel(mphf_load_factor, &addresses_unchecked, None);
        pb.finish_with_message("MPHF constructed");

        // Ensure the directory exists
        std::fs::create_dir_all(dir)?;

        // serialize mphf to a file in the folder using bincode
        let mphf_bytes = bincode::serialize(&mphf).unwrap();
        let mut mphf_file = File::create(dir.join("mphf.bin")).unwrap();
        mphf_file.write_all(&mphf_bytes).unwrap();

        // Create or open the LMDB environment and database
        let env = Self::env_open(&dir)?;
        let mut wtxn = env.write_txn()?;
        let db: Database<U64<byteorder::NativeEndian>, SerdeBincode<Address<NetworkUnchecked>>> =
            env.create_database(&mut wtxn, None)?;

        // Populate the database
        for address in (&addresses_unchecked).iter().progress() {
            if let Some(hash) = mphf.try_hash(address) {
                db.put(&mut wtxn, &hash, address)?;
            }
        }
        wtxn.commit()?;

        // Read final count from database
        let index = Self { mphf, env };
        let count = index.len();
        pb.finish_with_message(format!("Index populated with {} addresses", count));

        Ok(())
    }

    pub fn load(dir: &Path) -> Result<Self, Box<dyn Error>> {
        let mphf: Mphf<Address<NetworkUnchecked>> = bincode::deserialize(&fs::read(dir.join("mphf.bin"))?)?;
        let env = Self::env_open(dir)?;
        Ok(Self { mphf, env })
    }

    pub fn read_txn(&self) -> Result<(Database<U64<byteorder::NativeEndian>, SerdeBincode<Address<NetworkUnchecked>>>, RoTxn), Box<dyn Error>> {
        let rtxn = self.env.read_txn()?;
        let db = self
            .env
            .open_database::<U64<byteorder::NativeEndian>, SerdeBincode<Address<NetworkUnchecked>>>(&rtxn, None)?
            .ok_or("Could not open database")?;
        Ok((db, rtxn))
    }

    pub fn contains_address_str(&self, formatted_address: &str) -> bool {
        let address = Address::from_str(formatted_address).unwrap();
        self.contains_address(&address)
    }

    pub fn contains_address(&self, address: &Address<NetworkUnchecked>) -> bool {
        match self.mphf.try_hash(address) {
            Some(index) => {
                if let Ok((db, rtxn)) = self.read_txn() {
                    db.get(&rtxn, &index)
                        .map(|opt| opt.map_or(false, |stored| stored == *address))
                        .unwrap_or(false)
                } else {
                    false
                }
            }
            None => false,
        }
    }

    pub fn len(&self) -> u64 {
        let (db, rtxn) = self.read_txn().unwrap();
        db.len(&rtxn).unwrap()
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use std::collections::HashSet;
    use std::str::FromStr;

    #[test]
    fn test_membership() -> Result<(), Box<dyn std::error::Error>> {
        // Create test index
        let formatted_addresses = [
            "bc1qrat292ehvxrv9qzfatswcqglymvk2mcw2jktny",
            "185AVLjTpLjXDpMTungGgoFsTrteixGNWB",
            "bc1qla25lharlzckesmfru8efdyd65jzy979svzq0ek09vasv23pn5rqp9rvvf",
        ];

        let addresses: HashSet<Address> = formatted_addresses
            .iter()
            .map(|addr| Address::from_str(addr).unwrap().assume_checked())
            .collect();

        let dir = tempdir()?;
        AddressIndex::create(dir.path(), &addresses, 1.7)?;

        let index = AddressIndex::load(dir.path())?;

        // Check index length
        assert_eq!(
            index.len(),
            formatted_addresses.len() as u64,
            "Index length does not match expected length"
        );

        // Check that all known addresses are in the index
        for addr in &formatted_addresses {
            assert!(
                index.contains_address_str(addr),
                "Address {:?} not found in the index",
                addr
            );
        }

        // Check that an unknown address is not in the index
        let unknown_address = "3D6YwwRAsyEEZHhkUaJC3gYtBN7FxKpyPC";
        assert!(
            !index.contains_address_str(unknown_address),
            "Unknown address was incorrectly found in the index"
        );

        Ok(())
    }

    #[test]
    fn test_save_and_load() -> Result<(), Box<dyn std::error::Error>> {
        let formatted_addresses = [
            "bc1qrat292ehvxrv9qzfatswcqglymvk2mcw2jktny",
            "185AVLjTpLjXDpMTungGgoFsTrteixGNWB",
            "bc1qla25lharlzckesmfru8efdyd65jzy979svzq0ek09vasv23pn5rqp9rvvf",
        ];

        let addresses: HashSet<Address> = formatted_addresses
            .iter()
            .map(|addr| Address::from_str(addr).unwrap().assume_checked())
            .collect();

        let dir = tempdir()?;
        AddressIndex::create(dir.path(), &addresses, 1.7)?;

        let index = AddressIndex::load(dir.path())?;

        // Ensure all addresses can be looked up in the loaded index
        for addr in &formatted_addresses {
            assert!(
                index.contains_address_str(addr),
                "Address {:?} not found in the loaded index",
                addr
            );
        }

        // Check length consistency
        assert_eq!(
            index.len(),
            formatted_addresses.len() as u64,
            "Loaded index length does not match expected length"
        );

        Ok(())
    }
}
