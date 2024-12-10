use std::fs::File;
use std::path::Path;
use std::str::FromStr;

use boomphf::Mphf;

use serde::{Serialize, Deserialize};
use bitcoin::Address;
use bitcoin::address::NetworkUnchecked;
use std::collections::HashSet;

// Structure to hold our index
#[derive(Serialize, Deserialize)]
pub struct AddressIndex {
    mphf: Mphf<Address<NetworkUnchecked>>,
    addresses: Vec<Address<NetworkUnchecked>>,
}

impl PartialEq for AddressIndex {
    fn eq(&self, other: &Self) -> bool {
        self.addresses == other.addresses
    }
}

impl AddressIndex {
    /// Look up an address. Returns true if present, false otherwise.
    pub fn contains(&self, formatted_address: &str) -> bool {
        let address = Address::from_str(formatted_address).unwrap();
        match self.mphf.try_hash(&address) {
            Some(index) => {
                let found_address = &self.addresses[index as usize];
                *found_address == address
            },
            None => false,
        }
    }

    pub fn len(&self) -> usize {
        self.addresses.len()
    }

    pub fn save(&self, output_path: &Path) -> std::io::Result<()> {
        print!("Writing address index to disk... ");
        let mut out_file = File::create(output_path)?;
        bincode::serialize_into(&mut out_file, &self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        println!("done");

        Ok(())
    }
}

pub fn build_index(addresses: &HashSet<Address>, c: f64) -> AddressIndex {
    print!("Constructing minimal perfect hashing function with factor {}... ", c);
    let addresses_unchecked: Vec<Address<NetworkUnchecked>> = addresses.iter().map(|a| a.clone().into_unchecked()).collect();
    let mphf = Mphf::new_parallel(c, &addresses_unchecked, None);
    println!("done");

    let mut addresses_ordered: Vec<Option<Address<NetworkUnchecked>>> =
        vec![None; addresses_unchecked.len()];

    for address in &addresses_unchecked {
        let index = mphf.try_hash(address).unwrap();
        addresses_ordered[index as usize] = Some(address.clone());
    }

    let addresses_ordered: Vec<Address<NetworkUnchecked>> =
        addresses_ordered.into_iter().map(|addr| addr.unwrap()).collect();

    AddressIndex { mphf: mphf, addresses: addresses_ordered }
}

/// Load an AddressIndex from a file
pub fn load_index(path: &Path) -> std::io::Result<AddressIndex> {
    let file = File::open(path)?;
    let index: AddressIndex = bincode::deserialize_from(file)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    Ok(index)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_memership() -> std::io::Result<()> {
        // Create test index
        let formatted_addresses = [
            "bc1qrat292ehvxrv9qzfatswcqglymvk2mcw2jktny",
            "185AVLjTpLjXDpMTungGgoFsTrteixGNWB",
            "bc1qla25lharlzckesmfru8efdyd65jzy979svzq0ek09vasv23pn5rqp9rvvf",
        ];
        let addresses: HashSet<Address> = formatted_addresses
            .iter()
            .map(|addr| Address::from_str(*addr).unwrap().assume_checked())
            .collect();
        let index = build_index(&addresses, 1.7);

        // Check index length
        assert!(
            index.len() == 3,
            "Index length {} does not match expected length 3",
            index.len()
        );

        // Check that all known addresses are in the index
        for addr in &formatted_addresses {
            assert!(
                index.contains(*addr),
                "Address {:?} not found in the index",
                addr
            );
        }

        // Check that an unknown address is not in the index
        let unknown_address = "3D6YwwRAsyEEZHhkUaJC3gYtBN7FxKpyPC";
        assert!(
            !index.contains(unknown_address),
            "Unknown address was incorrectly found in the index"
        );

        Ok(())
    }

    #[test]
    fn test_save_and_load() -> std::io::Result<()> {
        let dir = tempdir()?;
        let path = dir.path().join("index.bin");
        let formatted_addresses = [
            "bc1qrat292ehvxrv9qzfatswcqglymvk2mcw2jktny",
            "185AVLjTpLjXDpMTungGgoFsTrteixGNWB",
            "bc1qla25lharlzckesmfru8efdyd65jzy979svzq0ek09vasv23pn5rqp9rvvf",
        ];
        let addresses: HashSet<Address> = formatted_addresses
            .iter()
            .map(|addr| Address::from_str(*addr).unwrap().assume_checked())
            .collect();

        let index = build_index(&addresses, 1.7);

        // Save and reload
        index.save(&path)?;
        let loaded_index = load_index(&path)?;

        assert!(
            loaded_index == index,
            "Loaded index is not equal to the original index"
        );

        Ok(())
    }

}
