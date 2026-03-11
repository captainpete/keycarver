fn main() {
    if std::env::var("CARGO_FEATURE_CUDA").is_ok() {
        println!("cargo:rerun-if-changed=kernels/secp256k1_hash.cu");
        println!("cargo:rerun-if-changed=kernels/secp256k1_field.cuh");
        println!("cargo:rerun-if-changed=kernels/secp256k1_ec.cuh");
        println!("cargo:rerun-if-changed=kernels/sha256.cuh");
        println!("cargo:rerun-if-changed=kernels/ripemd160.cuh");

        let cuda_root = std::env::var("CUDA_ROOT")
            .or_else(|_| std::env::var("CUDA_PATH"))
            .unwrap_or_else(|_| "/usr/local/cuda".to_string());
        let out_dir = std::env::var("OUT_DIR").unwrap();
        let ptx_out = format!("{}/secp256k1_hash.ptx", out_dir);

        let status = std::process::Command::new(format!("{}/bin/nvcc", cuda_root))
            .args([
                "-ptx",
                "-arch=sm_86",
                "-O3",
                "--use_fast_math",
                "-Ikernels",
                "kernels/secp256k1_hash.cu",
                "-o",
                &ptx_out,
            ])
            .status()
            .expect("nvcc failed to run");

        if !status.success() {
            panic!("nvcc compilation failed");
        }

        println!("cargo:rustc-env=SECP256K1_PTX_PATH={}", ptx_out);
    }
}
