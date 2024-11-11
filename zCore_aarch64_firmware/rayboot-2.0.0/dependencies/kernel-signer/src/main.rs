#![warn(dead_code)]
use irsa::{RsaPrivateKey, RsaPublicKey, RSA_2048_LEN, Sha256};

struct KernelHeader {
    pub pk_size: usize,
    pub sign_size: usize
}

fn main() {
    // Generate RSA key
    let sk = RsaPrivateKey::new(RSA_2048_LEN).expect("generate RSA private key failed");
    let pk = RsaPublicKey::from_private_key(&sk).expect("generate RSA public key failed");
    let pk_raw = pk.to_raw();

    // Load kernel image from disk
    let kernel_image = std::fs::read("kernel.elf").expect("open kernel image failed");

    // Get kernel hash
    let mut kernel_hasher = Sha256::new();
    kernel_hasher.input(kernel_image.as_slice()).expect("failed to load kernel to hasher");
    let kernel_hash = kernel_hasher.finalize().expect("fail to hash kernel image");

    // Get public key hash
    let mut pk_hasher = Sha256::new();
    pk_hasher.input(pk_raw.as_slice()).expect("fail to load pk_raw to hasher");
    let pk_hash = pk_hasher.finalize().expect("fail to hash public key");

    // Use private key to sign kernel hash
    let kernel_sign = sk.sign(&kernel_hash).expect("fail to sign kernel hash");

    // Package three of them to signed image
    let head = KernelHeader {
        pk_size: pk_raw.len(),
        sign_size: kernel_sign.len()
    };
    let head = unsafe { std::slice::from_raw_parts(&head as *const KernelHeader as *const u8, std::mem::size_of::<KernelHeader>()) };
    let mut final_image: Vec<u8> = vec![];
    for i in head {
        final_image.push(*i);
    }
    assert_eq!(final_image.len(), 2 * std::mem::size_of::<usize>());
    for i in pk_raw {
        final_image.push(i);
    }
    for i in kernel_sign {
        final_image.push(i);
    }
    for i in kernel_image {
        final_image.push(i);
    }

    // Write to disk
    std::fs::write("kernel", final_image).expect("fail to write signed kernel to disk");
    std::fs::write("pk_hash", pk_hash).expect("fail to write pk_hash to disk");
}