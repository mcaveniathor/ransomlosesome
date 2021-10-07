extern crate structopt;
use structopt::StructOpt;
extern crate pretty_env_logger;
#[macro_use] extern crate log;
#[macro_use] extern crate anyhow;
extern crate aes;
use aes::{Aes256, Aes256Ctr};
use aes::cipher::{
    NewBlockCipher,
    StreamCipher,
    FromBlockCipher,
    generic_array::GenericArray,
};
extern crate hex;
extern crate rand;
use rand::{ Rng, thread_rng };

use std::path::{PathBuf,Path};

#[derive(Debug,StructOpt)]
struct Opt {
    #[structopt(short, long)]
    /// Top-level directory to encrypt
    dir: PathBuf,
    #[structopt(short,long)]
    /// Hex-encoded key to be used for encryption/decryption
    key: String,
    #[structopt(long)]
    /// Enable to delete existing files
    delete: bool,
}


fn encrypt_file<P: AsRef<Path>>(cipher: Aes256, path: P, delete: bool) -> anyhow::Result<()> {
    let path = path.as_ref();
    if !path.is_file() {
        println!("Test");
   }
   else {
        let nonce = thread_rng().gen::<[u8; 16]>();
        let mut stream_cipher = Aes256Ctr::from_block_cipher(cipher, GenericArray::from_slice(&nonce));
        let mut contents = std::fs::read(&path)?;
        stream_cipher.try_apply_keystream(&mut contents).map_err(|_| anyhow!("Reached end of keystream."))?;
        let extension = match  path.extension() {
            Some(s) => format!("{}{}", s.to_str().unwrap(), "enc"),
            _ => "enc".to_string(),
        };
        std::fs::write(path.with_extension(extension), contents)?;
        info!("Encrypted file {}", path.display());
        if delete {
            std::fs::write(path, "")?;
        }



   }
    Ok(())

}

fn encrypt_directory<P: AsRef<Path>+Send+Sync>(path: P, key: &[u8], delete: bool) -> anyhow::Result<()> {
    let cipher = Aes256::new_from_slice(key)
        .map_err(|_| anyhow!("Invalid key length."))?;
    let path = path.as_ref();
    if !path.is_dir() {
        bail!("Path does not exist or is not a directory: {}", path.display());
    }
    info!("Encrypting directory {}", path.display());
    let entries = path.read_dir()?;
    for entry in entries {
        if let Ok(entry) = entry {
            if let Ok(file_type) = entry.file_type() {
                if file_type.is_file() {
                    encrypt_file(cipher.clone(), entry.path(), delete)?;
                }
                else if file_type.is_dir() {
                    encrypt_directory(entry.path(), &key, delete)?;
                }
            }
        }
    }

    Ok(())
}

fn main() -> anyhow::Result<()> {
    let opt = Opt::from_args();
    pretty_env_logger::init();
    run(opt).map_err(|e| { 
        error!("{}",e);
        e
    })
}

fn run(opt: Opt) -> anyhow::Result<()> {
    encrypt_directory(opt.dir, &hex::decode(&opt.key)?, opt.delete)?;
    Ok(())
}
