use PFDE_KZG::commit::powers_cache::PowersCache;
use ark_bw6_761::BW6_761;
use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::test_rng;
use std::path::PathBuf;

type Scalar = <BW6_761 as Pairing>::ScalarField;

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("setup-cache") => run_setup_cache(args.collect()),
        Some(_) => Err(usage()),
        None => Err(usage()),
    }
}

fn run_setup_cache(args: Vec<String>) -> Result<(), String> {
    let mut range = None;
    let mut dir = PathBuf::from(".cache/kzg/bw6_761");
    let mut chunk_size = 1usize << 16;
    // G2 powers are only needed up to the degree of the sampled vanishing
    // polynomial, so a few thousand covers every R the benchmark uses.
    let mut g2_range = 1usize << 12;
    let mut tau = None;

    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--range" => {
                i += 1;
                let value = args.get(i).ok_or_else(usage)?;
                range = Some(value.parse::<usize>().map_err(|_| usage())?);
            }
            "--dir" => {
                i += 1;
                let value = args.get(i).ok_or_else(usage)?;
                dir = PathBuf::from(value);
            }
            "--g2-range" => {
                i += 1;
                let value = args.get(i).ok_or_else(usage)?;
                g2_range = value.parse::<usize>().map_err(|_| usage())?;
            }
            "--chunk-size" => {
                i += 1;
                let value = args.get(i).ok_or_else(usage)?;
                chunk_size = value.parse::<usize>().map_err(|_| usage())?;
            }
            "--tau-hex" => {
                i += 1;
                let value = args.get(i).ok_or_else(usage)?;
                tau = Some(parse_scalar_hex(value)?);
            }
            _ => return Err(usage()),
        }
        i += 1;
    }

    let range = range.ok_or_else(usage)?;
    let mut cache = if dir.join("manifest.txt").exists() {
        PowersCache::<BW6_761>::open(&dir).map_err(|err| err.to_string())?
    } else {
        let tau = tau.unwrap_or_else(|| Scalar::rand(&mut test_rng()));
        PowersCache::<BW6_761>::open_or_create(&dir, tau, chunk_size, g2_range)
            .map_err(|err| err.to_string())?
    };

    cache.ensure_range(range).map_err(|err| err.to_string())?;
    let manifest = cache.manifest();
    println!("cache_dir={}", dir.display());
    println!("generated={}", manifest.generated);
    println!("g2_range={}", manifest.g2_range);
    println!("chunk_size={}", manifest.chunk_size);
    println!("tau={}", scalar_to_hex(&manifest.tau));
    Ok(())
}

fn usage() -> String {
    "usage: cargo run -- setup-cache --range <N> [--g2-range <N>] [--dir <PATH>] [--chunk-size <N>] [--tau-hex <HEX>]"
        .to_string()
}

fn scalar_to_hex(value: &Scalar) -> String {
    let mut bytes = Vec::new();
    value.serialize_compressed(&mut bytes).unwrap();
    encode_hex(&bytes)
}

fn parse_scalar_hex(value: &str) -> Result<Scalar, String> {
    let bytes = decode_hex(value)?;
    Scalar::deserialize_compressed(&*bytes).map_err(|err| err.to_string())
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(nibble_to_hex(byte >> 4));
        out.push(nibble_to_hex(byte & 0x0f));
    }
    out
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if value.len() % 2 != 0 {
        return Err("tau hex length must be even".to_string());
    }

    let mut out = Vec::with_capacity(value.len() / 2);
    let bytes = value.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let high = hex_to_nibble(bytes[i])?;
        let low = hex_to_nibble(bytes[i + 1])?;
        out.push((high << 4) | low);
    }
    Ok(out)
}

fn nibble_to_hex(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'a' + value - 10) as char,
        _ => unreachable!(),
    }
}

fn hex_to_nibble(value: u8) -> Result<u8, String> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err("tau hex contains a non-hex character".to_string()),
    }
}
