use crate::commit::kzg::Powers;
use ark_ec::{CurveGroup, pairing::Pairing};
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::any::type_name;
use std::fs::{self, File};
use std::io::{self, Seek};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use thiserror::Error;

const MANIFEST_FILE: &str = "manifest.txt";
const MANIFEST_VERSION: &str = "1";

#[derive(Debug, Error)]
pub enum PowersCacheError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] ark_serialize::SerializationError),
    #[error("invalid cache manifest")]
    InvalidManifest,
    #[error("unsupported cache version {0}")]
    UnsupportedVersion(String),
    #[error("cache was created for curve {found}, not {expected}")]
    CurveMismatch { expected: String, found: String },
    #[error("cache chunk size mismatch: expected {expected}, found {found}")]
    ChunkSizeMismatch { expected: usize, found: usize },
    #[error("cache tau mismatch")]
    TauMismatch,
    #[error("requested range {requested} exceeds cached range {generated}")]
    RangeUnavailable { requested: usize, generated: usize },
    #[error("range {0} does not fit into u64 exponentiation")]
    RangeTooLarge(usize),
}

pub struct StoredPowers<C: Pairing> {
    pub tau: C::ScalarField,
    pub powers: Powers<C>,
}

#[derive(Debug, Clone)]
pub struct PowersCacheManifest<C: Pairing> {
    pub chunk_size: usize,
    pub generated: usize,
    pub tau: C::ScalarField,
    _curve: PhantomData<C>,
}

impl<C: Pairing> PowersCacheManifest<C> {
    fn new(tau: C::ScalarField, chunk_size: usize) -> Self {
        Self {
            chunk_size,
            generated: 0,
            tau,
            _curve: PhantomData,
        }
    }
}

pub struct PowersCache<C: Pairing> {
    root: PathBuf,
    manifest: PowersCacheManifest<C>,
}

impl<C: Pairing> PowersCache<C> {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, PowersCacheError> {
        let root = root.as_ref().to_path_buf();
        let manifest = read_manifest::<C>(&root)?;
        Ok(Self { root, manifest })
    }

    pub fn open_or_create(
        root: impl AsRef<Path>,
        tau: C::ScalarField,
        chunk_size: usize,
    ) -> Result<Self, PowersCacheError> {
        let root = root.as_ref().to_path_buf();
        if manifest_path(&root).exists() {
            let cache = Self::open(&root)?;
            if cache.manifest.chunk_size != chunk_size {
                return Err(PowersCacheError::ChunkSizeMismatch {
                    expected: chunk_size,
                    found: cache.manifest.chunk_size,
                });
            }
            if cache.manifest.tau != tau {
                return Err(PowersCacheError::TauMismatch);
            }
            return Ok(cache);
        }

        fs::create_dir_all(&root)?;
        let manifest = PowersCacheManifest::<C>::new(tau, chunk_size);
        write_manifest(&root, &manifest)?;
        Ok(Self { root, manifest })
    }

    pub fn manifest(&self) -> &PowersCacheManifest<C> {
        &self.manifest
    }

    pub fn ensure_range(&mut self, range: usize) -> Result<(), PowersCacheError> {
        while self.manifest.generated < range {
            let remainder = self.manifest.generated % self.manifest.chunk_size;
            if remainder == 0 {
                let start = self.manifest.generated;
                let remaining = range - start;
                let len = remaining.min(self.manifest.chunk_size);
                let chunk = Powers::<C>::unsafe_setup_from(self.manifest.tau, start, len)?;
                let path = chunk_path(&self.root, start, len);
                let mut file = File::create(path)?;
                write_chunk(&mut file, &chunk)?;
                self.manifest.generated += len;
            } else {
                let start = self.manifest.generated - remainder;
                let current_len = remainder;
                let target_len = (range - start).min(self.manifest.chunk_size);
                let existing_path = chunk_path(&self.root, start, current_len);
                let mut existing_file = File::open(&existing_path)?;
                let mut chunk = read_chunk::<C>(&mut existing_file)?;
                let missing = target_len - current_len;
                let suffix = Powers::<C>::unsafe_setup_from(
                    self.manifest.tau,
                    self.manifest.generated,
                    missing,
                )?;
                chunk.g1.extend(suffix.g1);
                chunk.g2.extend(suffix.g2);
                fs::remove_file(existing_path)?;
                let path = chunk_path(&self.root, start, target_len);
                let mut file = File::create(path)?;
                write_chunk(&mut file, &chunk)?;
                self.manifest.generated = start + target_len;
            }
            write_manifest(&self.root, &self.manifest)?;
        }
        Ok(())
    }

    pub fn load_prefix(&self, range: usize) -> Result<Powers<C>, PowersCacheError> {
        self.load_prefix_with_tau(range).map(|stored| stored.powers)
    }

    pub fn load_prefix_with_tau(&self, range: usize) -> Result<StoredPowers<C>, PowersCacheError> {
        if range > self.manifest.generated {
            return Err(PowersCacheError::RangeUnavailable {
                requested: range,
                generated: self.manifest.generated,
            });
        }

        let mut g1 = Vec::with_capacity(range);
        let mut g2 = Vec::with_capacity(range);
        let mut start = 0usize;

        while g1.len() < range {
            let available = (self.manifest.generated - start).min(self.manifest.chunk_size);
            let path = chunk_path(&self.root, start, available);
            let mut file = File::open(path)?;
            let chunk = read_chunk::<C>(&mut file)?;
            let take = (range - g1.len()).min(chunk.g1.len());
            g1.extend_from_slice(&chunk.g1[..take]);
            g2.extend_from_slice(&chunk.g2[..take]);
            start += available;
        }

        Ok(StoredPowers {
            tau: self.manifest.tau,
            powers: Powers { g1, g2 },
        })
    }
}

impl<C: Pairing> Powers<C> {
    pub fn unsafe_setup_from(
        tau: C::ScalarField,
        start: usize,
        len: usize,
    ) -> Result<Self, PowersCacheError> {
        let start = usize_to_u64(start)?;
        let mut g1 = Vec::with_capacity(len);
        let mut g2 = Vec::with_capacity(len);
        let mut exponent = tau.pow([start]);
        for _ in 0..len {
            g1.push((<C::G1Affine as ark_ec::AffineRepr>::generator() * exponent).into_affine());
            g2.push((<C::G2Affine as ark_ec::AffineRepr>::generator() * exponent).into_affine());
            exponent *= tau;
        }
        Ok(Self { g1, g2 })
    }
}

fn manifest_path(root: &Path) -> PathBuf {
    root.join(MANIFEST_FILE)
}

fn chunk_path(root: &Path, start: usize, len: usize) -> PathBuf {
    root.join(format!("chunk_{start:020}_{len:020}.bin"))
}

fn write_chunk<C: Pairing>(file: &mut File, chunk: &Powers<C>) -> Result<(), PowersCacheError> {
    chunk.serialize_uncompressed(file)?;
    Ok(())
}

fn read_chunk<C: Pairing>(file: &mut File) -> Result<Powers<C>, PowersCacheError> {
    match Powers::<C>::deserialize_uncompressed_unchecked(&mut *file) {
        Ok(chunk) => Ok(chunk),
        Err(_) => {
            file.rewind()?;
            Ok(Powers::<C>::deserialize_compressed_unchecked(file)?)
        }
    }
}

fn read_manifest<C: Pairing>(root: &Path) -> Result<PowersCacheManifest<C>, PowersCacheError> {
    let contents = fs::read_to_string(manifest_path(root))?;
    let mut version = None;
    let mut curve = None;
    let mut chunk_size = None;
    let mut generated = None;
    let mut tau_hex = None;

    for line in contents.lines().filter(|line| !line.trim().is_empty()) {
        let (key, value) = line.split_once('=').ok_or(PowersCacheError::InvalidManifest)?;
        match key {
            "version" => version = Some(value.to_string()),
            "curve" => curve = Some(value.to_string()),
            "chunk_size" => chunk_size = value.parse::<usize>().ok(),
            "generated" => generated = value.parse::<usize>().ok(),
            "tau" => tau_hex = Some(value.to_string()),
            _ => {}
        }
    }

    let version = version.ok_or(PowersCacheError::InvalidManifest)?;
    if version != MANIFEST_VERSION {
        return Err(PowersCacheError::UnsupportedVersion(version));
    }

    let expected_curve = type_name::<C>().to_string();
    let found_curve = curve.ok_or(PowersCacheError::InvalidManifest)?;
    if found_curve != expected_curve {
        return Err(PowersCacheError::CurveMismatch {
            expected: expected_curve,
            found: found_curve,
        });
    }

    let tau_bytes = decode_hex(&tau_hex.ok_or(PowersCacheError::InvalidManifest)?)?;
    let tau = C::ScalarField::deserialize_compressed_unchecked(&*tau_bytes)?;

    Ok(PowersCacheManifest {
        chunk_size: chunk_size.ok_or(PowersCacheError::InvalidManifest)?,
        generated: generated.ok_or(PowersCacheError::InvalidManifest)?,
        tau,
        _curve: PhantomData,
    })
}

fn write_manifest<C: Pairing>(
    root: &Path,
    manifest: &PowersCacheManifest<C>,
) -> Result<(), PowersCacheError> {
    let mut tau_bytes = Vec::new();
    manifest.tau.serialize_compressed(&mut tau_bytes)?;
    let contents = format!(
        "version={}\ncurve={}\nchunk_size={}\ngenerated={}\ntau={}\n",
        MANIFEST_VERSION,
        type_name::<C>(),
        manifest.chunk_size,
        manifest.generated,
        encode_hex(&tau_bytes),
    );
    fs::write(manifest_path(root), contents)?;
    Ok(())
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(nibble_to_hex(byte >> 4));
        out.push(nibble_to_hex(byte & 0x0f));
    }
    out
}

fn decode_hex(value: &str) -> Result<Vec<u8>, PowersCacheError> {
    if value.len() % 2 != 0 {
        return Err(PowersCacheError::InvalidManifest);
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

fn hex_to_nibble(value: u8) -> Result<u8, PowersCacheError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(PowersCacheError::InvalidManifest),
    }
}

fn usize_to_u64(value: usize) -> Result<u64, PowersCacheError> {
    value
        .try_into()
        .map_err(|_| PowersCacheError::RangeTooLarge(value))
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_ec::pairing::Pairing;
    use std::time::{SystemTime, UNIX_EPOCH};

    type Scalar = <Bls12_381 as Pairing>::ScalarField;

    fn temp_cache_dir(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("pfde_kzg_{name}_{suffix}"))
    }

    #[test]
    fn cache_roundtrip_and_resume() {
        let root = temp_cache_dir("powers_cache");
        let tau = Scalar::from(5u64);

        let mut cache = PowersCache::<Bls12_381>::open_or_create(&root, tau, 4).unwrap();
        cache.ensure_range(6).unwrap();

        let stored = cache.load_prefix_with_tau(6).unwrap();
        let expected = Powers::<Bls12_381>::unsafe_setup(tau, 6);
        assert_eq!(stored.tau, tau);
        assert_eq!(stored.powers.g1, expected.g1);
        assert_eq!(stored.powers.g2, expected.g2);

        cache.ensure_range(10).unwrap();
        let stored = cache.load_prefix_with_tau(10).unwrap();
        let expected = Powers::<Bls12_381>::unsafe_setup(tau, 10);
        assert_eq!(stored.tau, tau);
        assert_eq!(stored.powers.g1, expected.g1);
        assert_eq!(stored.powers.g2, expected.g2);
        assert_eq!(cache.manifest().generated, 10);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cache_writes_uncompressed_chunks_and_reads_legacy_compressed_chunks() {
        let root = temp_cache_dir("powers_cache_legacy");
        let tau = Scalar::from(7u64);

        let mut manifest = PowersCacheManifest::<Bls12_381>::new(tau, 4);
        manifest.generated = 6;
        fs::create_dir_all(&root).unwrap();
        write_manifest(&root, &manifest).unwrap();

        let first_chunk = Powers::<Bls12_381>::unsafe_setup_from(tau, 0, 4).unwrap();
        let second_chunk = Powers::<Bls12_381>::unsafe_setup_from(tau, 4, 2).unwrap();

        let mut file = File::create(chunk_path(&root, 0, 4)).unwrap();
        first_chunk.serialize_compressed(&mut file).unwrap();
        let mut file = File::create(chunk_path(&root, 4, 2)).unwrap();
        second_chunk.serialize_compressed(&mut file).unwrap();

        let mut cache = PowersCache::<Bls12_381>::open(&root).unwrap();
        let stored = cache.load_prefix_with_tau(6).unwrap();
        let expected = Powers::<Bls12_381>::unsafe_setup(tau, 6);
        assert_eq!(stored.tau, tau);
        assert_eq!(stored.powers.g1, expected.g1);
        assert_eq!(stored.powers.g2, expected.g2);

        cache.ensure_range(10).unwrap();

        let mut file = File::open(chunk_path(&root, 4, 4)).unwrap();
        let rewritten_chunk = Powers::<Bls12_381>::deserialize_uncompressed_unchecked(&mut file)
            .expect("rewritten chunk should be uncompressed");
        let expected_chunk = Powers::<Bls12_381>::unsafe_setup_from(tau, 4, 4).unwrap();
        assert_eq!(rewritten_chunk.g1, expected_chunk.g1);
        assert_eq!(rewritten_chunk.g2, expected_chunk.g2);

        let stored = cache.load_prefix_with_tau(10).unwrap();
        let expected = Powers::<Bls12_381>::unsafe_setup(tau, 10);
        assert_eq!(stored.tau, tau);
        assert_eq!(stored.powers.g1, expected.g1);
        assert_eq!(stored.powers.g2, expected.g2);

        fs::remove_dir_all(root).unwrap();
    }
}
