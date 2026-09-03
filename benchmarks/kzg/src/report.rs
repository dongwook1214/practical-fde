//! CSV reporting.

use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::time::Duration;

pub const HEADER: &str = "scheme,curve,log_ell,ell,R,lambda,beta,m,code_len,\
srs_load_ms,encode_ms,commit_ms,encrypt_ms,sample_ms,subset_ms,sample_crypto_ms,kzg_proof_ms,\
prove_total_ms,verify_ms,measured_payload,extrapolated,verified,spread_pct";

#[derive(Clone, Debug, Default)]
pub struct Row {
    pub scheme: String,
    pub curve: String,
    pub log_ell: u32,
    pub ell: usize,
    pub r: usize,
    pub lambda: usize,
    pub beta: f64,
    pub m: usize,
    pub code_len: usize,
    pub srs_load_ms: f64,
    pub encode_ms: f64,
    pub commit_ms: f64,
    pub encrypt_ms: f64,
    pub sample_ms: f64,
    pub subset_ms: f64,
    pub sample_crypto_ms: f64,
    pub kzg_proof_ms: f64,
    pub verify_ms: Option<f64>,
    /// How many payload symbols the linear stages were actually run on.
    pub measured_payload: usize,
    pub extrapolated: bool,
    pub verified: bool,
    /// How much of `prove_total_ms` is measurement spread: the absolute spreads
    /// of the repeated stages, summed, as a percentage of the total.  Zero when
    /// nothing could be repeated.
    pub spread_pct: f64,
}

impl Row {
    pub fn prove_total_ms(&self) -> f64 {
        self.encode_ms
            + self.commit_ms
            + self.encrypt_ms
            + self.sample_ms
            + self.subset_ms
            + self.sample_crypto_ms
            + self.kzg_proof_ms
    }

    fn to_csv(&self) -> String {
        format!(
            "{},{},{},{},{},{},{:.6},{},{},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3},{},{},{},{},{:.2}",
            self.scheme,
            self.curve,
            self.log_ell,
            self.ell,
            self.r,
            self.lambda,
            self.beta,
            self.m,
            self.code_len,
            self.srs_load_ms,
            self.encode_ms,
            self.commit_ms,
            self.encrypt_ms,
            self.sample_ms,
            self.subset_ms,
            self.sample_crypto_ms,
            self.kzg_proof_ms,
            self.prove_total_ms(),
            self.verify_ms
                .map(|value| format!("{value:.3}"))
                .unwrap_or_default(),
            self.measured_payload,
            self.extrapolated,
            self.verified,
            self.spread_pct,
        )
    }
}

pub fn ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000.0
}

/// Open the CSV, writing the header if the file is new.
pub struct Writer {
    inner: BufWriter<File>,
}

impl Writer {
    pub fn create(path: &Path) -> std::io::Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = File::create(path)?;
        let mut inner = BufWriter::new(file);
        writeln!(inner, "{HEADER}")?;
        inner.flush()?;
        Ok(Self { inner })
    }

    pub fn push(&mut self, row: &Row) -> std::io::Result<()> {
        writeln!(self.inner, "{}", row.to_csv())?;
        self.inner.flush()
    }
}
