//! Command line configuration for the end-to-end benchmark.

use std::path::PathBuf;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Scheme {
    /// VECK_EL — Tas et al., "Atomic BlockChain Data Exchange with Fairness".
    /// No coding, no sampling: the whole file is exponential-ElGamal encrypted
    /// and every 32-bit shard carries a range proof.
    Veck,
    /// VECK+_EL — the sampling/coding variant benchmarked in arXiv:2506.14944.
    /// The whole codeword is exponential-ElGamal encrypted; range proofs are
    /// produced only for the R sampled positions.
    VeckPlus,
    /// VECK*_EL — Khabbazian et al., "plaintext-scale" VECK. The codeword is
    /// masked with a symmetric PRF; only the R sampled positions enter the
    /// SNARK, where they are re-encrypted under ElGamal in the KZG group.
    VeckStar,
    /// This work.  The codeword is masked with a Poseidon PRF and the sampled
    /// positions are bound to the commitment by a KZG opening plus a SNARK that
    /// contains no elliptic-curve gadget.
    Ours,
}

impl Scheme {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "veck" => Ok(Self::Veck),
            "veck-plus" | "veck+" => Ok(Self::VeckPlus),
            "veck-star" | "veck*" => Ok(Self::VeckStar),
            "ours" | "pfde" => Ok(Self::Ours),
            other => Err(format!("unknown scheme `{other}`")),
        }
    }

    pub fn tag(self) -> &'static str {
        match self {
            Self::Veck => "veck",
            Self::VeckPlus => "veck-plus",
            Self::VeckStar => "veck-star",
            Self::Ours => "ours",
        }
    }

    /// Whether the scheme applies a Reed--Solomon expansion before encrypting.
    pub fn is_coded(self) -> bool {
        !matches!(self, Self::Veck)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Curve {
    Bls12_381,
    Bw6_761,
}

impl Curve {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "bls12-381" | "bls12_381" => Ok(Self::Bls12_381),
            "bw6-761" | "bw6_761" => Ok(Self::Bw6_761),
            other => Err(format!("unknown curve `{other}`")),
        }
    }

    pub fn tag(self) -> &'static str {
        match self {
            Self::Bls12_381 => "bls12-381",
            Self::Bw6_761 => "bw6-761",
        }
    }

    pub fn cache_tag(self) -> &'static str {
        match self {
            Self::Bls12_381 => "bls12_381",
            Self::Bw6_761 => "bw6_761",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    pub scheme: Scheme,
    pub curve: Curve,
    pub min_log: u32,
    pub max_log: u32,
    pub subset_sizes: Vec<usize>,
    pub lambda: usize,
    /// Grinding budget `q_S = 2^grinding` the redundancy `beta` must survive.
    pub grinding: usize,
    pub out: PathBuf,
    pub srs_dir: PathBuf,
    pub srs_chunk: usize,
    /// Largest file size (as a log2) whose *linear*, full-file stages are
    /// actually executed.  Larger sizes reuse the measured per-element cost.
    /// `None` disables extrapolation entirely.
    pub max_measured_log: Option<u32>,
    /// Run (and assert) the verifier as well.
    pub verify: bool,
    /// How many times to repeat a stage before taking the median.
    pub repeat: usize,
    /// Per-stage time budget; a stage that exceeds it is not repeated.
    pub repeat_budget_ms: u64,
}

impl Config {
    pub fn limits(&self) -> crate::timer::Limits {
        crate::timer::Limits::new(self.repeat, self.repeat_budget_ms)
    }
}

/// Sample counts, chosen so that the redundancy `beta = compute_beta(R, 160)`
/// lands on 1.1, 1.25, 1.5 and 2 -- the sweep is parameterised by how much the
/// codeword expands, which is what the buyer pays for in bandwidth, rather than
/// by `R` itself.
pub const DEFAULT_SUBSET_SIZES: [usize; 4] = [2384, 1053, 609, 386];

/// `beta = 1.1` needs 2384 samples.  Only our scheme is measured there: it is
/// the low-redundancy regime that the per-sample cost of the baselines keeps
/// them out of, which is the point the comparison is making.
pub const OURS_ONLY_SUBSET_SIZES: [usize; 1] = [2384];

const USAGE: &str = "\
usage: pfde-bench [options]

  --scheme <veck|veck-plus|veck-star|ours>   scheme under test        (required)
  --curve  <bls12-381|bw6-761>               pairing curve            (required)
  --min-log <k>                              smallest file size 2^k   (default 10)
  --max-log <k>                              largest  file size 2^k   (default 20)
  --subsets <R,...>                          sample counts            (default 2384,1053,609,386)
  --lambda <bits>                            security parameter       (default 128)
  --grinding <g>                             grinding budget q_S = 2^g (default 32)
  --out <path>                               CSV output               (default results/<scheme>_<curve>.csv)
  --srs-dir <path>                           powers-of-tau cache      (default .cache/srs)
  --srs-chunk <n>                            cache chunk size         (default 65536)
  --max-measured-log <k>                     cap on measured linear stages
                                             (default 14 for veck, 16 for veck-plus, none otherwise)
  --no-extrapolate                           never extrapolate; measure everything
  --no-verify                                skip verification
  --repeat <n>                               samples per stage, median reported (default 5)
  --repeat-budget-ms <ms>                    a stage over this budget is not repeated (default 2000)
";

pub fn usage() -> String {
    USAGE.to_string()
}

pub fn parse_args(args: Vec<String>) -> Result<Config, String> {
    let mut scheme = None;
    let mut curve = None;
    let mut min_log = 10u32;
    let mut max_log = 20u32;
    let mut subset_sizes = DEFAULT_SUBSET_SIZES.to_vec();
    let mut lambda = 128usize;
    let mut grinding = 32usize;
    let mut out: Option<PathBuf> = None;
    let mut srs_dir: Option<PathBuf> = None;
    let mut srs_chunk = 1usize << 16;
    let mut max_measured_log: Option<u32> = None;
    let mut extrapolate = true;
    let mut verify = true;
    let mut repeat = 5usize;
    let mut repeat_budget_ms = 2_000u64;

    let mut i = 0usize;
    while i < args.len() {
        let key = args[i].as_str();
        let mut value = || -> Result<String, String> {
            i += 1;
            args.get(i).cloned().ok_or_else(|| format!("`{key}` needs a value"))
        };
        match key {
            "--scheme" => scheme = Some(Scheme::parse(&value()?)?),
            "--curve" => curve = Some(Curve::parse(&value()?)?),
            "--min-log" => min_log = value()?.parse().map_err(|_| "bad --min-log")?,
            "--max-log" => max_log = value()?.parse().map_err(|_| "bad --max-log")?,
            "--lambda" => lambda = value()?.parse().map_err(|_| "bad --lambda")?,
            "--grinding" => grinding = value()?.parse().map_err(|_| "bad --grinding")?,
            "--out" => out = Some(PathBuf::from(value()?)),
            "--srs-dir" => srs_dir = Some(PathBuf::from(value()?)),
            "--srs-chunk" => srs_chunk = value()?.parse().map_err(|_| "bad --srs-chunk")?,
            "--max-measured-log" => {
                max_measured_log = Some(value()?.parse().map_err(|_| "bad --max-measured-log")?)
            }
            "--subsets" => {
                let raw = value()?;
                subset_sizes = raw
                    .split(',')
                    .map(|part| part.trim().parse::<usize>().map_err(|_| "bad --subsets".to_string()))
                    .collect::<Result<Vec<_>, _>>()?;
            }
            "--no-extrapolate" => extrapolate = false,
            "--repeat" => repeat = value()?.parse().map_err(|_| "bad --repeat")?,
            "--repeat-budget-ms" => {
                repeat_budget_ms = value()?.parse().map_err(|_| "bad --repeat-budget-ms")?
            }
            "--no-verify" => verify = false,
            "-h" | "--help" => return Err(usage()),
            other => return Err(format!("unknown option `{other}`\n\n{USAGE}")),
        }
        i += 1;
    }

    let scheme = scheme.ok_or_else(|| format!("--scheme is required\n\n{USAGE}"))?;
    let curve = curve.ok_or_else(|| format!("--curve is required\n\n{USAGE}"))?;

    if min_log > max_log {
        return Err("--min-log must not exceed --max-log".to_string());
    }
    if subset_sizes.is_empty() {
        return Err("--subsets must list at least one value".to_string());
    }

    // The public-key stages that touch *every* transmitted symbol are exactly
    // linear in the payload length and embarrassingly parallel, but they are far
    // too slow to run at 2^20: base VECK range-proves every 32-bit shard of every
    // file element, and VECK+ ElGamal-encrypts the whole codeword.  By default we
    // measure them on a bounded prefix and scale; `--no-extrapolate` measures
    // everything, at the cost of a multi-day run.
    if max_measured_log.is_none() {
        max_measured_log = match scheme {
            Scheme::Veck => Some(14),
            Scheme::VeckPlus => Some(16),
            _ => None,
        };
    }
    if !extrapolate {
        max_measured_log = None;
    }

    let out = out.unwrap_or_else(|| {
        PathBuf::from("results").join(format!("kzg_{}_{}.csv", scheme.tag(), curve.tag()))
    });
    // Each curve needs its own powers-of-tau cache.
    let srs_dir = srs_dir.unwrap_or_else(|| PathBuf::from(".cache/srs").join(curve.cache_tag()));

    Ok(Config {
        scheme,
        curve,
        min_log,
        max_log,
        subset_sizes,
        lambda,
        grinding,
        out,
        srs_dir,
        srs_chunk,
        max_measured_log,
        verify,
        repeat,
        repeat_budget_ms,
    })
}
