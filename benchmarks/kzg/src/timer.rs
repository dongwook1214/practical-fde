//! Repeated measurement.
//!
//! Stages in this harness span five orders of magnitude: the sampled subset
//! opening is milliseconds, the whole-codeword ElGamal is minutes.  Repeating
//! everything a fixed number of times is either useless (too few samples where
//! it matters) or ruinous (many repeats of a stage that already takes minutes).
//!
//! So a stage runs until it has `repeat` samples *or* it has spent `budget`,
//! whichever comes first, and always at least once.  Cheap stages get the full
//! count; expensive ones self-limit to a single run, which is fine because their
//! relative noise is small — a stage that takes seconds averages over its own
//! scheduling jitter, a stage that takes 6 ms does not.
//!
//! The reported figure is the median.  Each stage also reports how far its
//! samples spread in absolute terms; summing those and dividing by the row total
//! bounds how much the row's total could have moved, which is what a reader
//! actually wants to know.  A relative spread would instead be dominated by the
//! stages too cheap to matter — sampling `R` indices takes 20 microseconds and
//! varies by 200%, and contributes nothing.

use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub repeat: usize,
    pub budget: Duration,
}

impl Limits {
    pub fn new(repeat: usize, budget_ms: u64) -> Self {
        Self {
            repeat: repeat.max(1),
            budget: Duration::from_millis(budget_ms),
        }
    }

    /// A single run, for stages that are measured once by construction.
    pub fn once() -> Self {
        Self {
            repeat: 1,
            budget: Duration::ZERO,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Sample {
    pub median: Duration,
    /// `max - min` over the samples.  Zero for a single run.
    pub spread: Duration,
    pub runs: usize,
}

impl Sample {
    pub fn ms(&self) -> f64 {
        self.median.as_secs_f64() * 1_000.0
    }

    /// Absolute spread in milliseconds.
    pub fn spread_ms(&self) -> f64 {
        self.spread.as_secs_f64() * 1_000.0
    }
}

/// Run `f` up to `limits.repeat` times or until `limits.budget` is spent,
/// returning the value from the last run alongside the timing statistics.
pub fn measure<T>(limits: Limits, mut f: impl FnMut() -> T) -> (T, Sample) {
    let mut durations: Vec<Duration> = Vec::with_capacity(limits.repeat);
    let mut spent = Duration::ZERO;
    let mut value = None;

    while durations.len() < limits.repeat {
        let started = Instant::now();
        let produced = f();
        let elapsed = started.elapsed();
        durations.push(elapsed);
        spent += elapsed;
        value = Some(produced);
        if spent >= limits.budget {
            break;
        }
    }

    durations.sort_unstable();
    let median = durations[durations.len() / 2];
    let spread = durations[durations.len() - 1] - durations[0];

    (
        value.expect("measure runs at least once"),
        Sample {
            median,
            spread,
            runs: durations.len(),
        },
    )
}

/// Wrap an already-taken duration so it can share the `Sample` plumbing.
pub fn single(duration: Duration) -> Sample {
    Sample {
        median: duration,
        spread: Duration::ZERO,
        runs: 1,
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn respects_the_repeat_count() {
        let mut calls = 0;
        let (_, sample) = measure(Limits::new(5, 60_000), || calls += 1);
        assert_eq!(calls, 5);
        assert_eq!(sample.runs, 5);
    }

    #[test]
    fn a_zero_budget_still_runs_once() {
        let mut calls = 0;
        let (_, sample) = measure(Limits::once(), || calls += 1);
        assert_eq!(calls, 1);
        assert_eq!(sample.runs, 1);
        assert_eq!(sample.spread, Duration::ZERO);
    }

    #[test]
    fn the_budget_stops_an_expensive_stage_after_one_run() {
        let mut calls = 0;
        let (_, sample) = measure(Limits::new(100, 1), || {
            calls += 1;
            std::thread::sleep(Duration::from_millis(5));
        });
        assert_eq!(calls, 1, "a stage over budget must not repeat");
        assert_eq!(sample.runs, 1);
    }

    #[test]
    fn reports_the_median_and_spread() {
        let mut lengths = [1u64, 30, 2].into_iter();
        let (_, sample) = measure(Limits::new(3, 60_000), || {
            std::thread::sleep(Duration::from_millis(lengths.next().unwrap()));
        });
        assert_eq!(sample.runs, 3);
        // Median is the middle sample, not dragged up by the slow one.
        assert!(sample.median.as_millis() < 10, "{:?}", sample.median);
        // The spread must see the slow outlier even though the median does not.
        assert!(sample.spread.as_millis() >= 25, "spread was {:?}", sample.spread);
    }
}
