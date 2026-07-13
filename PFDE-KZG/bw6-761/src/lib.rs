pub mod commit;
pub mod divide;
#[cfg(test)]
mod tests;
pub mod veck;

use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum Error {
    #[error("couldn't generate valid FFT domain of size {0}")]
    InvalidFftDomain(usize),
    #[error("subset polynomial remainder is nonzero")]
    NonZeroSubsetRemainder,
}
