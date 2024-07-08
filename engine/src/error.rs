//! engine error
use std::io::ErrorKind;
use std::num::ParseIntError;
use thiserror::Error as ThisError;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(ThisError, Debug)]
pub enum Error {
  #[error(transparent)]
  IO(#[from] std::io::Error),
  #[error(transparent)]
  Http(slinger::Error),
  #[error(transparent)]
  IntError(#[from] ParseIntError),
}

impl From<slinger::Error> for Error {
  fn from(value: slinger::Error) -> Self {
    Error::Http(value)
  }
}

pub(crate) fn new_regex_error<T: std::error::Error + Send + Sync + 'static>(msg: T) -> Error {
  Error::IO(std::io::Error::new(ErrorKind::InvalidInput, msg))
}

impl From<slinger::http::header::InvalidHeaderValue> for Error {
  fn from(value: slinger::http::header::InvalidHeaderValue) -> Self {
    Error::Http(slinger::Error::from(value))
  }
}
