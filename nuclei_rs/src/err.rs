use std::fmt;
#[derive(Debug, Clone, PartialEq)]
pub enum BuildRequestError {
    Other(String),
}

impl fmt::Display for BuildRequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                BuildRequestError::Other(err) => format!("Other/{}", err),
            }
        )
    }
}

impl std::convert::From<std::io::Error> for BuildRequestError {
    fn from(err: std::io::Error) -> Self {
        BuildRequestError::Other(err.to_string())
    }
}

impl From<tera::Error> for BuildRequestError {
    fn from(err: tera::Error) -> Self {
        BuildRequestError::Other(err.to_string())
    }
}

impl From<url::ParseError> for BuildRequestError {
    fn from(err: url::ParseError) -> Self {
        BuildRequestError::Other(err.to_string())
    }
}

impl From<&dyn std::error::Error> for BuildRequestError {
    fn from(err: &dyn std::error::Error) -> Self {
        BuildRequestError::Other(err.to_string())
    }
}