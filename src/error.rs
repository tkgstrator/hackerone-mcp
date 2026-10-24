use std::fmt;

#[derive(Debug)]
pub enum Error {
    Config(String),
    Http(String),
    Draft(String),
    Validation(String),
    Busy,
}

pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(m) => write!(f, "configuration error: {m}"),
            Self::Http(m) => write!(f, "HackerOne request failed: {m}"),
            Self::Draft(m) => write!(f, "draft error: {m}"),
            Self::Validation(m) => write!(f, "invalid input: {m}"),
            Self::Busy => write!(f, "another operation is in progress, retry shortly"),
        }
    }
}

impl std::error::Error for Error {}

impl From<Error> for rmcp::ErrorData {
    fn from(e: Error) -> Self {
        match e {
            Error::Validation(_) => rmcp::ErrorData::invalid_params(e.to_string(), None),
            _ => rmcp::ErrorData::internal_error(e.to_string(), None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_variants() {
        assert!(Error::Busy.to_string().contains("in progress"));
        assert!(Error::Validation("x".into()).to_string().contains("x"));
    }

    #[test]
    fn validation_maps_to_invalid_params() {
        let d: rmcp::ErrorData = Error::Validation("bad".into()).into();
        assert_eq!(d.code, rmcp::model::ErrorCode::INVALID_PARAMS);
        let d: rmcp::ErrorData = Error::Draft("bad".into()).into();
        assert_eq!(d.code, rmcp::model::ErrorCode::INTERNAL_ERROR);
    }
}
