use thiserror::Error;

/// Errors that can occur when operating with a key share proof
#[derive(Error, Debug)]
pub enum KeyShareProofError {
    /// A general purpose error message
    #[error("an error occurred: '{0}'")]
    General(String),
}

/// Result type for key share proof operations
pub type KeyShareProofResult<T> = Result<T, KeyShareProofError>;
