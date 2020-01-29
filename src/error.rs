use std::{
    error::Error as ErrorTrait,
    fmt,
};

pub type Error = Box<dyn std::error::Error>;

#[derive(Debug)]
pub enum SignatureError {
    RevocationTokenMatch,
    ProofVerificationFailed,
}

impl ErrorTrait for SignatureError {
    fn source(self: &Self) -> Option<&(dyn ErrorTrait + 'static)> {
        match self {
            _ => None,
        }
    }
}

impl fmt::Display for SignatureError {
    fn fmt(self: &Self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignatureError::RevocationTokenMatch => write!(f, "matched with revocation token"),
            SignatureError::ProofVerificationFailed => write!(f, "proof verification failed"),
        }
    }
}
