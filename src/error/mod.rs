use core::fmt;
use std::error::Error;


#[derive(Debug, PartialEq)]
pub enum AuthError {
    ClaimsValidateExp,
    ClaimsValidateNbf,
    ClaimsValidateIat,
    KeyInvalidExtension,
    FileError(String),
    KeyError(String),
    PathError(String),
    EncodeError(String),
    DecodeError(String),
    AlgorithmError(String),
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {

        match self {
            AuthError::ClaimsValidateExp => write!(f, "Expiration time (exp) must be in the future"),
            AuthError::ClaimsValidateNbf => write!(f, "The time 'not before' (nbf) cannot be in the future"),
            AuthError::ClaimsValidateIat => write!(f, "The time of issuance (iat) cannot be in the future"),
            AuthError::KeyInvalidExtension => write!(f, "File does not have .pem extension"),
            AuthError::FileError(err) => write!(f, "Error file: {}", err),
            AuthError::KeyError(err) => write!(f, "{}", err),
            AuthError::PathError(err) => write!(f, "{}", err),
            AuthError::EncodeError(err) => write!(f, "{}", err),
            AuthError::DecodeError(err) => write!(f, "{}", err),
            AuthError::AlgorithmError(err) => write!(f, "{}", err),
        }
    }
}

impl Error for AuthError {

}

