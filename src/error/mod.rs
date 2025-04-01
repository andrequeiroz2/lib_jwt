use core::fmt;
use std::error::Error;


#[derive(Debug, PartialEq)]
pub enum EnumError {
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

impl fmt::Display for EnumError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {

        match self {
            EnumError::ClaimsValidateExp => write!(f, "Expiration time (exp) must be in the future"),
            EnumError::ClaimsValidateNbf => write!(f, "The time 'not before' (nbf) cannot be in the future"),
            EnumError::ClaimsValidateIat => write!(f, "The time of issuance (iat) cannot be in the future"),
            EnumError::KeyInvalidExtension => write!(f, "File does not have .pem extension"),
            EnumError::FileError(err) => write!(f, "Error file: {}", err),
            EnumError::KeyError(err) => write!(f, "{}", err),
            EnumError::PathError(err) => write!(f, "{}", err),
            EnumError::EncodeError(err) => write!(f, "{}", err),
            EnumError::DecodeError(err) => write!(f, "{}", err),
            EnumError::AlgorithmError(err) => write!(f, "{}", err),
        }
    }
}

impl Error for EnumError {
    
}

