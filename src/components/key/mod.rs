use std::fs::OpenOptions;
use std::io::Read;
use std::path::Path;
use std::sync::OnceLock;
use crate::error::EnumError;

pub static PRIVATE_KEY: OnceLock<Vec<u8>> = OnceLock::new();
pub static PUBLIC_KEY: OnceLock<Vec<u8>> = OnceLock::new();

pub static PRIVATE_KEY_PATH: OnceLock<String> = OnceLock::new();
pub static PUBLIC_KEY_PATH: OnceLock<String> = OnceLock::new();

pub struct JwtPath{}

impl JwtPath {
    pub fn set_private_key_path(path: &str) -> Result<(), EnumError> {
        
        let path= PRIVATE_KEY_PATH.set(path.to_string());

        match path {
            Ok(_) => Ok(()),
            Err(err) => Err(EnumError::PathError(format!("Error set private key path: {}", err)))?
        }
    }

    pub fn set_public_key_path(path: &str) -> Result<(), EnumError> {
        
        let path= PUBLIC_KEY_PATH.set(path.to_string());

        match path {
            Ok(_) => Ok(()),
            Err(err) => Err(EnumError::PathError(format!("Error set public key path: {}", err)))?
        }
    }
}

pub struct Jwtkey{}

impl Jwtkey {

    pub fn set_private_key() -> Result<(), EnumError> {

        let path = PRIVATE_KEY_PATH.get();

        let path = match path {
            Some(path) => path,
            None => Err(EnumError::PathError("Private key path is not set".to_string()))?
        };

        match set_path(path){    
            Ok(vec_key) => {

                match PRIVATE_KEY.set(vec_key){
                    Ok(_) => Ok(()),
                    Err(_) => Err(EnumError::KeyError("Private key already initialized".to_string()))?
                }
            },
            
            Err(err) => Err(err)?
        }
    }

    pub fn set_public_key() -> Result<(), EnumError> {

        let path = PUBLIC_KEY_PATH.get();

        let path = match path {
            Some(path) => path,
            None => Err(EnumError::PathError("Public key path is not set".to_string()))?
        };

        match set_path(path){    
            Ok(vec_key) => {

                match PUBLIC_KEY.set(vec_key){
                    Ok(_) => Ok(()),
                    Err(_) => Err(EnumError::KeyError("Public key already initialized".to_string()))?
                }
            },
            
            Err(err) => Err(err)?
        }
    }   
}


fn set_path(path: &str) -> Result<Vec<u8>, EnumError>{
    
    let path = Path::new(path);
    
    if path.extension().and_then(|ext| ext.to_str()) != Some("pem") {
        Err(EnumError::KeyInvalidExtension)?;
    }

    let file = &OpenOptions::new().read(true).open(path);

    let mut file_ok = match file {
        Ok(file) => file,
        Err(err) => Err(EnumError::FileError(err.to_string()))?,
    };
    
    let mut buffer = Vec::new();

    match file_ok.read_to_end(&mut buffer){
        Ok(_) => Ok(buffer),
        Err(err) => Err(EnumError::FileError(err.to_string()))?,
    }
}

#[cfg(test)]
mod jwt_key_tests {
    use std::{
        env, 
        path::PathBuf, 
        fs::File, 
        time::{SystemTime, UNIX_EPOCH},
        io::Write
    };
    use super::*;

    fn create_temp_key_file(content: &[u8]) -> PathBuf {

        let mut temp_path = env::temp_dir();
        
        let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis();
        
        temp_path.push(format!("test_key_{}.pem", timestamp));
        
        let mut file = File::create(&temp_path).expect("Failed to create temp key file");
    
        file.write_all(content).expect("Failed to write to temp key file");
        
        temp_path
    }

    #[test]
    fn private_key_path_success(){

        let _ = JwtPath::set_private_key_path("./keys/public_key.pem");

        let private_key_path = PRIVATE_KEY_PATH.get().unwrap();
        
        assert_eq!("./keys/private_key.pem", private_key_path);
    }
    
    #[test]
    fn public_key_path_success(){
        
        let _ = JwtPath::set_public_key_path("./keys/public_key.pem");
        
        let public_key_path = PUBLIC_KEY_PATH.get().unwrap();
        
        assert_eq!("./keys/public_key.pem", public_key_path);
    }

    #[test]
    fn private_key_path_error() {

        let private_key_path = JwtPath::set_private_key_path("./keys/private_key.pem");

        let set_private_key_other_path=  JwtPath::set_private_key_path("./keys/public_key.pem");

        assert_eq!(set_private_key_other_path.is_err(), true);      
    }

    #[test]
    fn public_key_path_error() {

        let _ = JwtPath::set_public_key_path("./keys/public_key.pem");

        let set_public_key_other_path=  JwtPath::set_public_key_path("./keys/private_key.pem");

        assert_eq!(set_public_key_other_path.is_err(), true);
    }
}