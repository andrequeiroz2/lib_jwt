
mod components;
mod error;

use components::claims::JwtClaims;
use components::key::{JwtPath, Jwtkey, PRIVATE_KEY};
use error::EnumError;
use jsonwebtoken::{decode, encode, EncodingKey, Header};

use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
    
fn exp_timestamp() -> usize {
    SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .expect("Time went backwards")
    .as_secs() as usize +20
}

// fn jwt_encode(algorithm: JwtAlgorithm, claims: JwtClaims) -> Result<String, EnumError> {

//     let private_key= PRIVATE_KEY.get();

//     if private_key.is_none() {
//         Err(EnumError::KeyError("Private key is not set".to_string()))?
//     }

//     let encode = encode(&Header::from(algorithm.to_header()), &claims, &EncodingKey::from_secret(private_key.unwrap()));

//     match encode {
//         Ok(token) => Ok(token),
//         Err(err) => Err(EnumError::EncodeError(format!("Error encoding token: {}", err.to_string())))?
//     }
// }


fn main() {
    // let exp = exp_timestamp();

    // let algorithm = JwtAlgorithm::from_str("HS256");

    // if algorithm.is_err() {
    //     panic!("error: {}", algorithm.err().unwrap());
    // }

    // let claims = JwtClaims::new(None, exp, None, None, None, None);
    
    // if claims.is_err() {
    //     panic!("error: {}", claims.err().unwrap());
    // }
    
    // let private_key_path = JwtPath::set_private_key_path("keys/private_key.pem");
    
    // if private_key_path.is_err() {
    //     panic!("error: {}", private_key_path.err().unwrap());
    // }
    
    // let private_key = Jwtkey::set_private_key();

    // if private_key.is_err() {
    //     panic!("error: {}", private_key.err().unwrap());
    // }

    // let token = jwt_encode(algorithm.unwrap(), claims.unwrap());
    
    // if token.is_err() {
    //     panic!("error: {}", token.err().unwrap());
    // }

    // println!("token: {}", token.unwrap());
}