mod components;
mod error;

use std::str::FromStr;
use components::claims::JwtClaims;
use components::key::PRIVATE_KEY;
use error::EnumError;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation, Algorithm};


fn jwt_encode(algorithm: &str, claims: JwtClaims) -> Result<String, EnumError> {

    let private_key= PRIVATE_KEY.get();

    if private_key.is_none() {
        Err(EnumError::KeyError("Private key is not set".to_string()))?
    }

    let algorithm = match Algorithm::from_str(algorithm){
        Ok(alg) => alg,
        Err(err) => Err(EnumError::AlgorithmError(format!("Invalid algorithm: {}", err)))?
    };
    
    let encode = encode(
        &Header::new(algorithm), 
        &claims, 
        &EncodingKey::from_secret(private_key.unwrap())
    );

    match encode {
        Ok(token) => Ok(token),
        Err(err) => Err(EnumError::EncodeError(format!("Error encoding token: {}", err.to_string())))?
    }
}

fn jwt_decode(algorithm: &str, token: String) -> Result<JwtClaims, EnumError> {

    let private_key= PRIVATE_KEY.get();

    if private_key.is_none() {
        Err(EnumError::KeyError("Private key is not set".to_string()))?
    }

    let algorithm = match Algorithm::from_str(algorithm) {
        Ok(alg) => alg,
        Err(err) => Err(EnumError::AlgorithmError(format!("Invalid algorithm: {}", err)))?
        
    };

    let decode = decode(
        &token, 
        &DecodingKey::from_secret(private_key.unwrap()), 
        &Validation::new(algorithm)
    );

    match decode {
        Ok(claims) => Ok(claims.claims),
        Err(err) => Err(EnumError::DecodeError(format!("Error decoding token: {}", err.to_string())))?
        
    }
}

#[cfg(test)]
mod tests_lib {

    use super::*;
    use std::{collections::HashMap, time::{SystemTime, UNIX_EPOCH}};
    use components::key::{JwtPath, Jwtkey};

    fn exp_timestamp() -> usize {
        SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() as usize + 600
    }

    fn inf() -> Option<HashMap<String, String>> {
        let mut my_map: HashMap<String, String> = HashMap::new();
        my_map.insert("uuid".to_string(), "123123-123123-123123-123123".to_string());
        my_map.insert("email".to_string(), "email_test@email_test.com".to_string());
        Some(my_map)
    }

    fn get_key_path() -> &'static str {
        concat!(env!("CARGO_MANIFEST_DIR"), "/keys/private_key.pem")
    }

    fn generate_jwt_encode() -> String {
        let exp = exp_timestamp();

        let inf = inf();

        let key_path = get_key_path();

        let algorithm = Algorithm::from_str("HS256");

        if algorithm.is_err() {
            panic!("error: {}", algorithm.err().unwrap());
        }

        let claims = JwtClaims::new(None, exp, None, None, None, None, inf);
        
        if claims.is_err() {
            panic!("error: {}", claims.err().unwrap());
        }
        
        let private_key_path = JwtPath::set_private_key_path(key_path);
        
        if private_key_path.is_err() {
            panic!("error: {}", private_key_path.err().unwrap());
        }
        
        let private_key = Jwtkey::set_private_key();

        if private_key.is_err() {
            panic!("error: {}", private_key.err().unwrap());
        }

        let token = jwt_encode("HS256", claims.unwrap());
        
        if token.is_err() {
            panic!("error: {}", token.err().unwrap());
        }

        token.unwrap()  
    }

    #[test]
    fn jwt_encode_test() {

        let exp = exp_timestamp();

        let inf = inf();

        let key_path = get_key_path();

        let algorithm = Algorithm::from_str("HS256");

        if algorithm.is_err() {
            panic!("error: {}", algorithm.err().unwrap());
        }

        let claims = JwtClaims::new(None, exp, None, None, None, None, inf);
        
        if claims.is_err() {
            panic!("error: {}", claims.err().unwrap());
        }
        
        let private_key_path = JwtPath::set_private_key_path(key_path);
        
        if private_key_path.is_err() {
            panic!("error: {}", private_key_path.err().unwrap());
        }
        
        let private_key = Jwtkey::set_private_key();

        if private_key.is_err() {
            panic!("error: {}", private_key.err().unwrap());
        }

        let token = jwt_encode("HS256", claims.unwrap());
        
        if token.is_err() {
            panic!("error: {}", token.err().unwrap());
        }

        println!("token: {}", token.unwrap());  
    }

    #[test]
    fn jwt_decode_test() {
        
        let token = generate_jwt_encode();

        let decoded = jwt_decode("HS256", token);

        if decoded.is_err() {
            panic!("error: {}", decoded.err().unwrap());
        }

        println!("decoded: {:#?}", decoded.unwrap());

    }

}   
