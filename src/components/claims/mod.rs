use std::collections::HashMap;
use serde::{Serialize, Deserialize};

use crate::error::EnumError;


#[derive(Debug, Serialize, Deserialize)]
pub struct JwtClaims{
    #[serde(skip_serializing_if = "Option::is_none")]
    aud: Option<String>,
    exp: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    iat: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nbf: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    inf: Option<HashMap<String, String>>
}

impl JwtClaims {
    pub fn new( 
        aud: Option<String>,
        exp: usize,
        iat: Option<usize>,
        iss: Option<String>,
        nbf: Option<usize>,
        sub: Option<String>,
        inf: Option<HashMap<String, String>>
    ) -> Result<Self, EnumError> {
        
        let claims = JwtClaims{aud, exp, iat, iss, nbf, sub, inf};

        claims.validate()?;
        
        Ok(claims)

    }

    fn validate(&self) -> Result<(), EnumError>{
        
        let now = jsonwebtoken::get_current_timestamp() as usize;

        if self.exp <= now {
            Err(EnumError::ClaimsValidateExp)?;
        }

        if let Some(nbf) = self.nbf {
            if nbf > now {
                return Err(EnumError::ClaimsValidateNbf)?;
            }
        }

        if let Some(iat) = self.iat {
            if iat > now {
                return Err(EnumError::ClaimsValidateIat)?;
            }
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod jwt_claims_tests {

    use super::*;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    fn now_timestamp() -> Duration {
        SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
    }

    fn exp_timestamp() -> usize {
        SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() as usize + 20
    }

    fn inf_test() -> Option<HashMap<String, String>> {
        let mut my_map: HashMap<String, String> = HashMap::new();
        my_map.insert("uuid".to_string(), "123123-123123-123123-123123".to_string());
        my_map.insert("email".to_string(), "email_test@email_test.com".to_string());
        Some(my_map)
    }

    fn inf_error_test() -> Option<HashMap<String, String>> {
        let mut my_map: HashMap<String, String> = HashMap::new();
        my_map.insert("uuid".to_string(), "123123-123123-123123-12312".to_string());
        my_map.insert("email".to_string(), "email_test_error@email_test.com".to_string());
        Some(my_map)
    }


    #[test]
    fn validate_exp_success() {
    
        let exp = exp_timestamp();

        let claims = JwtClaims::new(None, exp, None, None, None, None, None);

        match claims {
            Ok(claims) => assert_eq!(claims.exp, exp),
            Err(err) => panic!("error: {}", err)
        }
    }

    #[test]
    fn validate_exp_error() {
        
        let now = now_timestamp();

        let exp = now.as_secs() as usize;
        
        let claims = JwtClaims::new(None, exp, None, None, None, None, None);

        match claims {
            Ok(claims) => panic!("error: {:?}", claims),
            Err(err) => assert_eq!(err.to_string(), "Expiration time (exp) must be in the future")}
        
    }

    #[test]
    fn validate_nbf_success() {
        
        let now = now_timestamp();

        let nbf = Some(now.as_secs() as usize);

        let claims = JwtClaims::new(None, exp_timestamp(), None, None, nbf, None, None);

        match claims {
            Ok(claims) => assert_eq!(claims.nbf, nbf),
            Err(err) => panic!("error: {}", err)
        }
    }

    #[test]
    fn validate_nbf_error() {
        
        let now = now_timestamp();

        let nbf = Some(now.as_secs() as usize + 20);

        let claims = JwtClaims::new(None, exp_timestamp(), None, None, nbf, None, None);

        match claims {
            Ok(claims) => panic!("error: {:?}", claims),
            Err(err) => {
                println!("{err}");
                assert_eq!(err.to_string(), "The time 'not before' (nbf) cannot be in the future")
            }
        }
    }

    #[test]
    fn validate_iat_success() {
        
        let now = now_timestamp();

        let iat = Some(now.as_secs() as usize);

        let claims = JwtClaims::new(None, exp_timestamp(), iat, None, None, None, None);

        match claims {
            Ok(claims) => assert_eq!(claims.iat, iat),
            Err(err) => panic!("error: {}", err)
        }
    }

    #[test]
    fn validate_iat_error() {
        
        let now = now_timestamp();

        let iat = Some(now.as_secs() as usize + 20);

        let claims = JwtClaims::new(None, exp_timestamp(), iat, None, None, None, None);

        match claims {
            Ok(claims) => panic!("error: {:?}", claims),
            Err(err) => assert_eq!(err.to_string(), "The time of issuance (iat) cannot be in the future")
        }
    }

    #[test]
    fn validate_inf_success() {
        
        let inf = inf_test();

        let inf_clone = inf.clone();

        let claims = JwtClaims::new(None, exp_timestamp(), None, None, None, None, inf);

        match claims {
            Ok(claims) => assert_eq!(claims.inf, inf_clone),
            Err(err) => panic!("error: {}", err)
        }
    }

    #[test]
    fn validate_inf_error() {

        let inf_error = inf_error_test();

        let inf = inf_test();

        let claims = JwtClaims::new(None, exp_timestamp(), None, None, None, None, inf);

        assert_ne!(claims.unwrap().inf, Some(inf_error).unwrap())
    }
}