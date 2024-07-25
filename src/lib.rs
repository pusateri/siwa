//! # Backend for Sign In With Apple
//!
//! Provides verification of identityToken from Apple's docs at:
//!	[https://developer.apple.com/documentation/signinwithapplerestapi/verifying_a_user]()
//!
//! To verify the identity token, your app server must:
//!
//! 1. Fetch Apple’s public key to verify the ID token signature.
//!
//! 	[https://appleid.apple.com/auth/keys]()
//!
//! 2. Verify the `JWS E256` signature using the server’s public key
//!
//! 3. Verify the nonce for the authentication
//!
//! 4. Verify that the `iss` field contains [https://appleid.apple.com]()
//!
//! 5. Verify that the `aud` field is the developer’s client_id
//!
//! 6. Verify that the time is earlier than the `exp` value of the token

use base64;
use jsonwebtoken::{self, decode, decode_header, DecodingKey, TokenData, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str;
use thiserror::Error;

const APPLE_PUB_KEYS: &'static str = "https://appleid.apple.com/auth/keys";
const APPLE_ISSUER: &'static str = "https://appleid.apple.com";

#[derive(Debug, Serialize, Deserialize)]
struct KeyComponents {
    kty: String,   // "RSA"
    kid: String,   // "eXaunmL"
    r#use: String, // "sig"
    alg: String,   // "RS256"
    n: String,     // "4dGQ7bQK8LgILOdL..."
    e: String,     // "AQAB"
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub aud: String,
    pub exp: i32,
    pub iat: i32,
    pub sub: String,
    pub c_hash: String,
    pub email: String,
    pub email_verified: bool,
    pub auth_time: i32,
    pub nonce_supported: bool,
}

#[derive(Error, Debug)]
pub enum ValidateError {
    #[error("Header algorithm unspecified")]
    HeaderAlgorithmUnspecified,
    #[error("Key ID not found")]
    KidNotFound,
    #[error("Key not found")]
    KeyNotFound,
    #[error("Iss claim mismatch")]
    IssClaimMismatch,
    #[error("Client ID mismatch")]
    ClientIdMismatch,
    #[error(transparent)]
    Base64(#[from] base64::DecodeError),
    #[error(transparent)]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
}

pub async fn validate(client_id: String, base64_token: String, audience: String, ignore_expire: bool) -> Result<TokenData<Claims>, ValidateError> {
    let token = base64::decode(&base64_token)?;
    let header = decode_header(str::from_utf8(&token).unwrap())?;

    let kid = match header.kid {
        Some(k) => k,
        None => return Err(ValidateError::KidNotFound),
    };

    let resp = reqwest::get(APPLE_PUB_KEYS).await?.json::<HashMap<String, Vec<KeyComponents>>>().await?;

    let mut pubkeys: HashMap<String, &KeyComponents> = HashMap::new();
    for (_i, val) in resp["keys"].iter().enumerate() {
        pubkeys.insert(val.kid.clone(), val);
    }

    let pubkey = match pubkeys.get(&kid) {
        Some(key) => key,
        None => return Err(ValidateError::KeyNotFound),
    };

    let mut val = Validation::new(header.alg);
    val.validate_exp = !ignore_expire;
    val.set_audience(&[audience]);

    let token_data = decode::<Claims>(
        str::from_utf8(&token).unwrap(),
        &DecodingKey::from_rsa_components(&pubkey.n, &pubkey.e).to_owned().unwrap(),
        &val,
    )?;

    if token_data.claims.iss != APPLE_ISSUER {
        return Err(ValidateError::IssClaimMismatch);
    }

    if token_data.claims.sub != client_id {
        return Err(ValidateError::ClientIdMismatch);
    }

    Ok(token_data)
}

#[cfg(test)]
mod tests {
    use crate::{validate, ValidateError};

    #[tokio::test]
    async fn validate_test() -> std::result::Result<(), ValidateError> {
        let user_token = "000904.f905e012081a4e139bbc0ffaed13caaf.1851";
        let identity_token = "ZXlKcmFXUWlPaUp3WjJkdVVXVk9RMDlWSWl3aVlXeG5Jam9pVWxNeU5UWWlmUS5leUpwYzNNaU9pSm9kSFJ3Y3pvdkwyRndjR3hsYVdRdVlYQndiR1V1WTI5dElpd2lZWFZrSWpvaVkyOXRMbVY0WVcxd2JHVXVZWEJ3YkdVdGMyRnRjR3hsWTI5a1pTNXFkV2xqWlNJc0ltVjRjQ0k2TVRjeU1qQXhPVGcyTlN3aWFXRjBJam94TnpJeE9UTXpORFkxTENKemRXSWlPaUl3TURBNU1EUXVaamt3TldVd01USXdPREZoTkdVeE16bGlZbU13Wm1aaFpXUXhNMk5oWVdZdU1UZzFNU0lzSW1OZmFHRnphQ0k2SW1KNFdraGpObTEyWjFCRlQweDFVMVZVVVRNMmNXY2lMQ0psYldGcGJDSTZJbkJ5WkRaMk5qWmpOM0ZBY0hKcGRtRjBaWEpsYkdGNUxtRndjR3hsYVdRdVkyOXRJaXdpWlcxaGFXeGZkbVZ5YVdacFpXUWlPblJ5ZFdVc0ltRjFkR2hmZEdsdFpTSTZNVGN5TVRrek16UTJOU3dpYm05dVkyVmZjM1Z3Y0c5eWRHVmtJanAwY25WbExDSnlaV0ZzWDNWelpYSmZjM1JoZEhWeklqb3hmUS5KTmEzRGVpUTZCYnFMXzRVa2daVldfMzJINVVoc0djQTk4UEZDSVV5SVdBbXZhRXlFWWREa3FuZS0xRm1GWWg2dFdZOUNta1RKYkZqcmRPMElkUFlROUJZdVNqdGxCYzV5VE4xVjlzR3A0NzYwR1dCcE5mRW50S1ZoUmx0OXh0LWZZV0lnNE05QmtBZXZBRkxPZ2NlOG43QndpRFlFeGx6WUxVamY0VmJ5R1hQRFlSMk0zbko5X2M4S19oc1FhV1Z3OWM2dGlPbUQyR0owaEJkOGl2a09IZjZwSzZMOFI3VmF5TWZyMGFYTUZpQkduTXN3WWpxT3UwVmgtcjJMblRUUlBzZDFYOE50cGpQb0kwWDBJeC1hZldNY092TzNlc1RTNVRoZF9Ba1I5M1c1eFlRTnFRSUFua1owekNNUDA4VWw5eV9wMTE4VnhYNVFhenlETThjcWc=";

        let result = validate(
            user_token.to_string(),
            identity_token.to_string(),
            "com.example.apple-samplecode.juice".to_string(),
            true,
        )
        .await?;

        println!("{:?}", result);
        Ok(())
    }
}
