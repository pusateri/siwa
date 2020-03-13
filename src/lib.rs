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
use jsonwebtoken::TokenData;
use jsonwebtoken::{self, decode, decode_header, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str;
use thiserror::Error;

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
    iss: String,
    aud: String,
    exp: i32,
    iat: i32,
    sub: String,
    c_hash: String,
    email: String,
    email_verified: String,
    auth_time: i32,
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

pub async fn validate(
    client_id: String,
    base64_token: String,
    ignore_expire: bool,
) -> Result<TokenData<Claims>, ValidateError> {
    let token = base64::decode(&base64_token)?;
    let header = decode_header(str::from_utf8(&token).unwrap())?;

    let kid = match header.kid {
        Some(k) => k,
        None => return Err(ValidateError::KidNotFound),
    };

    let resp = reqwest::get("https://appleid.apple.com/auth/keys")
        .await?
        .json::<HashMap<String, Vec<KeyComponents>>>()
        .await?;

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
    let token_data = decode::<Claims>(
        str::from_utf8(&token).unwrap(),
        &DecodingKey::from_rsa_components(&pubkey.n, &pubkey.e),
        &val,
    )?;

    if token_data.claims.iss != "https://appleid.apple.com" {
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
        let user_token = "foo";
        let identity_token = "bar";

        let result = validate(user_token.to_string(), identity_token.to_string(), false).await?;
        println!("{:?}", result);
        Ok(())
    }
}
