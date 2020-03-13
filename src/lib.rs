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

    let resp = reqwest::get(APPLE_PUB_KEYS)
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
        let user_token = "001888.0aa25f01cd2e49bbb529647575ef6ff9.1820";
        let identity_token = "ZXlKcmFXUWlPaUpsV0dGMWJtMU1JaXdpWVd4bklqb2lVbE15TlRZaWZRLmV5SnBjM01pT2lKb2RIUndjem92TDJGd2NHeGxhV1F1WVhCd2JHVXVZMjl0SWl3aVlYVmtJam9pYjNKbkxtaHZjR1Z5WldsdWN5NVNaV2x1Y3lJc0ltVjRjQ0k2TVRVNE5ERTBNamsxTUN3aWFXRjBJam94TlRnME1UUXlNelV3TENKemRXSWlPaUl3TURFNE9EZ3VNR0ZoTWpWbU1ERmpaREpsTkRsaVltSTFNamsyTkRjMU56VmxaalptWmprdU1UZ3lNQ0lzSW1OZmFHRnphQ0k2SWtkSmJUQllibEozYlhsT1lsZDBaMDltWjBoT05VRWlMQ0psYldGcGJDSTZJakptWkRNMk5YSmxiVGRBY0hKcGRtRjBaWEpsYkdGNUxtRndjR3hsYVdRdVkyOXRJaXdpWlcxaGFXeGZkbVZ5YVdacFpXUWlPaUowY25WbElpd2lhWE5mY0hKcGRtRjBaVjlsYldGcGJDSTZJblJ5ZFdVaUxDSmhkWFJvWDNScGJXVWlPakUxT0RReE5ESXpOVEFzSW01dmJtTmxYM04xY0hCdmNuUmxaQ0k2ZEhKMVpYMC5JbmJ4VUdJSjhSZU1kNDlXZ2RPcHZZWnlSaUZVdklCR3V1TmtKamd6RDI4V3h5MnE2a2thZUVobFF3T2V6dkcxNHpOWlRtSllzcjdkUk1JSkFHdWFOMXBsOTY4M3RDcUFraHZyek04REdaX0JaYzktUEt5cWFvNVUzeklyeUFidGdnWXFPWHFFVjZ0U0hhTFZQM2xSSjdoRzZWYjhsMkl2cGU2MlNJNWxZVkFVMWhlWUx1RWI0THBPa1RjRjVUMGNRWXNZNVFhMG1xci1UVUtsbGJ1RUlWZHNKUG9WTjdMVTJOWkZfWjJOUzJoQVZ3MXlCRzVZekpJWmNxZlRmZXNYLVNKQVNNNWVwd2dHcU51WDJPc3NhMng0X21yY1NxOGZOYWNRZ1phelpUVlNyZWdWd3V0ZjFKdnZoczBNODNsQWlXTTh3NFpvd3RsczdVRnprejM5dkE=";

        let result = validate(user_token.to_string(), identity_token.to_string(), true).await?;
        println!("{:?}", result);
        Ok(())
    }
}
