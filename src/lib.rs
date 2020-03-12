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
use jsonwebtoken::decode_header;
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str;

#[derive(Debug, Serialize, Deserialize)]
struct KeyComponents {
    kty: String,   // "RSA"
    kid: String,   // "eXaunmL"
    r#use: String, // "sig"
    alg: String,   // "RS256"
    n: String,     // "4dGQ7bQK8LgILOdL..."
    e: String,     // "AQAB"
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
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

#[derive(Debug)]
pub enum ValidateError {
    HeaderAlgorithmUnspecified,
    KidNotFound,
    KeyNotFound,
    BadJWTHeader,
}

pub async fn validate(base64_token: String, ignore_expire: bool) -> Result<bool, ValidateError> {
    // Claims is a struct that implements Deserialize

    let token = base64::decode(&base64_token).expect("cannot base64 decode token");
    let header = match decode_header(str::from_utf8(&token).unwrap()) {
        Ok(hdr) => hdr,
        Err(e) => {
            eprintln!("jwttoken error: {}", e);
            return Err(ValidateError::BadJWTHeader);
        }
    };

    let kid = match header.kid {
        Some(k) => k,
        None => return Err(ValidateError::KidNotFound),
    };

    let resp = reqwest::get("https://appleid.apple.com/auth/keys")
        .await
        .unwrap()
        .json::<HashMap<String, Vec<KeyComponents>>>()
        .await
        .unwrap();

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
    match decode::<Claims>(
        str::from_utf8(&token).unwrap(),
        &DecodingKey::from_rsa_components(&pubkey.n, &pubkey.e),
        &val,
    ) {
        Ok(msg) => {
            println!("{:?}", msg);
        }
        Err(e) => {
            eprintln!("validation error: {}", e);
            return Ok(false);
        }
    };
    Ok(true)
}

#[cfg(test)]
mod tests {
    use crate::validate;

    #[tokio::test]
    async fn validate_test() -> std::result::Result<(), String> {
    	let identity_token = "<insert your token here>";

        let result = validate(identity_token.to_string(), false).await;
        println!("{:?}", result);
        Ok(())
    }
}
