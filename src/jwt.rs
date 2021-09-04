use anyhow::Error;
use chrono::NaiveDate;
use openssl::{
    ec::{EcGroup, EcKey},
    nid::Nid,
    pkey::PKey,
};
use rocket::{
    http::Status,
    request::{self, FromRequest, Outcome, Request},
};

enum Role {
    USER_TOKEN,
}

pub struct Payload {
    role: Role,
}

pub struct TokenData {
    user: i64,
    issued_at: NaiveDate,
    public_key: String,
    key_id: String,
    payload: Payload,
}

pub struct JsonWebToken(pub String);

fn verify_token(token: &str) -> Option<JsonWebToken> {
    if token == "asdf" {
        return Some(JsonWebToken(token.to_string()));
    }
    None
}

fn extract_jwt_query(request: &Request<'_>) -> Option<String> {
    if let Some(Ok(jwt)) = request.query_value("jwt") {
        Some(jwt)
    } else {
        None
    }
}

fn extract_jwt_header(request: &Request<'_>) -> Option<String> {
    let keys: Vec<_> = request.headers().get("Authorization").collect();
    if keys.len() != 1 {
        return None;
    }
    let mut jwt = keys[0].split_whitespace();
    if jwt.next() != Some("Bearer") {
        return None;
    }
    jwt.next().map(|token| token.to_string())
}

fn extract_jwt(request: &Request<'_>) -> Option<String> {
    if let Some(token) = extract_jwt_header(request) {
        return Some(token);
    }
    if let Some(token) = extract_jwt_query(request) {
        return Some(token);
    }
    None
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for JsonWebToken {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        match extract_jwt(request) {
            Some(token) if let Some(jwt) = verify_token(&token) => Outcome::Success(jwt),
            Some(_) => Outcome::Failure((Status::BadRequest, "Authorization invalid")),
            _ => Outcome::Failure((Status::BadRequest, "Authorization missing")),
        }
    }
}

pub fn issue_token(user_id: i64) {
    let (sig, data) = create(
        user_id,
        Payload {
            role: Role::USER_TOKEN,
        },
    );
}

fn create(user_id: i64, payload: Payload) -> Result<(String, TokenData), Error> {
    let (pub_key, priv_key) = generate_key_pair()?;
    unimplemented!();
}

fn generate_key_pair() -> Result<(String, String), Error> {
    let curve = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let ec = EcKey::generate(&curve)?;
    let pkey = PKey::from_ec_key(ec)?;

    let pub_key: Vec<u8> = pkey.public_key_to_pem()?;
    let pub_key = String::from_utf8(pub_key.as_slice().to_vec())?;

    let priv_key: Vec<u8> = pkey.private_key_to_pem_pkcs8()?;
    let priv_key = String::from_utf8(priv_key.as_slice().to_vec())?;
    Ok((pub_key, priv_key))
}
