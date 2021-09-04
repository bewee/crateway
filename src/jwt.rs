use rocket::{
    http::Status,
    request::{self, FromRequest, Outcome, Request},
};

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
