use crate::misc::ENV;
use actix_web::{
    Error, HttpRequest, HttpResponse,
    body::{EitherBody, MessageBody},
    dev::{ServiceRequest, ServiceResponse},
    middleware::Next,
};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

static JWT_SECRET: Lazy<&[u8]> = Lazy::new(|| ENV["JWT_SECRET"].as_bytes());

#[derive(Deserialize)]
pub struct UserLogin {
    pub username: String,
    pub password: String,
}

#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub usrnm: String,
    pub lngid: u8,
    pub exp: usize,
}

pub fn decode_jwt_from_req(req: HttpRequest) -> Option<Claims> {
    if let Some(jwt) = req.cookie("token") {
        let claims = decode::<Claims>(
            jwt.value(),
            &DecodingKey::from_secret(*JWT_SECRET),
            &Validation::default(),
        )
        .unwrap()
        .claims;
        if claims.exp > OffsetDateTime::now_utc().unix_timestamp() as usize {
            Some(claims)
        } else {
            None
        }
    } else {
        None
    }
}

pub fn encode_jwt(username: &str, language_id: u8) -> String {
    let expiration = OffsetDateTime::now_utc() + Duration::hours(1);
    let claims = Claims {
        usrnm: username.to_owned(),
        lngid: language_id,
        exp: expiration.unix_timestamp() as usize,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(*JWT_SECRET),
    )
    .unwrap()
}

pub async fn jwt_auth_mw(
    req: ServiceRequest,
    next: Next<impl MessageBody>,
) -> Result<ServiceResponse<EitherBody<impl MessageBody>>, Error> {
    let path = req.path();

    if path.starts_with("/static") {
        return Ok(next.call(req).await.unwrap().map_into_left_body());
    }

    if decode_jwt_from_req(req.request().clone()).is_some() {
        if path == "/" || path.starts_with("/login") || path.starts_with("/register") {
            let res = HttpResponse::SeeOther()
                .append_header(("Location", "/profile"))
                .finish();
            Ok(req.into_response(res.map_into_right_body()))
        } else {
            Ok(next.call(req).await.unwrap().map_into_left_body())
        }
    } else if path == "/" || path.starts_with("/login") || path.starts_with("/register") {
        Ok(next.call(req).await.unwrap().map_into_left_body())
    } else {
        Ok(req.into_response(
            HttpResponse::SeeOther()
                .append_header(("Location", "/"))
                .finish()
                .map_into_right_body(),
        ))
    }
}
