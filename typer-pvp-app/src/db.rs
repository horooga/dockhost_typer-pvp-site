use crate::{
    auth::encode_jwt,
    misc::{ENV, validate},
};
use base64ct::{Base64Bcrypt, Encoding};
use bcrypt::{DEFAULT_COST, hash_with_salt, verify};
use deadpool_postgres::Client;
use once_cell::sync::Lazy;

static SALT_BYTES: Lazy<[u8; 16]> = Lazy::new(|| {
    let bytes = Base64Bcrypt::decode_vec(&ENV["BCRYPT_SALT"]).unwrap();
    bytes[..16].try_into().unwrap()
});

pub struct User {
    pub username: String,
    pub password: String,
}

pub fn hash_password(password: &str) -> String {
    hash_with_salt(password, DEFAULT_COST, *SALT_BYTES)
        .unwrap()
        .to_string()
}

pub async fn login(
    client: &Client,
    username: &String,
    password: &String,
) -> Result<String, String> {
    if let Ok(user) = get_user(client, username).await {
        if verify(password, user.password.as_str()).unwrap() {
            Ok(encode_jwt(username, 0_u8))
        } else {
            Err("wrong username or password".to_string())
        }
    } else {
        Err("username is not registered".to_string())
    }
}

pub async fn register(
    client: &Client,
    username: &String,
    password: &String,
) -> Result<(), Vec<String>> {
    if let Err(x) = validate(username, password).await {
        Err(x)
    } else if let Err(x) = add_user(client, username, password).await {
        Err(vec![x])
    } else {
        Ok(())
    }
}

pub async fn add_user(client: &Client, username: &String, password: &String) -> Result<(), String> {
    let _stmt = include_str!("../sql/add_user.sql");
    let stmt = client.prepare(_stmt).await.unwrap();

    if get_user(client, username).await.is_ok() {
        return Err("user is already registered".to_string());
    }

    if client
        .query(&stmt, &[&username, &hash_password(password)])
        .await
        .is_ok()
    {
        return Ok(());
    }

    Err("sorry".to_string())
}

pub async fn get_user(client: &Client, username: &String) -> Result<User, String> {
    let _stmt = include_str!("../sql/get_user.sql");
    let _stmt = _stmt.replace("$username", username.as_str());
    let stmt = client.prepare(&_stmt).await.unwrap();

    if let Ok(x) = client.query(&stmt, &[]).await {
        if !x.is_empty() {
            Ok(User {
                username: x[0].get(1),
                password: x[0].get(2),
            })
        } else {
            Err("user is not registered".to_string())
        }
    } else {
        Err("sorry, try again later".to_string())
    }
}
