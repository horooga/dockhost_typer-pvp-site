use env_file_reader::read_file;
use once_cell::sync::Lazy;
use std::collections::HashMap;

pub static ENV: Lazy<HashMap<String, String>> = Lazy::new(|| read_file(".env").unwrap());

pub async fn validate(username: &String, password: &String) -> Result<(), Vec<String>> {
    let mut errs: Vec<String> = vec![];
    if username.len() < 5 {
        errs.push("username should be longer than 5 symbols".to_string());
    }
    if password.len() < 8 {
        errs.push("password should be longer than 8 symbols".to_string());
    }
    if password.len() > 30 {
        errs.push("password should be shorter than 30 symbols".to_string());
    }
    if username.len() > 15 {
        errs.push("username should be shorter than 15 symbols".to_string());
    }
    if !username.chars().all(char::is_alphanumeric) {
        errs.push("username should contain only alphanumeric symbols".to_string());
    }
    if !password
        .chars()
        .all(|x| char::is_alphanumeric(x) || "!@#$%^&*()_+=-?><".contains(x))
    {
        errs.push(
            "password should contain only alphanumeric symbols + \"!@#$%^&*()_+=-?><\"".to_string(),
        );
    }

    if errs.is_empty() { Ok(()) } else { Err(errs) }
}
