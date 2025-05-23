use actix_files::{Files, NamedFile};
use actix_web::{
    App, Either, HttpRequest, HttpResponse, HttpServer, Responder,
    cookie::{Cookie, SameSite},
    get,
    middleware::from_fn,
    post,
    web::{Data, Form, Html},
};
use deadpool_postgres::{Config, ManagerConfig, Pool, RecyclingMethod, tokio_postgres::NoTls};
use std::path::PathBuf;
use tera::{Context, Tera};
use time::Duration;
mod auth;
use auth::{UserLogin, decode_jwt_from_req, jwt_auth_mw};
mod misc;
use misc::ENV;
mod db;
use db::{get_user, login, register};

#[get("/")]
async fn index() -> impl Responder {
    let path: PathBuf = "static/html/start.html".parse().unwrap();
    NamedFile::open(path).unwrap()
}

#[get("/login")]
async fn login_handler(tmpl: Data<Tera>) -> impl Responder {
    Html::new(tmpl.render("login.tera", &Context::new()).unwrap())
}

#[get("/register")]
async fn register_handler(tmpl: Data<Tera>) -> impl Responder {
    Html::new(tmpl.render("register.tera", &Context::new()).unwrap())
}

#[post("/login-processing")]
async fn login_processing(
    pool: Data<Pool>,
    tmpl: Data<Tera>,
    Form(form): Form<UserLogin>,
) -> Either<Html, HttpResponse> {
    let client = pool.get().await.unwrap();
    match login(&client, &form.username, &form.password).await {
        Ok(jwt) => Either::Right(
            HttpResponse::SeeOther()
                .append_header(("Location", "/profile"))
                .cookie(
                    Cookie::build("token", jwt)
                        .path("/")
                        .http_only(true)
                        .same_site(SameSite::Lax)
                        .max_age(Duration::hours(1))
                        .finish(),
                )
                .finish(),
        ),
        Err(x) => {
            let mut ctx = Context::new();
            ctx.insert("err", &x);
            Either::Left(Html::new(tmpl.render("login.tera", &ctx).unwrap()))
        }
    }
}

#[post("/register-processing")]
async fn regster_processing(
    pool: Data<Pool>,
    tmpl: Data<Tera>,
    Form(form): Form<UserLogin>,
) -> Either<Html, HttpResponse> {
    let client = pool.get().await.unwrap();
    if let Err(x) = register(&client, &form.username, &form.password).await {
        let mut ctx = Context::new();
        ctx.insert("errs", &x);
        Either::Left(Html::new(tmpl.render("register.tera", &ctx).unwrap()))
    } else {
        let jwt = login(&client, &form.username, &form.password)
            .await
            .unwrap();
        Either::Right(
            HttpResponse::SeeOther()
                .append_header(("Location", "/profile"))
                .cookie(
                    Cookie::build("token", jwt)
                        .path("/")
                        .http_only(true)
                        .same_site(SameSite::Lax)
                        .max_age(Duration::hours(1))
                        .finish(),
                )
                .finish(),
        )
    }
}

#[get("/profile")]
async fn profile(req: HttpRequest, pool: Data<Pool>, tmpl: Data<Tera>) -> impl Responder {
    let client = pool.get().await.unwrap();
    if let Some(claims) = decode_jwt_from_req(req) {
        let user = get_user(&client, &claims.usrnm).await.unwrap();
        let mut ctx = Context::new();
        ctx.insert("username", user.username.as_str());
        Html::new(tmpl.render("profile.tera", &ctx).unwrap())
    } else {
        let mut ctx = Context::new();
        ctx.insert("err", "sorry, try again later");
        Html::new(tmpl.render("login.tera", &ctx).unwrap())
    }
}

#[post("/logout")]
async fn logout() -> impl Responder {
    HttpResponse::SeeOther()
        .append_header(("Location", "/"))
        .cookie(
            Cookie::build("token", "")
                .max_age(Duration::hours(0))
                .finish(),
        )
        .finish()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        let tera = Tera::new("/app/static/html/*").unwrap();
        let mut cfg = Config::new();
        cfg.dbname = Some("app".to_string());
        cfg.host = Some("postgres".to_string());
        cfg.port = Some(5432);
        cfg.user = Some(ENV["POSTGRES_USER"].clone());
        cfg.password = Some(ENV["POSTGRES_PASSWORD"].clone());
        cfg.manager = Some(ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        });
        let pool = cfg.create_pool(None, NoTls).unwrap();

        App::new()
            .wrap(from_fn(jwt_auth_mw))
            .service(index)
            .service(login_handler)
            .service(register_handler)
            .service(login_processing)
            .service(regster_processing)
            .service(profile)
            .service(logout)
            .service(Files::new("/static", "./static"))
            .app_data(Data::new(tera))
            .app_data(Data::new(pool.clone()))
    })
    .bind(("0.0.0.0", 8000))?
    .run()
    .await
}
