mod google_auth_jwt;
use google_auth_jwt::google_auth_jwt::*;

use std::collections::HashMap;

use jsonwebtoken::{self, EncodingKey};
use salvo::http::{Method, StatusError};
use salvo::jwt_auth::{ConstDecoder, QueryFinder};
use salvo::prelude::*;
use salvo::serve_static::StaticDir;
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

use askama::Template;


const SECRET_KEY: &str = "YOUR SECRET_KEY";
const DOMAIN: &str= "iut-rodez.fr";
const GOOGLE_ID: &str = "331442361372-f9bbnhoevkchlr0pq0ss7sd4r0g7v7j1.apps.googleusercontent.com";
const LOGIN_URL: &str = "https://refidweb.iut-rodez.fr/refid3/";


#[derive(Debug, Serialize, Deserialize)]
pub struct JwtClaims {
    google_id: String,
    email: String,
    name: String,
    family_name: String,
    given_name: String,
    exp: i64,
}


#[derive(Template)]
#[template(path = "logged.html")]
struct LoggedTemplate<'a> {
    name: &'a str,
}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate {
    html_google_part: String,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().init();

    let auth_handler: JwtAuth<JwtClaims, _> =
        JwtAuth::new(ConstDecoder::from_secret(SECRET_KEY.as_bytes()))
            .finders(vec![
                // Box::new(HeaderFinder::new()),
                Box::new(QueryFinder::new("jwt_token")),
                //Box::new(CookieFinder::new("jwt_token")),
            ])
            .force_passed(true);

    let router = Router::new()
                .push(
                    Router::with_hoop(auth_handler).goal(index)
                ).push(
                    Router::with_path("<**path>").get(
                        StaticDir::new(["static"]).defaults("index.html").auto_list(true)
                    )
                );
    let acceptor = TcpListener::new("192.168.100.84:5800").bind().await;
    Server::new(acceptor)
        .serve(router)
        .await;
}


#[handler]
async fn index(req: &mut Request, depot: &mut Depot, res: &mut Response) -> anyhow::Result<()> {

    
    if req.method() == Method::POST {
        let hm: HashMap<String, String> = req.parse_body().await.unwrap();
        let cr = hm.get("credential").unwrap();

        let google_claims = get_google_claims(cr, GOOGLE_ID);

        let hd = google_claims.hd;
        // Vérifie que l'utilisateur Google fait bien partie de notre domaine iut-rodez.fr
        if &hd != DOMAIN {
            let login_html = get_login_page();
            res.render(login_html);
            return Ok(());
        }

        // Gestion du JWT de "session" de Salvo, une fois l'auth Google validée
        let exp = OffsetDateTime::now_utc() + Duration::days(14);
        let claim = JwtClaims {
            google_id: google_claims.sub,
            email: google_claims.email,
            name: google_claims.name,
            family_name: google_claims.family_name,
            given_name: google_claims.given_name,
            exp: exp.unix_timestamp(),
        };
        let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &claim,
            &EncodingKey::from_secret(SECRET_KEY.as_bytes()),
        )?;
        res.render(Redirect::other(&format!("/refid3/?jwt_token={}", token)));
    } else {
        match depot.jwt_auth_state() {
            JwtAuthState::Authorized => {
                let data = depot.jwt_auth_data::<JwtClaims>().unwrap();
                let logged_template = LoggedTemplate {
                    name: &data.claims.name,
                };
                res.render(Text::Html((logged_template).render().unwrap()) );
            }
            JwtAuthState::Unauthorized => {
                let login_html = get_login_page();
                res.render(login_html);
            }
            JwtAuthState::Forbidden => {
                res.render(StatusError::forbidden());
            }
        }
    }
    Ok(())
}

// Renvoie un Text<String> prêt pour le render de Salvo
fn get_login_page() -> Text<String> {
    let html_google_part = get_google_auth_html(GOOGLE_ID, LOGIN_URL);
    let login_template = LoginTemplate{ html_google_part };
    let login_html = Text::Html((login_template).render().unwrap());
    return login_html; 
}
