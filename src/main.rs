mod google_auth_jwt;
use google_auth_jwt::google_auth_jwt::*;

use std::collections::HashMap;

use jsonwebtoken::{self, EncodingKey};
use salvo::http::{Method, StatusError};
use salvo::jwt_auth::{ConstDecoder, QueryFinder};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};


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

    let acceptor = TcpListener::new("192.168.100.84:5800").bind().await;
    Server::new(acceptor)
        .serve(Router::with_hoop(auth_handler).goal(index))
        .await;
}
#[handler]
async fn index(req: &mut Request, depot: &mut Depot, res: &mut Response) -> anyhow::Result<()> {
    let html_google_part = get_google_auth_html(GOOGLE_ID, LOGIN_URL);
    let login_html = build_login_page(&html_google_part);
    
    if req.method() == Method::POST {
        let hm: HashMap<String, String> = req.parse_body().await.unwrap();
        let cr = hm.get("credential").unwrap();

        let google_claims = get_google_claims(cr);

        let hd = google_claims.hd;
        // Vérifie que l'utilisateur Google fait bien partie de notre domaine iut-rodez.fr
        if &hd != DOMAIN {
            res.render(Text::Html(login_html));
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
                res.render(Text::Plain(format!(
                    "Connecté en tant que  {} sur REFID3",
                    data.claims.name
                )));
            }
            JwtAuthState::Unauthorized => {
                res.render(Text::Html(login_html));
            }
            JwtAuthState::Forbidden => {
                res.render(StatusError::forbidden());
            }
        }
    }
    Ok(())
}


// Renvoie la string de la page de login
fn build_login_page(google_auth_part: &String) -> String {

    format!("<!DOCTYPE html>
    <html>
    <body>
    <script language='JavaScript' type='text/javascript'
    src='https://kjur.github.io/jsrsasign/jsrsasign-latest-all-min.js'>
    </script>
    {}
    <script>
    function decodeJwtResponse(response) {{
        var sJWT = response;
        var headerObj = KJUR.jws.JWS.readSafeJSONString(b64utoutf8(sJWT.split('.')[0]));
        var payloadObj = KJUR.jws.JWS.readSafeJSONString(b64utoutf8(sJWT.split('.')[1]));
        console.log(headerObj);
        console.log(payloadObj);
        console.log('==============');
        return payloadObj;
    }}

    function handleCredentialResponse(response) {{
        // decodeJwtResponse() is a custom function defined by you
        // to decode the credential response.
            const responsePayload = decodeJwtResponse(response.credential);

            var d = document.querySelector('#msg');
            var str_id = 'ID : ' + responsePayload.sub;
            var str_fu = 'Full Name : ' + responsePayload.name;
            var str_gn = 'Given Name : ' + responsePayload.given_name;
            var str_fn = 'Family Name : ' + responsePayload.family_name;
            var str_em = 'Email : ' + responsePayload.email
            var sp = '<div>';
            var fp = '</div>';
            var ep = fp + sp;
            var str = sp + str_id + ep + str_fu + ep + str_gn + ep + str_fn + ep + str_em + fp;
            d.innerHTML = str;
    }}
    </script>

    <div id='msg'>
    </div>
    </body>
    </html>
    ", google_auth_part)
}
