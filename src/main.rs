use std::collections::HashMap;

use jsonwebtoken::{self, decode, EncodingKey};
use salvo::http::{Method, StatusError};
use salvo::jwt_auth::{ConstDecoder, QueryFinder, Algorithm};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};


const SECRET_KEY: &str = "YOUR SECRET_KEY";
const DOMAIN: &str= "iut-rodez.fr";

// https://developers.google.com/identity/gsi/web/reference/js-reference?hl=fr#CredentialResponse
#[derive(Deserialize, Debug, Serialize)]
struct JwtGooglePayload {
    iss: String,
    azp: String,
    aud: String,
    sub: String,
    hd: String,
    email: String,
    email_verified: bool,
    nbf: i64,
    name: String,
    picture: String,
    given_name: String,
    family_name: String,
    locale: String,
    iat: i64,
    exp: i64,
    jti: String,
}



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
    if req.method() == Method::POST {
        let hm: HashMap<String, String> = req.parse_body().await.unwrap();
        let cr = hm.get("credential").unwrap();

        // lire le payload sans clé : 
        // https://github.com/Keats/jsonwebtoken/issues/277#issuecomment-1349610845
        // https://docs.rs/jsonwebtoken/latest/jsonwebtoken/struct.Validation.html#structfield.validate_aud
        // note : Google utilise RS256 et pas HS256
        let key = salvo::jwt_auth::DecodingKey::from_secret(&[]);
        let mut validation = salvo::jwt_auth::Validation::new(Algorithm::RS256);
        validation.insecure_disable_signature_validation();
        validation.validate_aud = false;

        // Debug : pour voir les champs et types attendus dans la réponse JSON
        // use base64::prelude::*;
        // let parts = cr.split(".").collect::<Vec<&str>>();
        // let pl = parts[1];
        // let dec = BASE64_STANDARD_NO_PAD.decode(pl).unwrap();
        // let tok = String::from_utf8(dec).unwrap();
        // println!("{}", tok);

        //let jwt_google_data: jsonwebtoken::TokenData<JwtGooglePayload> = decode::<JwtGooglePayload>(cr, &key, &validation).unwrap();

        // https://docs.rs/salvo-jwt-auth/latest/salvo_jwt_auth/index.html
        let jwt_google_data: salvo::jwt_auth::TokenData<JwtGooglePayload> = decode::<JwtGooglePayload>(cr, &key, &validation).unwrap();
        let google_claims = jwt_google_data.claims;

        let hd = google_claims.hd;
        // Vérifie que l'utilisateur Google fait bien partie de notre domaine iut-rodez.fr
        if &hd != DOMAIN {
            res.render(Text::Html(LOGIN_HTML));
            return Ok(());
        }


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
                res.render(Text::Html(LOGIN_HTML));
            }
            JwtAuthState::Forbidden => {
                res.render(StatusError::forbidden());
            }
        }
    }
    Ok(())
}



// code generator : https://developers.google.com/identity/gsi/web/tools/configurator?hl=fr
// gérer les réponses : https://developers.google.com/identity/gsi/web/guides/handle-credential-responses-js-functions?hl=fr
// JWT verification : https://github.com/kjur/jsrsasign/wiki/Tutorial-for-JWT-verification

static LOGIN_HTML: &str = r#"<!DOCTYPE html>
<html>
  <body>
<script language="JavaScript" type="text/javascript"
  src="https://kjur.github.io/jsrsasign/jsrsasign-latest-all-min.js">
</script>
    <script src="https://accounts.google.com/gsi/client" async defer></script>
    <div id="g_id_onload"
    data-client_id="331442361372-f9bbnhoevkchlr0pq0ss7sd4r0g7v7j1.apps.googleusercontent.com"
    data-context="use"
    data-ux_mode="redirect"
    data-login_uri="https://refidweb.iut-rodez.fr/refid3/"
    data-callback="handleCredentialResponse"
    data-auto_prompt="false">
</div>

<div class="g_id_signin"
    data-type="standard"
    data-shape="pill"
    data-theme="outline"
    data-text="signin"
    data-size="medium"
    data-logo_alignment="left">
</div>
<script>
  function decodeJwtResponse(response) {
    var sJWT = response;
    var headerObj = KJUR.jws.JWS.readSafeJSONString(b64utoutf8(sJWT.split(".")[0]));
    var payloadObj = KJUR.jws.JWS.readSafeJSONString(b64utoutf8(sJWT.split(".")[1]));
    console.log(headerObj);
    console.log(payloadObj);
    console.log("==============");
    return payloadObj;
  }


  function handleCredentialResponse(response) {
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
  }
</script>

  <div id="msg">
  </div>
 </body>
</html>
"#;
