use jsonwebtoken::{self, EncodingKey};
use salvo::http::{Method, StatusError};
use salvo::jwt_auth::{ConstDecoder, QueryFinder};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};


const SECRET_KEY: &str = "YOUR SECRET_KEY";

#[derive(Debug, Serialize, Deserialize)]
pub struct JwtClaims {
    username: String,
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
                // Box::new(CookieFinder::new("jwt_token")),
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
        let (username, password) = (
            req.form::<String>("username").await.unwrap_or_default(),
            req.form::<String>("password").await.unwrap_or_default(),
        );
        if !validate(&username, &password) {
            res.render(Text::Html(LOGIN_HTML));
            return Ok(());
        }
        let exp = OffsetDateTime::now_utc() + Duration::days(14);
        let claim = JwtClaims {
            username,
            exp: exp.unix_timestamp(),
        };
        let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &claim,
            &EncodingKey::from_secret(SECRET_KEY.as_bytes()),
        )?;
        res.render(Redirect::other(&format!("/?jwt_token={}", token)));
    } else {
        match depot.jwt_auth_state() {
            JwtAuthState::Authorized => {
                let data = depot.jwt_auth_data::<JwtClaims>().unwrap();
                res.render(Text::Plain(format!(
                    "Hi {}, have logged in successfully!",
                    data.claims.username
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

fn validate(username: &str, password: &str) -> bool {
    username == "root" && password == "pwd"
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
    data-ux_mode="popup"
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

     console.log("ID: " + responsePayload.sub);
     console.log('Full Name: ' + responsePayload.name);
     console.log('Given Name: ' + responsePayload.given_name);
     console.log('Family Name: ' + responsePayload.family_name);
     console.log("Image URL: " + responsePayload.picture);
     console.log("Email: " + responsePayload.email);
  }
</script>

 </body>
</html>
"#;
