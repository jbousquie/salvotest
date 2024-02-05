pub mod google_auth_jwt {
    use jsonwebtoken::{self, decode, DecodingKey, Validation, Algorithm};
    use serde::{Deserialize, Serialize};

    // issuers Google attendus
    const ISSUERS: [&str; 2] = ["accounts.google.com", "https://accounts.google.com"];

    // https://developers.google.com/identity/gsi/web/reference/js-reference?hl=fr#CredentialResponse
    #[derive(Deserialize, Debug, Serialize)]
    pub struct JwtGooglePayload {
        pub iss: String,
        pub azp: String,
        pub aud: String,
        pub sub: String,
        pub hd: String,
        pub email: String,
        pub email_verified: bool,
        pub nbf: i64,
        pub name: String,
        pub picture: String,
        pub given_name: String,
        pub family_name: String,
        pub locale: String,
        pub iat: i64,
        pub exp: i64,
        pub jti: String,
    }

    // Renvoie un objet JwtGooglePayload après analyse du token JWT renvoyé par Google passé en paramètre "credentials"
    pub fn get_google_claims(credential: &String, google_id: &str) -> JwtGooglePayload {
        // pour lire le payload sans clé : https://github.com/Keats/jsonwebtoken/issues/277#issuecomment-1349610845
        // https://docs.rs/jsonwebtoken/latest/jsonwebtoken/struct.Validation.html#structfield.validate_aud
        // note : Google utilise RS256 et pas HS256
        let key = DecodingKey::from_secret(&[]);

        // TODO : CSRF + signature jeton
        // https://developers.google.com/identity/gsi/web/guides/verify-google-id-token?hl=fr
        let mut validation = Validation::new(Algorithm::RS256);
        validation.insecure_disable_signature_validation();
        validation.set_audience(&[google_id]);
        validation.set_issuer(&ISSUERS);

        //Debug : pour voir les champs et types attendus dans la réponse JSON
        // use base64::prelude::*;
        // let parts = credential.split(".").collect::<Vec<&str>>();
        // let head = parts[0];
        // let pl = parts[1];
        // let hed = BASE64_STANDARD_NO_PAD.decode(head).unwrap();
        // let dec = BASE64_STANDARD_NO_PAD.decode(pl).unwrap();
        // let header = String::from_utf8(hed).unwrap();
        // let tok = String::from_utf8(dec).unwrap();
        // println!("\n\nheader = {}\n\ntoken = {}\n\n", header, tok);

        let jwt_google_data: jsonwebtoken::TokenData<JwtGooglePayload> = decode::<JwtGooglePayload>(&credential, &key, &validation).unwrap();

        
        
        let google_claims = jwt_google_data.claims;
        return google_claims;


    }


    // Renvoie une string de code HTML à insérer dans la page de login Google de l'application
    pub fn get_google_auth_html(client_id: &str, login_url: &str) -> String {
        // code generator : https://developers.google.com/identity/gsi/web/tools/configurator?hl=fr
        format!("
        <script src='https://accounts.google.com/gsi/client' async defer></script>
        <div id='g_id_onload'
        data-client_id='{}'
        data-context='use'
        data-ux_mode='redirect'
        data-login_uri='{}'
        data-callback='handleCredentialResponse'
        data-auto_prompt='false'>
    </div>
    <div class='g_id_signin'
        data-type='standard'
        data-shape='pill'
        data-theme='outline'
        data-text='signin'
        data-size='medium'
        data-logo_alignment='left'>
    </div>", client_id, login_url)
    }
}

