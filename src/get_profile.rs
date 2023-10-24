use async_trait::async_trait;
use http::{HeaderMap, HeaderValue};
use oauth2::{AccessToken, HttpRequest};
use serde::{Deserialize, Serialize};

use crate::{
    curl::Curl,
    error::{OAuth2Error, OAuth2Result},
    provider::ProfileUrl,
};

pub struct SenderName(pub String);
pub struct SenderEmail(pub String);

#[async_trait]
pub trait SenderProfile {
    async fn get_sender_profile(
        access_token: &AccessToken,
        profile_endpoint: &ProfileUrl,
        curl: Curl,
    ) -> OAuth2Result<(SenderName, SenderEmail)>;
}

// Start for Microsoft
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct MicrosoftProfile {
    #[serde(rename = "@odata.context")]
    odata_context: String,
    #[serde(rename = "@odata.id")]
    odata_id: String,
    id: String,
    pub email_address: String,
    pub display_name: String,
    alias: String,
    mailbox_guid: String,
}

#[async_trait]
impl SenderProfile for MicrosoftProfile {
    async fn get_sender_profile(
        access_token: &AccessToken,
        profile_endpoint: &ProfileUrl,
        curl: Curl,
    ) -> OAuth2Result<(SenderName, SenderEmail)> {
        let mut headers = HeaderMap::new();

        let header_val = format!("Bearer {}", access_token.secret().as_str());
        headers.insert(
            "Authorization",
            HeaderValue::from_str(&header_val).map_err(OAuth2Error::from)?,
        );

        let request = HttpRequest {
            url: profile_endpoint.0.to_owned(),
            method: http::method::Method::GET,
            headers,
            body: Vec::new(),
        };
        let response = curl.send(request).await?;

        let body = String::from_utf8(response.body).unwrap_or(String::new());

        let sender_profile: MicrosoftProfile = serde_json::from_str(&body)?;
        log::info!("Sender Name: {}", sender_profile.display_name.as_str());
        log::info!("Sender E-mail: {}", sender_profile.email_address.as_str());
        Ok((
            SenderName(sender_profile.display_name),
            SenderEmail(sender_profile.email_address),
        ))
    }
}
// End  for Microsoft
// Start for Google
#[derive(Debug, Deserialize, Serialize)]
pub struct GoogleProfile {
    id: String,
    email: String,
    verified_email: bool,
    name: String,
    given_name: String,
    picture: String,
    locale: String,
}

#[async_trait]
impl SenderProfile for GoogleProfile {
    async fn get_sender_profile(
        access_token: &AccessToken,
        profile_endpoint: &ProfileUrl,
        curl: Curl,
    ) -> OAuth2Result<(SenderName, SenderEmail)> {
        let mut headers = HeaderMap::new();

        let header_val = format!("Bearer {}", access_token.secret().as_str());
        headers.insert(
            "Authorization",
            HeaderValue::from_str(&header_val).map_err(OAuth2Error::from)?,
        );

        let request = HttpRequest {
            url: profile_endpoint.0.to_owned(),
            method: http::method::Method::GET,
            headers,
            body: Vec::new(),
        };

        let response = curl.send(request).await?;

        let body = String::from_utf8(response.body).unwrap_or(String::new());

        let sender_profile: GoogleProfile = serde_json::from_str(&body)?;
        log::info!("Sender Name: {}", sender_profile.given_name.as_str());
        log::info!("Sender E-mail: {}", sender_profile.email.as_str());
        Ok((
            SenderName(sender_profile.given_name),
            SenderEmail(sender_profile.email),
        ))
    }
}
// End for Google

#[cfg(test)]
mod tests {
    use super::GoogleProfile;

    #[test]
    fn test_google_profile() {
        let google_json = r#"{
            "id": "1525363627",
            "email": "test@gmail.com",
            "verified_email": true,
            "name": "My Name",
            "given_name": "My Name",
            "picture": "https://picutre",
            "locale": "en"
          }"#;

        let google: GoogleProfile = serde_json::from_str(google_json).unwrap();
        println!("deserialize = {:?}", &google);
        println!("serialize = {:?}", serde_json::to_string(&google).unwrap());
    }
}
