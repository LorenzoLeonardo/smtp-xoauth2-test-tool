use async_trait::async_trait;
use http::{HeaderMap, HeaderValue};
use oauth2::{url::Url, AccessToken, HttpRequest};
use serde::{Deserialize, Serialize};

use crate::{
    error::{OAuth2Error, OAuth2Result},
    http_client::async_http_client,
};

#[async_trait]
pub trait SenderProfile {
    async fn get_sender_profile(access_token: &AccessToken) -> OAuth2Result<(String, String)>;
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
    async fn get_sender_profile(access_token: &AccessToken) -> OAuth2Result<(String, String)> {
        let mut headers = HeaderMap::new();

        let header_val = format!("Bearer {}", access_token.secret().as_str());
        headers.insert(
            "Authorization",
            HeaderValue::from_str(&header_val).map_err(OAuth2Error::from)?,
        );

        let request = HttpRequest {
            url: Url::parse("https://outlook.office.com/api/v2.0/me/")?,
            method: http::method::Method::GET,
            headers,
            body: Vec::new(),
        };

        let response = async_http_client(request)
            .await
            .map_err(OAuth2Error::from)?;

        let body = String::from_utf8(response.body).unwrap_or(String::new());

        let sender_profile: MicrosoftProfile = serde_json::from_str(&body)?;
        log::info!("Sender Name: {}", sender_profile.display_name.as_str());
        log::info!("Sender E-mail: {}", sender_profile.email_address.as_str());
        Ok((sender_profile.display_name, sender_profile.email_address))
    }
}
// End  for Microsoft
// Start for Google
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Person {
    given_name: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct PersonImage {
    url: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Email {
    #[serde(rename(serialize = "type"))]
    #[serde(rename(deserialize = "type"))]
    email_type: String,
    value: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GoogleProfile {
    kind: String,
    display_name: String,
    name: Person,
    language: String,
    image: PersonImage,
    emails: Vec<Email>,
    etag: String,
    id: String,
}

#[async_trait]
impl SenderProfile for GoogleProfile {
    async fn get_sender_profile(access_token: &AccessToken) -> OAuth2Result<(String, String)> {
        let mut headers = HeaderMap::new();

        let header_val = format!("Bearer {}", access_token.secret().as_str());
        headers.insert(
            "Authorization",
            HeaderValue::from_str(&header_val).map_err(OAuth2Error::from)?,
        );

        let request = HttpRequest {
            url: Url::parse("https://www.googleapis.com/plus/v1/people/me")?,
            method: http::method::Method::GET,
            headers,
            body: Vec::new(),
        };

        let response = async_http_client(request)
            .await
            .map_err(OAuth2Error::from)?;

        let body = String::from_utf8(response.body).unwrap_or(String::new());

        let sender_profile: GoogleProfile = serde_json::from_str(&body)?;
        log::info!("Sender Name: {}", sender_profile.display_name.as_str());
        log::info!("Sender E-mail: {}", sender_profile.emails[0].value.as_str());
        Ok((
            sender_profile.display_name,
            sender_profile.emails[0].value.to_owned(),
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
            "kind": "plus#person", 
            "displayName": "Sender Name", 
            "name": {
              "givenName": "Sender Name"
            }, 
            "language": "en", 
            "image": {
              "url": "https://dummy_user_contentq"
            }, 
            "emails": [
              {
                "type": "ACCOUNT", 
                "value": "dummyemail@gmail.com"
              }
            ], 
            "etag": "%SaMple", 
            "id": "12345678"
          }"#;

        let google: GoogleProfile = serde_json::from_str(google_json).unwrap();
        println!("deserialize = {:?}", &google);
        println!("serialize = {:?}", serde_json::to_string(&google).unwrap());
    }
}
