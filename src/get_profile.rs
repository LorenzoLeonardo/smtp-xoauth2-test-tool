use std::str::FromStr;

use derive_deref_rs::Deref;
use http::{HeaderMap, HeaderValue};
use oauth2::AccessToken;
use serde::{Deserialize, Serialize};

use crate::{
    curl::Curl,
    error::{OAuth2Error, OAuth2Result},
    provider::ProfileUrl,
};

#[derive(Deref)]
pub struct SenderName(pub String);
#[derive(Deref)]
pub struct SenderEmail(pub String);

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct MicrosoftProfile {
    #[serde(rename = "@odata.context")]
    odata_context: String,
    #[serde(rename = "@odata.id")]
    odata_id: String,
    id: String,
    email_address: String,
    display_name: String,
    alias: String,
    mailbox_guid: String,
}

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

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Profile {
    Microsoft(MicrosoftProfile),
    Google(GoogleProfile),
}

impl Profile {
    pub async fn get_sender_profile(
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
        let mut request = oauth2::HttpRequest::new(Vec::new());
        *request.uri_mut() = oauth2::http::Uri::from_str(profile_endpoint.0.to_owned().as_ref())?;
        *request.method_mut() = oauth2::http::Method::GET;

        request.headers_mut().insert(
            oauth2::http::HeaderName::from_str("Authorization")?,
            oauth2::http::HeaderValue::from_str(&header_val)?,
        );

        let response = curl.send(request).await?;

        let body = String::from_utf8(response.body().to_vec()).unwrap_or_default();

        let sender_profile: Profile = serde_json::from_str(&body)?;
        let (name, email) = match sender_profile {
            Profile::Microsoft(profile) => {
                log::debug!("Response: {:?}", profile);
                (
                    SenderName(profile.display_name),
                    SenderEmail(profile.email_address),
                )
            }
            Profile::Google(profile) => {
                log::debug!("Response: {:?}", profile);
                (SenderName(profile.given_name), SenderEmail(profile.email))
            }
        };
        log::info!("Sender Name: {}", name.as_str());
        log::info!("Sender E-mail: {}", email.as_str());
        Ok((name, email))
    }
}

#[cfg(test)]
mod tests {
    use crate::get_profile::Profile;

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

        let google: Profile = serde_json::from_str(google_json).unwrap();

        if let Profile::Google(google) = google {
            println!("deserialize = {:?}", &google);
            println!("serialize = {:?}", serde_json::to_string(&google).unwrap());
        } else {
            panic!("Not Google");
        }
    }

    #[test]
    fn test_microsoft_profile() {
        let ms_json = r#"{
            "@odata.context": "data context",
            "@odata.id": "data id",
            "Id": "sample id",
            "EmailAddress": "test@outlook.com",
            "DisplayName": "My Name",
            "Alias": "Haxxx",
            "MailboxGuid": "en"
          }"#;

        let ms: Profile = serde_json::from_str(ms_json).unwrap();

        if let Profile::Microsoft(ms) = ms {
            println!("deserialize = {:?}", &ms);
            println!("serialize = {:?}", serde_json::to_string(&ms).unwrap());
        } else {
            panic!("Not Microsoft");
        }
    }
}
