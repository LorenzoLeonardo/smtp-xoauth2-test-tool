// Standard libraries
use std::path::Path;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use extio::Extio;
// 3rd party crates
use oauth2::basic::BasicTokenType;
use oauth2::{
    AccessToken, EmptyExtraTokenFields, RefreshToken, StandardTokenResponse, TokenResponse,
};
use openidconnect::core::CoreIdToken;
use serde::{Deserialize, Serialize};

use crate::device_code_flow::CustomTokenResponse;
// My crates
use crate::error::{OAuth2Error, OAuth2Result};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenKeeper {
    pub access_token: AccessToken,
    pub refresh_token: Option<RefreshToken>,
    pub id_token: Option<CoreIdToken>,
    scopes: Option<Vec<String>>,
    expires_in: Option<Duration>,
    token_receive_time: Duration,
}

impl Default for TokenKeeper {
    fn default() -> Self {
        Self::new()
    }
}

impl From<StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>> for TokenKeeper {
    fn from(
        token_response: StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>,
    ) -> TokenKeeper {
        let refresh_token = token_response
            .refresh_token()
            .map(|ref_tok| ref_tok.to_owned());

        let scopes = token_response
            .scopes()
            .map(|scope| scope.iter().map(|e| e.to_string()).collect());

        Self {
            access_token: token_response.access_token().to_owned(),
            refresh_token,
            id_token: None,
            scopes,
            expires_in: token_response.expires_in(),
            token_receive_time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards"),
        }
    }
}

impl From<CustomTokenResponse> for TokenKeeper {
    fn from(token_response: CustomTokenResponse) -> TokenKeeper {
        let refresh_token = token_response
            .refresh_token()
            .map(|ref_tok| ref_tok.to_owned());

        let scopes = token_response
            .scopes()
            .map(|scope| scope.iter().map(|e| e.to_string()).collect());

        Self {
            access_token: token_response.access_token().to_owned(),
            refresh_token,
            id_token: Some(token_response.extra_fields().id_token.clone()),
            scopes,
            expires_in: token_response.expires_in(),
            token_receive_time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards"),
        }
    }
}

impl TokenKeeper {
    pub fn new() -> Self {
        Self {
            access_token: AccessToken::new(String::new()),
            refresh_token: None,
            id_token: None,
            scopes: None,
            expires_in: None,
            token_receive_time: Duration::new(0, 0),
        }
    }

    pub fn has_access_token_expired(&self) -> bool {
        let time_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");

        if let Some(expires) = self.expires_in {
            (time_now - self.token_receive_time) >= expires
        } else {
            true
        }
    }

    pub fn read<I>(&mut self, file_name: &Path, interface: &I) -> OAuth2Result<()>
    where
        I: Extio,
        I::Error: std::error::Error,
        OAuth2Error: From<I::Error>,
    {
        let result = interface.read_file(file_name)?;

        *self = serde_json::from_slice::<Self>(&result)?;
        Ok(())
    }

    pub fn save<I>(&self, file_name: &Path, interface: &I) -> OAuth2Result<()>
    where
        I: Extio,
        I::Error: std::error::Error,
        OAuth2Error: From<I::Error>,
    {
        let json = serde_json::to_vec(self)?;
        interface.write_file(file_name, &json)?;
        Ok(())
    }

    pub fn delete<I>(&self, file_name: &Path, interface: &I) -> OAuth2Result<()>
    where
        I: Extio,
        I::Error: std::error::Error,
        OAuth2Error: From<I::Error>,
    {
        interface.delete_file(file_name)?;
        Ok(())
    }
}
