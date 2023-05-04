use std::path::{Path, PathBuf};

use oauth2::{AuthUrl, DeviceAuthorizationUrl, Scope, TokenUrl};
use serde::{Deserialize, Serialize};

use crate::error::OAuth2Result;

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Hash)]
pub struct SmtpHostName(pub String);

#[derive(Serialize, Deserialize, Debug)]
pub struct SmtpPort(pub u16);

#[derive(Serialize, Deserialize, Debug)]
pub struct Provider {
    pub authorization_endpoint: AuthUrl,
    pub token_endpoint: TokenUrl,
    pub device_auth_endpoint: DeviceAuthorizationUrl,
    pub scopes: Vec<Scope>,
    pub smtp_server: SmtpHostName,
    pub smtp_server_port: SmtpPort,
}

impl Provider {
    pub fn read(directory: &Path, file_name: &PathBuf) -> OAuth2Result<Self> {
        let input_path = directory.join(file_name);
        eprintln!("Fullpath: {}", &input_path.to_string_lossy());
        let text = std::fs::read_to_string(input_path)?;

        Ok(serde_json::from_str::<Self>(&text)?)
    }
}
