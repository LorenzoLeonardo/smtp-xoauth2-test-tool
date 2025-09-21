use std::path::{Path, PathBuf};

use oauth2::{AuthUrl, DeviceAuthorizationUrl, Scope, TokenUrl, url::Url};
use serde::{Deserialize, Serialize};

use crate::{
    ParamIndex,
    error::{ErrorCodes, OAuth2Error, OAuth2Result},
    interface::ExtioExtended,
};

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Hash, Default)]
pub struct SmtpHostName(pub String);

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct SmtpPort(pub u16);

#[derive(Serialize, Deserialize, Debug)]
pub struct ProfileUrl(pub Url);

#[derive(Serialize, Deserialize, Debug)]
pub struct Provider {
    pub authorization_endpoint: AuthUrl,
    pub token_endpoint: TokenUrl,
    pub device_auth_endpoint: DeviceAuthorizationUrl,
    pub scopes: Vec<Scope>,
    pub smtp_server: SmtpHostName,
    pub smtp_server_port: SmtpPort,
    pub profile_endpoint: ProfileUrl,
}

impl Provider {
    fn read(directory: &Path, file_name: &PathBuf) -> OAuth2Result<Self> {
        let input_path = directory.join(file_name);
        let text = std::fs::read_to_string(&input_path).map_err(|err| {
            OAuth2Error::new(
                ErrorCodes::IoError,
                format!["{err} => {}", input_path.display()],
            )
        })?;
        Ok(serde_json::from_str::<Self>(&text)?)
    }

    pub fn get_provider<I>(args: &[String], interface: &I) -> OAuth2Result<Provider>
    where
        I: ExtioExtended,
    {
        let provider_directory = interface.provider_path();

        let provider = Provider::read(
            provider_directory,
            &PathBuf::from(args[ParamIndex::Provider as usize].to_string()),
        );
        match provider {
            Ok(provider) => Ok(provider),
            Err(_err) => {
                let provider = Provider::read(
                    &PathBuf::from("endpoints"),
                    &PathBuf::from(args[ParamIndex::Provider as usize].to_string()),
                )?;
                Ok(provider)
            }
        }
    }
}
