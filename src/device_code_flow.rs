// Standard libraries
use std::path::{Path, PathBuf};

// 3rd party crates
use extio::Extio;
use oauth2::{
    Client, ClientId, ClientSecret, DeviceAuthorizationUrl, EndpointNotSet, ExtraTokenFields,
    RequestTokenError, Scope, StandardDeviceAuthorizationResponse, StandardErrorResponse,
    StandardRevocableToken, StandardTokenResponse, TokenUrl,
    basic::{
        BasicErrorResponse, BasicErrorResponseType, BasicRevocationErrorResponse,
        BasicTokenIntrospectionResponse, BasicTokenType,
    },
};
use openidconnect::core::CoreIdToken;
use serde::{Deserialize, Serialize};

// My crates
use crate::error::{ErrorCodes, OAuth2Error, OAuth2Result};
use crate::{TokenKeeper, http_client::OAuth2Client};

pub struct DeviceCodeFlow {
    client_id: ClientId,
    client_secret: Option<ClientSecret>,
    device_auth_endpoint: DeviceAuthorizationUrl,
    token_endpoint: TokenUrl,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CustomExtraFields {
    pub id_token: CoreIdToken,
}

pub type CustomTokenResponse = StandardTokenResponse<CustomExtraFields, BasicTokenType>;

impl ExtraTokenFields for CustomExtraFields {}

pub type CustomClient<
    HasAuthUrl = EndpointNotSet,
    HasDeviceAuthUrl = EndpointNotSet,
    HasIntrospectionUrl = EndpointNotSet,
    HasRevocationUrl = EndpointNotSet,
    HasTokenUrl = EndpointNotSet,
> = Client<
    BasicErrorResponse,
    CustomTokenResponse,
    BasicTokenIntrospectionResponse,
    StandardRevocableToken,
    BasicRevocationErrorResponse,
    HasAuthUrl,
    HasDeviceAuthUrl,
    HasIntrospectionUrl,
    HasRevocationUrl,
    HasTokenUrl,
>;

impl DeviceCodeFlow {
    pub fn new(
        client_id: ClientId,
        client_secret: Option<ClientSecret>,
        device_auth_endpoint: DeviceAuthorizationUrl,
        token_endpoint: TokenUrl,
    ) -> Self {
        Self {
            client_id,
            client_secret,
            device_auth_endpoint,
            token_endpoint,
        }
    }
    pub async fn request_device_code<RE, I>(
        &self,
        scopes: Vec<Scope>,
        interface: &I,
    ) -> OAuth2Result<StandardDeviceAuthorizationResponse>
    where
        RE: std::error::Error + 'static,
        I: Extio + Send + Sync + Clone + 'static,
        I::Error: std::error::Error,
        OAuth2Error: From<I::Error>
            + From<RequestTokenError<RE, StandardErrorResponse<BasicErrorResponseType>>>,
    {
        log::info!(
            "There is no Access token, please login via browser with this link and input the code."
        );
        let mut client = CustomClient::new(self.client_id.to_owned());
        if let Some(client_secret) = self.client_secret.to_owned() {
            client = client.set_client_secret(client_secret);
        }
        let async_http_callback = OAuth2Client::new(interface.clone());
        let device_auth_response = client
            .set_auth_type(oauth2::AuthType::RequestBody)
            .set_token_uri(self.token_endpoint.to_owned())
            .set_device_authorization_url(self.device_auth_endpoint.to_owned())
            .exchange_device_code()
            .add_scopes(scopes)
            .request_async(&async_http_callback)
            .await?;

        Ok(device_auth_response)
    }
    pub async fn poll_access_token<RE, I>(
        &self,
        device_auth_response: StandardDeviceAuthorizationResponse,
        interface: &I,
    ) -> OAuth2Result<CustomTokenResponse>
    where
        RE: std::error::Error + 'static,
        I: Extio + Send + Sync + Clone + 'static,
        I::Error: std::error::Error,
        OAuth2Error: From<I::Error>
            + From<RequestTokenError<RE, StandardErrorResponse<BasicErrorResponseType>>>,
    {
        let mut client = CustomClient::new(self.client_id.to_owned());
        if let Some(client_secret) = self.client_secret.to_owned() {
            client = client.set_client_secret(client_secret);
        }
        let async_http_callback = OAuth2Client::new(interface.clone());
        let token_result = client
            .set_auth_type(oauth2::AuthType::RequestBody)
            .set_token_uri(self.token_endpoint.to_owned())
            .exchange_device_access_token(&device_auth_response)
            .request_async(&async_http_callback, tokio::time::sleep, None)
            .await?;
        log::info!("Access token successfuly retrieved from the endpoint.");
        Ok(token_result)
    }

    pub async fn get_access_token<I, RE>(
        &self,
        file_name: &Path,
        interface: &I,
    ) -> OAuth2Result<TokenKeeper>
    where
        RE: std::error::Error + 'static,
        I: Extio + Send + Sync + Clone + 'static,
        I::Error: std::error::Error,
        OAuth2Error: From<I::Error>
            + From<RequestTokenError<RE, StandardErrorResponse<BasicErrorResponseType>>>,
    {
        let mut token_keeper = TokenKeeper::new();
        token_keeper.read(file_name, interface)?;

        if token_keeper.has_access_token_expired() {
            match token_keeper.refresh_token {
                Some(ref_token) => {
                    log::info!(
                        "Access token has expired, contacting endpoint to get a new access token."
                    );
                    let mut client = CustomClient::new(self.client_id.to_owned());
                    if let Some(client_secret) = self.client_secret.to_owned() {
                        client = client.set_client_secret(client_secret);
                    }
                    let async_http_callback = OAuth2Client::new(interface.clone());
                    let response = client
                        .set_auth_type(oauth2::AuthType::RequestBody)
                        .set_token_uri(self.token_endpoint.to_owned())
                        .exchange_refresh_token(&ref_token)
                        .request_async(&async_http_callback)
                        .await;

                    match response {
                        Ok(res) => {
                            token_keeper = TokenKeeper::from(res);
                            token_keeper.save(file_name, interface)?;
                            Ok(token_keeper)
                        }
                        Err(e) => {
                            let error = OAuth2Error::from(e);
                            if error.error_code == ErrorCodes::InvalidGrant {
                                let file = TokenKeeper::new();
                                if let Err(e) = file.delete(file_name, interface) {
                                    log::error!("{e:?}");
                                }
                            }
                            Err(error)
                        }
                    }
                }
                None => {
                    log::info!(
                        "Access token has expired but there is no refresh token, please login again."
                    );
                    token_keeper.delete(file_name, interface)?;
                    Err(OAuth2Error::new(
                        ErrorCodes::NoToken,
                        "There is no refresh token.".into(),
                    ))
                }
            }
        } else {
            Ok(token_keeper)
        }
    }
}

pub async fn device_code_flow<I, RE>(
    client_id: &str,
    client_secret: Option<ClientSecret>,
    device_auth_endpoint: DeviceAuthorizationUrl,
    token_endpoint: TokenUrl,
    scopes: Vec<Scope>,
    interface: I,
) -> OAuth2Result<TokenKeeper>
where
    RE: std::error::Error + 'static,
    I: Extio + Clone + Send + Sync + 'static,
    I::Error: std::error::Error,
    OAuth2Error:
        From<I::Error> + From<RequestTokenError<RE, StandardErrorResponse<BasicErrorResponseType>>>,
{
    let oauth2_cloud = DeviceCodeFlow::new(
        ClientId::new(client_id.to_string()),
        client_secret,
        device_auth_endpoint,
        token_endpoint,
    );

    let token_file = PathBuf::from(format!("{client_id}_device_code_flow.json"));
    log::debug!("Path: {token_file:?}");

    let mut token_keeper = TokenKeeper::new();

    // If there is no exsting token, get it from the cloud
    if let Err(_err) = token_keeper.read(&token_file, &interface) {
        let device_auth_response = oauth2_cloud.request_device_code(scopes, &interface).await?;

        log::info!(
            "Login Here: {}",
            &device_auth_response.verification_uri().as_str(),
        );
        log::info!(
            "Device Code: {}",
            &device_auth_response.user_code().secret()
        );

        let token = oauth2_cloud
            .poll_access_token(device_auth_response, &interface)
            .await?;
        token_keeper = TokenKeeper::from(token);
        token_keeper.save(&token_file, &interface)?;
    } else {
        token_keeper = oauth2_cloud
            .get_access_token(&token_file, &interface)
            .await?;
    }
    Ok(token_keeper)
}
