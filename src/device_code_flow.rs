// Standard libraries
use std::{
    future::Future,
    path::{Path, PathBuf},
};

// 3rd party crates
use async_trait::async_trait;
use directories::UserDirs;
use oauth2::{
    Client, ClientId, ClientSecret, DeviceAuthorizationUrl, EndpointNotSet, ExtraTokenFields,
    HttpRequest, HttpResponse, Scope, StandardDeviceAuthorizationResponse, StandardRevocableToken,
    StandardTokenResponse, TokenUrl,
    basic::{
        BasicErrorResponse, BasicRevocationErrorResponse, BasicTokenIntrospectionResponse,
        BasicTokenType,
    },
};
use openidconnect::core::CoreIdToken;
use serde::{Deserialize, Serialize};

// My crates
use crate::TokenKeeper;
use crate::{
    curl::Curl,
    error::{ErrorCodes, OAuth2Error, OAuth2Result},
};

#[async_trait(?Send)]
pub trait DeviceCodeFlowTrait {
    async fn request_device_code<
        F: Future<Output = Result<HttpResponse, RE>>,
        RE: std::error::Error + 'static,
        T: Fn(HttpRequest) -> F,
    >(
        &self,
        scopes: Vec<Scope>,
        async_http_callback: T,
    ) -> OAuth2Result<StandardDeviceAuthorizationResponse>;
    async fn poll_access_token<
        F: Future<Output = Result<HttpResponse, RE>>,
        RE: std::error::Error + 'static,
        T: Fn(HttpRequest) -> F,
    >(
        &self,
        device_auth_response: StandardDeviceAuthorizationResponse,
        async_http_callback: T,
    ) -> OAuth2Result<CustomTokenResponse>;
    async fn get_access_token<
        F: Future<Output = Result<HttpResponse, RE>>,
        RE: std::error::Error + 'static,
        T: Fn(HttpRequest) -> F,
    >(
        &self,
        file_directory: &Path,
        file_name: &Path,
        async_http_callback: T,
    ) -> OAuth2Result<TokenKeeper>;
}

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

#[async_trait(?Send)]
impl DeviceCodeFlowTrait for DeviceCodeFlow {
    async fn request_device_code<
        F: Future<Output = Result<HttpResponse, RE>>,
        RE: std::error::Error + 'static,
        T: Fn(HttpRequest) -> F,
    >(
        &self,
        scopes: Vec<Scope>,
        async_http_callback: T,
    ) -> OAuth2Result<StandardDeviceAuthorizationResponse> {
        log::info!(
            "There is no Access token, please login via browser with this link and input the code."
        );
        let mut client = CustomClient::new(self.client_id.to_owned());
        if let Some(client_secret) = self.client_secret.to_owned() {
            client = client.set_client_secret(client_secret);
        }
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
    async fn poll_access_token<
        F: Future<Output = Result<HttpResponse, RE>>,
        RE: std::error::Error + 'static,
        T: Fn(HttpRequest) -> F,
    >(
        &self,
        device_auth_response: StandardDeviceAuthorizationResponse,
        async_http_callback: T,
    ) -> OAuth2Result<CustomTokenResponse> {
        let mut client = CustomClient::new(self.client_id.to_owned());
        if let Some(client_secret) = self.client_secret.to_owned() {
            client = client.set_client_secret(client_secret);
        }
        let token_result = client
            .set_auth_type(oauth2::AuthType::RequestBody)
            .set_token_uri(self.token_endpoint.to_owned())
            .exchange_device_access_token(&device_auth_response)
            .request_async(&async_http_callback, tokio::time::sleep, None)
            .await?;
        log::info!("Access token successfuly retrieved from the endpoint.");
        Ok(token_result)
    }

    async fn get_access_token<
        F: Future<Output = Result<HttpResponse, RE>>,
        RE: std::error::Error + 'static,
        T: Fn(HttpRequest) -> F,
    >(
        &self,
        file_directory: &Path,
        file_name: &Path,
        async_http_callback: T,
    ) -> OAuth2Result<TokenKeeper> {
        let mut token_keeper = TokenKeeper::new(file_directory.to_path_buf());
        token_keeper.read(file_name)?;

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
                    let response = client
                        .set_auth_type(oauth2::AuthType::RequestBody)
                        .set_token_uri(self.token_endpoint.to_owned())
                        .exchange_refresh_token(&ref_token)
                        .request_async(&async_http_callback)
                        .await;

                    match response {
                        Ok(res) => {
                            token_keeper = TokenKeeper::from(res);
                            token_keeper.set_directory(file_directory.to_path_buf());
                            token_keeper.save(file_name)?;
                            Ok(token_keeper)
                        }
                        Err(e) => {
                            let error = OAuth2Error::from(e);
                            if error.error_code == ErrorCodes::InvalidGrant {
                                let file = TokenKeeper::new(file_directory.to_path_buf());
                                if let Err(e) = file.delete(file_name) {
                                    log::error!("{:?}", e);
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
                    token_keeper.delete(file_name)?;
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
}

pub async fn device_code_flow(
    client_id: &str,
    client_secret: Option<ClientSecret>,
    device_auth_endpoint: DeviceAuthorizationUrl,
    token_endpoint: TokenUrl,
    scopes: Vec<Scope>,
    curl: Curl,
) -> OAuth2Result<TokenKeeper> {
    let oauth2_cloud = DeviceCodeFlow::new(
        ClientId::new(client_id.to_string()),
        client_secret,
        device_auth_endpoint,
        token_endpoint,
    );

    let directory = UserDirs::new().ok_or(OAuth2Error::new(
        ErrorCodes::DirectoryError,
        "No valid directory".to_string(),
    ))?;
    let mut directory = directory.home_dir().to_owned();

    directory = directory.join("token");

    let token_file = PathBuf::from(format!("{}_device_code_flow.json", client_id));
    log::debug!("Path: {:?}", token_file);
    log::debug!("Directory: {:?}", directory);
    let mut token_keeper = TokenKeeper::new(directory.to_path_buf());

    // If there is no exsting token, get it from the cloud
    if let Err(_err) = token_keeper.read(&token_file) {
        let device_auth_response = oauth2_cloud
            .request_device_code(scopes, |request| async { curl.send(request).await })
            .await?;

        log::info!(
            "Login Here: {}",
            &device_auth_response.verification_uri().as_str(),
        );
        log::info!(
            "Device Code: {}",
            &device_auth_response.user_code().secret()
        );

        let token = oauth2_cloud
            .poll_access_token(device_auth_response, |request| async {
                curl.send(request).await
            })
            .await?;
        token_keeper = TokenKeeper::from(token);
        token_keeper.set_directory(directory.to_path_buf());

        token_keeper.save(&token_file)?;
    } else {
        token_keeper = oauth2_cloud
            .get_access_token(&directory, &token_file, |request| async {
                curl.send(request).await
            })
            .await?;
    }
    Ok(token_keeper)
}
