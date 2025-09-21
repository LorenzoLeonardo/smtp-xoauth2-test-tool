// Standard libraries
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::Path;
use std::path::PathBuf;

// 3rd party crates
use extio::Extio;
use oauth2::basic::BasicErrorResponseType;
use oauth2::{AuthUrl, ClientId, ClientSecret, CsrfToken, RedirectUrl, Scope, TokenUrl, url::Url};
use oauth2::{AuthorizationCode, RequestTokenError, StandardErrorResponse};

use crate::http_client::OAuth2Client;
use crate::interface::ExtioExtended;
// My crates
use crate::TokenKeeper;
use crate::device_code_flow::CustomClient;
use crate::error::{ErrorCodes, OAuth2Error, OAuth2Result};

pub struct AuthCodeGrant {
    client_id: ClientId,
    client_secret: Option<ClientSecret>,
    auth_endpoint: AuthUrl,
    token_endpoint: TokenUrl,
}

impl AuthCodeGrant {
    pub fn new(
        client_id: ClientId,
        client_secret: Option<ClientSecret>,
        auth_endpoint: AuthUrl,
        token_endpoint: TokenUrl,
    ) -> Self {
        Self {
            client_id,
            client_secret,
            auth_endpoint,
            token_endpoint,
        }
    }
    async fn generate_authorization_url(
        &self,
        scopes: Vec<Scope>,
    ) -> OAuth2Result<(Url, CsrfToken)> {
        log::info!("There is no Access token, please login.");
        let mut client = CustomClient::new(self.client_id.to_owned());
        if let Some(client_secret) = self.client_secret.to_owned() {
            client = client.set_client_secret(client_secret);
        }
        let (authorize_url, csrf_state) = client
            .set_redirect_uri(
                RedirectUrl::new("http://localhost:8080".to_string())
                    .expect("Invalid redirect URL"),
            )
            .set_auth_type(oauth2::AuthType::RequestBody)
            .set_redirect_uri(
                RedirectUrl::new("http://localhost:8080".to_string())
                    .expect("Invalid redirect URL"),
            )
            .set_token_uri(self.token_endpoint.to_owned())
            .set_auth_uri(self.auth_endpoint.to_owned())
            .authorize_url(CsrfToken::new_random)
            .add_scopes(scopes)
            .url();

        Ok((authorize_url, csrf_state))
    }

    async fn exchange_auth_code<I, RE>(
        &self,
        file_name: &Path,
        auth_code: AuthorizationCode,
        interface: &I,
    ) -> OAuth2Result<TokenKeeper>
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
        let token_res = client
            .set_auth_type(oauth2::AuthType::RequestBody)
            .set_redirect_uri(
                RedirectUrl::new("http://localhost:8080".to_string())
                    .expect("Invalid redirect URL"),
            )
            .set_token_uri(self.token_endpoint.to_owned())
            .set_auth_uri(self.auth_endpoint.to_owned())
            .exchange_code(auth_code)
            .request_async(&async_http_callback)
            .await?;

        let token_keeper = TokenKeeper::from(token_res);
        token_keeper.save(file_name, interface)?;
        log::info!("Access token successfuly retrieved from the endpoint.");
        Ok(token_keeper)
    }

    async fn get_access_token<I, RE>(
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
                        .set_redirect_uri(
                            RedirectUrl::new("http://localhost:8080".to_string())
                                .expect("Invalid redirect URL"),
                        )
                        .set_token_uri(self.token_endpoint.to_owned())
                        .set_auth_uri(self.auth_endpoint.to_owned())
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

pub async fn auth_code_grant<I, RE>(
    client_id: &str,
    client_secret: Option<ClientSecret>,
    auth_url: AuthUrl,
    token_url: TokenUrl,
    scopes: Vec<Scope>,
    interface: &I,
) -> OAuth2Result<TokenKeeper>
where
    RE: std::error::Error + 'static,
    I: ExtioExtended + Clone + Send + Sync + 'static,
    I::Error: std::error::Error,
    OAuth2Error:
        From<I::Error> + From<RequestTokenError<RE, StandardErrorResponse<BasicErrorResponseType>>>,
{
    let auth_code_grant = AuthCodeGrant::new(
        ClientId::new(client_id.to_string()),
        client_secret,
        auth_url,
        token_url,
    );

    let token_file = PathBuf::from(format!("{client_id}_auth_code_grant.json"));
    let token_file = interface.token_path().join(&token_file);
    log::debug!("Path: {token_file:?}");
    let mut token_keeper = TokenKeeper::new();

    // If there is no exsting token, get it from the cloud
    if let Err(_err) = token_keeper.read(&token_file, interface) {
        let (authorize_url, _csrf_state) =
            auth_code_grant.generate_authorization_url(scopes).await?;
        log::info!("Open this URL in your browser: {authorize_url}");

        let listener = TcpListener::bind("0.0.0.0:8080")?;
        if let Some(mut stream) = listener.incoming().flatten().next() {
            let code;
            let _state;
            {
                let mut reader = BufReader::new(&stream);

                let mut request_line = String::new();
                reader.read_line(&mut request_line)?;

                let redirect_url =
                    request_line
                        .split_whitespace()
                        .nth(1)
                        .ok_or(OAuth2Error::new(
                            ErrorCodes::UrlParseError,
                            "No redirect URL found.".to_string(),
                        ))?;
                let url = Url::parse(&("http://localhost:8080".to_string() + redirect_url))?;

                let code_pair = url
                    .query_pairs()
                    .find(|pair| {
                        let (key, _) = pair;
                        key == "code"
                    })
                    .ok_or(OAuth2Error::new(
                        ErrorCodes::UrlParseError,
                        "No code was found in the redirect URL".to_string(),
                    ))?;

                let (_, value) = code_pair;
                code = AuthorizationCode::new(value.into_owned());

                let state_pair = url
                    .query_pairs()
                    .find(|pair| {
                        let (key, _) = pair;
                        key == "state"
                    })
                    .ok_or(OAuth2Error::new(
                        ErrorCodes::UrlParseError,
                        "No state was found in the redirect URL".to_string(),
                    ))?;

                let (_, value) = state_pair;
                _state = CsrfToken::new(value.into_owned());
            }

            let message = "Go back to your terminal :)";
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{}",
                message.len(),
                message
            );
            stream.write_all(response.as_bytes())?;

            // Exchange the code with a token.
            token_keeper = auth_code_grant
                .exchange_auth_code(&token_file, code, interface)
                .await?;

            // The server will terminate itself after collecting the first code.
        }
    } else {
        token_keeper = auth_code_grant
            .get_access_token(&token_file, interface)
            .await?;
    }
    Ok(token_keeper)
}
