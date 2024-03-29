// Standard libraries
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::{future::Future, path::Path};

// 3rd party crates
use async_trait::async_trait;
use directories::UserDirs;
use oauth2::{
    basic::BasicClient, url::Url, AuthUrl, ClientId, ClientSecret, CsrfToken, HttpRequest,
    HttpResponse, RedirectUrl, Scope, TokenUrl,
};
use oauth2::{AccessToken, AuthorizationCode};

// My crates
use crate::curl::Curl;
use crate::error::{ErrorCodes, OAuth2Error, OAuth2Result};
use crate::TokenKeeper;

#[async_trait(?Send)]
pub trait AuthCodeGrantTrait {
    async fn generate_authorization_url(
        &self,
        scopes: Vec<Scope>,
    ) -> OAuth2Result<(Url, CsrfToken)>;

    async fn exchange_auth_code<
        F: Future<Output = Result<HttpResponse, RE>>,
        RE: std::error::Error + 'static,
        T: Fn(HttpRequest) -> F,
    >(
        &self,
        file_directory: &Path,
        file_name: &Path,
        auth_code: AuthorizationCode,
        async_http_callback: T,
    ) -> OAuth2Result<TokenKeeper>;

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

pub struct AuthCodeGrant {
    client_id: ClientId,
    client_secret: Option<ClientSecret>,
    auth_endpoint: AuthUrl,
    token_endpoint: TokenUrl,
}

#[async_trait(?Send)]
impl AuthCodeGrantTrait for AuthCodeGrant {
    async fn generate_authorization_url(
        &self,
        scopes: Vec<Scope>,
    ) -> OAuth2Result<(Url, CsrfToken)> {
        log::info!("There is no Access token, please login.");
        let mut client = BasicClient::new(self.client_id.to_owned());
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

    async fn exchange_auth_code<
        F: Future<Output = Result<HttpResponse, RE>>,
        RE: std::error::Error + 'static,
        T: Fn(HttpRequest) -> F,
    >(
        &self,
        file_directory: &Path,
        file_name: &Path,
        auth_code: AuthorizationCode,
        async_http_callback: T,
    ) -> OAuth2Result<TokenKeeper> {
        let mut client = BasicClient::new(self.client_id.to_owned());
        if let Some(client_secret) = self.client_secret.to_owned() {
            client = client.set_client_secret(client_secret);
        }
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

        let mut token_keeper = TokenKeeper::from(token_res);
        token_keeper.set_directory(file_directory.to_path_buf());
        token_keeper.save(file_name)?;
        log::info!("Access token successfuly retrieved from the endpoint.");
        Ok(token_keeper)
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
                    let mut client = BasicClient::new(self.client_id.to_owned());
                    if let Some(client_secret) = self.client_secret.to_owned() {
                        client = client.set_client_secret(client_secret);
                    }
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
                    log::info!("Access token has expired but there is no refresh token, please login again.");
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
}

pub async fn auth_code_grant(
    client_id: &str,
    client_secret: Option<ClientSecret>,
    auth_url: AuthUrl,
    token_url: TokenUrl,
    scopes: Vec<Scope>,
    curl: Curl,
) -> OAuth2Result<AccessToken> {
    let auth_code_grant = AuthCodeGrant::new(
        ClientId::new(client_id.to_string()),
        client_secret,
        auth_url,
        token_url,
    );

    let directory = UserDirs::new().ok_or(OAuth2Error::new(
        ErrorCodes::DirectoryError,
        "No valid directory".to_string(),
    ))?;
    let mut directory = directory.home_dir().to_owned();

    directory = directory.join("token");

    let token_file = PathBuf::from(format!("{}_auth_code_grant.json", client_id));
    let mut token_keeper = TokenKeeper::new(directory.to_path_buf());

    // If there is no exsting token, get it from the cloud
    if let Err(_err) = token_keeper.read(&token_file) {
        let (authorize_url, _csrf_state) =
            auth_code_grant.generate_authorization_url(scopes).await?;
        log::info!(
            "Open this URL in your browser: {}",
            authorize_url.to_string()
        );

        let listener = TcpListener::bind("127.0.0.1:8080")?;
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
                let url = Url::parse(&("http://localhost".to_string() + redirect_url))?;

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
                .exchange_auth_code(&directory, &token_file, code, |request| async {
                    curl.send(request).await
                })
                .await?;

            // The server will terminate itself after collecting the first code.
        }
    } else {
        token_keeper = auth_code_grant
            .get_access_token(&directory, &token_file, |request| async {
                curl.send(request).await
            })
            .await?;
    }
    Ok(token_keeper.access_token)
}
