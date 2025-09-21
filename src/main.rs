mod auth_code_grant;
mod device_code_flow;
mod emailer;
mod error;
mod http_client;
mod interface;
mod openid;
mod provider;
mod token_keeper;

// Standard libraries
use std::env;
use std::io::Write;
use std::str::FromStr;

// 3rd party crates
use chrono::Local;
use log::LevelFilter;
use oauth2::{ClientId, ClientSecret};
use strum_macros::EnumString;

// My crates
use auth_code_grant::auth_code_grant;
use device_code_flow::device_code_flow;
use emailer::Emailer;
use error::OAuth2Result;
use error::{ErrorCodes, OAuth2Error};
use provider::Provider;
use token_keeper::TokenKeeper;

use crate::http_client::HttpClient;
use crate::http_client::reqwest::Reqwest;
use crate::interface::ActualInterface;
use crate::openid::{ApplicationNonce, verify_id_token};

enum ParamIndex {
    Provider = 1,
    TokenGrantType,
    ClientId,
    ClientSecret,
    RecipientEmail,
    RecipientName,
    DebugLevel,
}

#[derive(EnumString)]
enum OAuth2TokenGrantFlow {
    AuthorizationCodeGrant,
    DeviceCodeFlow,
}

impl OAuth2TokenGrantFlow {
    pub fn from(str: String) -> OAuth2Result<Self> {
        OAuth2TokenGrantFlow::from_str(str.as_str()).map_err(|e| {
            OAuth2Error::new(ErrorCodes::ParseError, format!("{} ({})", e, str.as_str()))
        })
    }
}

fn init_logger(level: &str) {
    let mut log_builder = env_logger::Builder::new();
    log_builder.format(|buf, record| {
        let mut module = "";
        if let Some(path) = record.module_path()
            && let Some(split) = path.split("::").last()
        {
            module = split;
        }

        writeln!(
            buf,
            "{}[{}]:{}: {}",
            Local::now().format("[%d-%m-%Y %H:%M:%S]"),
            record.level(),
            module,
            record.args()
        )
    });

    log_builder.filter_level(LevelFilter::from_str(level).unwrap_or(LevelFilter::Info));
    if let Err(e) = log_builder.try_init() {
        log::error!("{e:?}");
    }
}

fn check_args(args: &[String]) -> OAuth2Result<()> {
    if args.len() < ParamIndex::DebugLevel as usize {
        eprintln!("How to use this tool?\n");
        eprintln!(
            "Execute: cargo run <provider> <access token grant type> <client id> <client secret> <recipient email> <recipient name> <debug log level>"
        );
        Err(OAuth2Error::new(
            ErrorCodes::InvalidParameters,
            String::from("Lacking parameters"),
        ))
    } else {
        Ok(())
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> OAuth2Result<()> {
    let args: Vec<String> = env::args().collect();
    check_args(&args)?;

    let interface = ActualInterface::new(HttpClient::Reqwest(Reqwest::new()));
    let provider: Provider = Provider::get_provider(&args, &interface)?;
    let client_secret = match args[ParamIndex::ClientSecret as usize].as_str() {
        "None" => None,
        _ => Some(ClientSecret::new(
            args[ParamIndex::ClientSecret as usize].to_string(),
        )),
    };
    let client_id = &args[ParamIndex::ClientId as usize];
    let recipient_email = &args[ParamIndex::RecipientEmail as usize];
    let recipient_name = &args[ParamIndex::RecipientName as usize];
    if args.len() <= (ParamIndex::DebugLevel as usize) {
        init_logger("info");
    } else {
        init_logger(args[ParamIndex::DebugLevel as usize].as_str());
    }

    let version = env!("CARGO_PKG_VERSION");
    log::info!("SMTP Test Tool v{version} has started...");

    let token =
        match OAuth2TokenGrantFlow::from(args[ParamIndex::TokenGrantType as usize].to_string())? {
            OAuth2TokenGrantFlow::AuthorizationCodeGrant => {
                auth_code_grant(
                    client_id,
                    client_secret.clone(),
                    provider.authorization_endpoint,
                    provider.token_endpoint,
                    provider.scopes,
                    &interface,
                )
                .await?
            }
            OAuth2TokenGrantFlow::DeviceCodeFlow => {
                device_code_flow(
                    client_id,
                    client_secret.clone(),
                    provider.device_auth_endpoint,
                    provider.token_endpoint,
                    provider.scopes,
                    &interface,
                )
                .await?
            }
        };

    let claims = verify_id_token(
        ClientId::new(client_id.to_string()),
        client_secret,
        token.id_token.unwrap(),
        ApplicationNonce::new(),
        &interface,
    )
    .await?;
    let name = if let Some(name) = claims.name() {
        name.get(None).unwrap().to_string()
    } else {
        log::error!("No name");
        return Ok(());
    };

    let email = if let Some(name) = claims.email() {
        name.to_string()
    } else {
        log::error!("No email");
        return Ok(());
    };
    log::info!(
        "***********************************************************************************************************************"
    );
    log::info!("Hi {name} ({email}), Welcome to our SMTP XOAuth2 Emailing System.");
    log::info!(
        "***********************************************************************************************************************"
    );
    Emailer::new(provider.smtp_server, provider.smtp_server_port)
        .set_sender(name, email)
        .add_recipient(recipient_name.into(), recipient_email.into())
        .send_email(token.access_token)
        .await
}
