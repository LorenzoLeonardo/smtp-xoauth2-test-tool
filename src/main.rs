mod auth_code_grant;
mod device_code_flow;
mod error;
mod http_client;
mod provider;
mod token_keeper;

// Standard libraries
use std::env;
use std::path::PathBuf;
use std::str::FromStr;

// 3rd party crates
use env_logger::Env;
use mail_send::{mail_builder::MessageBuilder, Credentials, SmtpClientBuilder};
use oauth2::ClientSecret;
use strum_macros::EnumString;

// My crates
use crate::auth_code_grant::auth_code_grant;
use crate::device_code_flow::device_code_flow;
use crate::error::{ErrorCodes, OAuth2Error};
use crate::provider::Provider;
use error::OAuth2Result;
use token_keeper::TokenKeeper;

#[derive(EnumString)]
enum OAuth2TokenGrantFlow {
    AuthorizationCodeGrant,
    DeviceCodeFlow,
}

impl From<String> for OAuth2TokenGrantFlow {
    fn from(str: String) -> Self {
        OAuth2TokenGrantFlow::from_str(str.as_str()).unwrap()
    }
}

fn init_logger(level: &str) {
    env_logger::Builder::from_env(Env::default().default_filter_or(level)).init();
}

fn check_args(args: &Vec<String>) -> OAuth2Result<()> {
    if args.len() != 10 {
        eprintln!("How to use this tool?\n");
        eprintln!("Execute: cargo run <provider> <access token grant type> <client secret> <client id> <sender email address> <sender name> <recipient email> <recipient name> <debug log level>");
        Err(OAuth2Error::new(
            ErrorCodes::InvalidParameters,
            String::from("Invalid args"),
        ))
    } else {
        Ok(())
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> OAuth2Result<()> {
    let args: Vec<String> = env::args().collect();
    check_args(&args)?;

    let provider_directory = std::env::current_exe()?
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let provider_directory = provider_directory.join(PathBuf::from("endpoints"));
    let provider = Provider::read(&provider_directory, &PathBuf::from(args[1].to_string()))?;
    let client_secret = match args[3].as_str() {
        "None" => None,
        _ => Some(ClientSecret::new(args[3].to_string())),
    };
    let client_id = &args[4];
    let sender_email = &args[5];
    let sender_name = &args[6];
    let receiver_email = &args[7];
    let receiver_name = &args[8];
    init_logger(args[9].as_str());

    let access_token = match OAuth2TokenGrantFlow::from(args[2].to_string()) {
        OAuth2TokenGrantFlow::AuthorizationCodeGrant => {
            auth_code_grant(
                client_id,
                client_secret,
                sender_email,
                provider.authorization_endpoint,
                provider.token_endpoint,
                provider.scopes,
            )
            .await?
        }
        OAuth2TokenGrantFlow::DeviceCodeFlow => {
            device_code_flow(
                client_id,
                client_secret,
                sender_email,
                provider.device_auth_endpoint,
                provider.token_endpoint,
                provider.scopes,
            )
            .await?
        }
    };

    // Start of sending Email
    let message = MessageBuilder::new()
        .from((sender_name.as_ref(), sender_email.as_ref()))
        .to(vec![(receiver_name.as_ref(), receiver_email.as_ref())])
        .subject("Test XOAUTH2 SMTP!")
        .html_body("<h1>Hello, world!</h1>")
        .text_body("Hello world!");

    let credentials = Credentials::new(sender_email.as_ref(), access_token.secret().as_str());
    log::info!("Authenticating SMTP XOAUTH2 Credentials....");
    let email_connect =
        SmtpClientBuilder::new(provider.smtp_server.0.as_ref(), provider.smtp_server_port.0)
            .implicit_tls(false)
            .credentials(credentials)
            .connect()
            .await;

    match email_connect {
        Ok(mut result) => {
            log::info!("Sending SMTP XOAUTH2 Email....");
            let send = result.send(message).await;
            match send {
                Ok(_result) => {}
                Err(err) => {
                    log::error!("SMTP Sending Error: {err:?}");
                }
            }
        }
        Err(err) => {
            log::error!("SMTP Connecting Error: {err:?}");
        }
    }
    Ok(())
}
