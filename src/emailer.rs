use mail_send::{mail_builder::MessageBuilder, Credentials, SmtpClientBuilder};
use oauth2::AccessToken;

use crate::{
    error::OAuth2Result,
    provider::{SmtpHostName, SmtpPort},
};

#[derive(Default)]
pub struct Emailer {
    pub smtp_server: SmtpHostName,
    pub smtp_port: SmtpPort,
    pub sender: (String, String),
    pub recipients: Vec<(String, String)>,
}

impl Emailer {
    pub fn new(smtp_server: SmtpHostName, smtp_port: SmtpPort) -> Self {
        Self {
            smtp_server,
            smtp_port,
            ..Default::default()
        }
    }

    pub fn set_sender(mut self, sender_name: String, sender_email: String) -> Self {
        self.sender = (sender_name, sender_email);
        self
    }

    pub fn add_recipient(mut self, recipient_name: String, recipient_email: String) -> Self {
        self.recipients.push((recipient_name, recipient_email));
        self
    }

    pub async fn send_email(self, access_token: AccessToken) -> OAuth2Result<()> {
        // Start of sending Email
        let message = MessageBuilder::new()
            .from(self.sender.to_owned())
            .to(self.recipients)
            .subject("Test XOAUTH2 SMTP!")
            .html_body("<h1>Hello, world!</h1>")
            .text_body("Hello world!");

        let (_sender_name, sender_email) = self.sender;
        let credentials =
            Credentials::new_xoauth2(sender_email.as_str(), access_token.secret().as_str());
        log::info!("Authenticating SMTP XOAUTH2 Credentials....");
        let email_connect = SmtpClientBuilder::new(self.smtp_server.0.as_ref(), self.smtp_port.0)
            .implicit_tls(false)
            .credentials(credentials)
            .connect()
            .await;

        match email_connect {
            Ok(mut result) => {
                log::info!("Sending SMTP XOAUTH2 Email....");
                let send = result.send(message).await;
                match send {
                    Ok(_result) => {
                        log::info!("Sending Email success!!");
                    }
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
}
