use chrono::{DateTime, Utc};
use extio::Extio;
use oauth2::{
    ClientId, ClientSecret, RequestTokenError, StandardErrorResponse, basic::BasicErrorResponseType,
};
use openidconnect::{
    NonceVerifier,
    core::{CoreIdToken, CoreIdTokenClaims, CoreIdTokenVerifier, CoreProviderMetadata},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    error::{OAuth2Error, OAuth2Result},
    http_client::OAuth2Client,
};

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct ApplicationNonce(String);

impl ApplicationNonce {
    pub fn new() -> Self {
        Self::default()
    }
    #[allow(dead_code)]
    pub fn from(nonce: String) -> Self {
        Self(nonce)
    }
}

impl NonceVerifier for ApplicationNonce {
    fn verify(self, nonce: Option<&openidconnect::Nonce>) -> Result<(), String> {
        if let Some(claims_nonce) = nonce {
            // Avoid timing side-channel.
            if !self.0.is_empty() {
                if Sha256::digest(claims_nonce.secret()) != Sha256::digest(self.0) {
                    log::info!("Nonce mismatch!");
                    return Err("nonce mismatch".to_string());
                } else {
                    log::info!("Nonce match!")
                }
            } else {
                log::info!("There is no application side nonce used.");
            }
        } else {
            log::info!("The server didn't give some Nonce.");
        }
        Ok(())
    }
}

fn check_expiry(issued_time: DateTime<Utc>, expiry_time: DateTime<Utc>) -> Result<(), String> {
    log::info!("ID Token Issue Time: {issued_time:?}");
    log::info!("ID Token Expiry Time: {expiry_time:?}");

    let allowed_expiry_range = expiry_time - issued_time;
    log::info!("Configured Lifetime (Expiry - Issue): {allowed_expiry_range:?}");

    let actual_diff = Utc::now() - issued_time;
    log::info!("Elapsed Since Issue: {actual_diff:?}");

    if actual_diff > allowed_expiry_range {
        Err(String::from("ID Token is expired (issue time too old)."))
    } else {
        Ok(())
    }
}

fn log_authenticated_time(time: Option<DateTime<Utc>>) -> Result<(), String> {
    if let Some(time) = time {
        log::info!("User authenticated at: {time:?}");
    }
    Ok(())
}

pub async fn verify_id_token<I, RE>(
    client_id: ClientId,
    client_secret: Option<ClientSecret>,
    id_token: CoreIdToken,
    app_nonce: ApplicationNonce,
    interface: &I,
) -> OAuth2Result<CoreIdTokenClaims>
where
    RE: std::error::Error + 'static,
    I: Extio + Clone + Send + Sync + 'static,
    I::Error: std::error::Error,
    OAuth2Error:
        From<I::Error> + From<RequestTokenError<RE, StandardErrorResponse<BasicErrorResponseType>>>,
{
    log::info!("Verifying logged-in user . . .");
    let verifier = CoreIdTokenVerifier::new_insecure_without_verification();
    let unverified_claims = id_token.claims(&verifier, ApplicationNonce::new())?;

    let url = unverified_claims.issuer();
    let aync_http_client = OAuth2Client::new(interface.clone());
    let provider_metadata =
        CoreProviderMetadata::discover_async(url.clone(), &aync_http_client).await?;

    let json_web_key_set = provider_metadata.jwks();
    let expiry = unverified_claims.expiration();
    let verifier = if let Some(secret) = client_secret {
        log::info!("Has client secret use => CoreIdTokenVerifier::new_confidential_client");
        CoreIdTokenVerifier::new_confidential_client(
            client_id,
            secret,
            url.clone(),
            json_web_key_set.clone(),
        )
        .enable_signature_check()
        .require_audience_match(true)
        .require_issuer_match(true)
        .set_time_fn(Utc::now)
        .set_issue_time_verifier_fn(|time| check_expiry(time, expiry))
        .set_auth_time_verifier_fn(log_authenticated_time)
    } else {
        log::info!("No client secret use => CoreIdTokenVerifier::new_public_client");
        CoreIdTokenVerifier::new_public_client(client_id, url.clone(), json_web_key_set.clone())
            .enable_signature_check()
            .require_audience_match(true)
            .require_issuer_match(true)
            .set_time_fn(Utc::now)
            .set_issue_time_verifier_fn(|time| check_expiry(time, expiry))
            .set_auth_time_verifier_fn(log_authenticated_time)
    };

    let verified_claims = id_token.claims(&verifier, app_nonce)?.clone();
    log::info!("Verifying logged-in user successfull!");
    Ok(verified_claims)
}
