use oauth2::{ClientId, ClientSecret};
use openidconnect::{
    NonceVerifier,
    core::{CoreIdToken, CoreIdTokenClaims, CoreIdTokenVerifier, CoreProviderMetadata},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{curl::Curl, error::OAuth2Result};

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

pub async fn verify_id_token(
    client_id: ClientId,
    client_secret: Option<ClientSecret>,
    id_token: CoreIdToken,
    app_nonce: ApplicationNonce,
    curl: Curl,
) -> OAuth2Result<CoreIdTokenClaims> {
    log::info!("Verifying logged-in user . . .");
    let verifier = CoreIdTokenVerifier::new_insecure_without_verification();
    let unverified_claims = id_token.claims(&verifier, ApplicationNonce::new())?;

    let url = unverified_claims.issuer();
    let provider_metadata = CoreProviderMetadata::discover_async(url.clone(), &|request| async {
        curl.send(request).await
    })
    .await?;

    let json_web_key_set = provider_metadata.jwks();

    let verifier = if let Some(secret) = client_secret {
        log::info!("Has client secret use => CoreIdTokenVerifier::new_confidential_client");
        CoreIdTokenVerifier::new_confidential_client(
            client_id,
            secret,
            url.clone(),
            json_web_key_set.clone(),
        )
    } else {
        log::info!("No client secret use => CoreIdTokenVerifier::new_public_client");
        CoreIdTokenVerifier::new_public_client(client_id, url.clone(), json_web_key_set.clone())
    };

    let verified_claims = id_token.claims(&verifier, app_nonce)?.clone();
    log::info!("Verifying logged-in user successfull!");
    Ok(verified_claims)
}
