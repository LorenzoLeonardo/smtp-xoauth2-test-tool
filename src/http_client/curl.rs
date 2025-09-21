use curl_http_client::{collector::Collector, dep::async_curl::CurlActor, http_client::HttpClient};

use crate::error::OAuth2Error;

#[derive(Clone)]
pub struct Curl {
    pub actor_handle: CurlActor<Collector>,
}

impl Default for Curl {
    fn default() -> Self {
        Self {
            actor_handle: CurlActor::new(),
        }
    }
}

impl Curl {
    pub async fn send(
        &self,
        request: oauth2::HttpRequest,
    ) -> Result<oauth2::HttpResponse, OAuth2Error> {
        log::debug!("Request Url: {}", request.uri());
        log::debug!("Request Header: {:?}", request.headers());
        log::debug!("Request Method: {}", request.method());
        log::debug!("Request Body: {}", String::from_utf8_lossy(request.body()));

        let response = HttpClient::new(Collector::RamAndHeaders(Vec::new(), Vec::new()))
            .request(request)?
            .nonblocking(self.actor_handle.clone())
            .perform()
            .await?
            .map(|resp| resp.unwrap_or_default());

        log::debug!("Response Status: {}", response.status());
        log::debug!("Response Header: {:?}", response.headers());
        log::debug!(
            "Response Body: {}",
            String::from_utf8_lossy(response.body())
        );
        Ok(response)
    }
}
