use std::pin::Pin;

use curl_http_client::{collector::Collector, dep::async_curl::CurlActor, http_client::HttpClient};
use extio::Extio;
use oauth2::{AsyncHttpClient, HttpRequest, HttpResponse};

use crate::error::OAuth2Error;

#[derive(Clone)]
pub struct Curl {
    pub actor_handle: CurlActor<Collector>,
}

impl Curl {
    pub fn new() -> Self {
        Self {
            actor_handle: CurlActor::new(),
        }
    }

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

impl Default for Curl {
    fn default() -> Self {
        Self::new()
    }
}

pub struct OAuth2Client<I>
where
    I: Extio + Clone + Send + Sync + 'static,
{
    interface: I,
}

impl<I> OAuth2Client<I>
where
    I: Extio + Clone + Send + Sync + 'static,
{
    pub fn new(interface: I) -> Self {
        Self { interface }
    }
}

impl<'c, I> AsyncHttpClient<'c> for OAuth2Client<I>
where
    I: Extio + Clone + Send + Sync + 'static,
    OAuth2Error: From<I::Error>,
{
    type Error = OAuth2Error;

    type Future = Pin<Box<dyn Future<Output = Result<HttpResponse, Self::Error>> + Send + 'c>>;

    fn call(&'c self, request: HttpRequest) -> Self::Future {
        let interface = self.interface.clone();
        Box::pin(async move {
            let result = interface.http_request(request).await?;
            Ok(result)
        })
    }
}
