use async_curl::actor::CurlActor;
use curl_http_client::{collector::Collector, http_client::HttpClient};

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

    fn to_curl_request(request: oauth2::HttpRequest) -> http::Request<Option<Vec<u8>>> {
        request.map(|req| if req.is_empty() { None } else { Some(req) })
    }

    fn to_oauth_response(response: http::Response<Option<Vec<u8>>>) -> oauth2::HttpResponse {
        response.map(|resp| {
            if let Some(resp) = resp {
                resp
            } else {
                Vec::new()
            }
        })
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
            .request(Curl::to_curl_request(request))?
            .nonblocking(self.actor_handle.clone())
            .perform()
            .await
            .map(Curl::to_oauth_response)?;

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
