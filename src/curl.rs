use std::str::FromStr;

use async_curl::actor::CurlActor;
use curl_http_client::{collector::Collector, error::Error, http_client::HttpClient};

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
        let body = if request.body().is_empty() {
            None
        } else {
            Some(request.body().to_owned())
        };
        let mut http_request = http::Request::new(body);

        *http_request.uri_mut() = http::Uri::from_str(&request.uri().to_string()).unwrap();
        *http_request.method_mut() = http::Method::from_str(&request.method().to_string()).unwrap();
        for (key, value) in request.headers() {
            http_request.headers_mut().insert(
                http::HeaderName::from_str(&key.to_string()).unwrap(),
                http::HeaderValue::from_str(value.to_str().unwrap()).unwrap(),
            );
        }
        http_request
    }

    fn to_oauth_response(response: http::Response<Option<Vec<u8>>>) -> oauth2::HttpResponse {
        let body = if let Some(body) = response.body().to_owned() {
            body
        } else {
            Vec::new()
        };
        let mut oauth2_response = oauth2::HttpResponse::new(body);
        *oauth2_response.status_mut() =
            oauth2::http::StatusCode::from_u16(u16::from(response.status())).unwrap();
        for (key, value) in response.headers() {
            oauth2_response.headers_mut().insert(
                oauth2::http::HeaderName::from_str(&key.to_string()).unwrap(),
                oauth2::http::HeaderValue::from_str(value.to_str().unwrap()).unwrap(),
            );
        }
        oauth2_response
    }

    pub async fn send(
        &self,
        request: oauth2::HttpRequest,
    ) -> Result<oauth2::HttpResponse, Error<Collector>> {
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
