use std::str::FromStr;

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

    fn to_curl_request(
        request: oauth2::HttpRequest,
    ) -> Result<http::Request<Option<Vec<u8>>>, OAuth2Error> {
        let body = if request.body().is_empty() {
            None
        } else {
            Some(request.body().to_owned())
        };
        let mut http_request = http::Request::new(body);

        *http_request.uri_mut() = http::Uri::from_str(&request.uri().to_string())?;
        *http_request.method_mut() = http::Method::from_str(request.method().as_ref())?;
        for (key, value) in request.headers() {
            http_request.headers_mut().insert(
                http::HeaderName::from_str(key.as_ref())?,
                http::HeaderValue::from_str(value.to_str()?)?,
            );
        }
        Ok(http_request)
    }

    fn to_oauth_response(
        response: http::Response<Option<Vec<u8>>>,
    ) -> Result<oauth2::HttpResponse, OAuth2Error> {
        let body = if let Some(body) = response.body().to_owned() {
            body
        } else {
            Vec::new()
        };
        let mut oauth2_response = oauth2::HttpResponse::new(body);
        *oauth2_response.status_mut() =
            oauth2::http::StatusCode::from_u16(u16::from(response.status()))?;
        for (key, value) in response.headers() {
            oauth2_response.headers_mut().insert(
                oauth2::http::HeaderName::from_str(key.as_ref())?,
                oauth2::http::HeaderValue::from_str(value.to_str()?)?,
            );
        }
        Ok(oauth2_response)
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
            .request(Curl::to_curl_request(request)?)?
            .nonblocking(self.actor_handle.clone())
            .perform()
            .await
            .map(Curl::to_oauth_response)??;

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
