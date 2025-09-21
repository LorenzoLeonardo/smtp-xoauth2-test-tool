use oauth2::{HttpRequest, HttpResponse, http::Response};
use reqwest::Client;

use crate::error::OAuth2Error;

#[derive(Clone)]
pub struct Reqwest {
    client: Client,
}

impl Default for Reqwest {
    fn default() -> Self {
        Self {
            client: Client::new(),
        }
    }
}

impl Reqwest {
    pub async fn send(&self, request: HttpRequest) -> Result<HttpResponse, OAuth2Error> {
        log::debug!("Request Url: {}", request.uri());
        log::debug!("Request Header: {:?}", request.headers());
        log::debug!("Request Method: {}", request.method());
        log::debug!("Request Body: {}", String::from_utf8_lossy(request.body()));

        // Build the Reqwest request
        let mut req_builder = self
            .client
            .request(request.method().clone(), request.uri().to_string())
            .body(request.body().clone());

        // Copy headers
        for (name, value) in request.headers().iter() {
            req_builder = req_builder.header(name, value);
        }

        // Send request
        let resp = req_builder.send().await?;

        // Extract parts for oauth2::HttpResponse
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = resp.bytes().await?.to_vec();

        log::debug!("Response Status: {status}");
        log::debug!("Response Header: {headers:?}");
        log::debug!("Response Body: {}", String::from_utf8_lossy(&body));

        // Build http::Response
        let mut builder = Response::builder().status(status);

        // Insert headers
        for (name, value) in headers.iter() {
            builder = builder.header(name, value);
        }

        Ok(builder.body(body)?)
    }
}
