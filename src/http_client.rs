pub mod curl;
pub mod reqwest;

use std::pin::Pin;

use extio::Extio;
use oauth2::{AsyncHttpClient, HttpRequest, HttpResponse};
use strum_macros::{Display, EnumString};

use crate::{
    error::OAuth2Error,
    http_client::{curl::Curl, reqwest::Reqwest},
};

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

#[derive(Clone, Display, EnumString)]
pub enum HttpClient {
    Curl(Curl),
    Reqwest(Reqwest),
}
