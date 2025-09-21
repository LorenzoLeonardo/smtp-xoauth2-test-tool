use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};

use directories::UserDirs;
use extio::Extio;
use oauth2::http::{Request, Response};

use crate::{error::OAuth2Error, http_client::HttpClient};

#[derive(Clone)]
pub struct ActualInterface {
    http_client: HttpClient,
    token_path: PathBuf,
    provider_path: PathBuf,
}

impl ActualInterface {
    pub fn new(http_client: HttpClient) -> Self {
        let token_path = UserDirs::new().unwrap();
        let mut token_path = token_path.home_dir().to_owned();
        token_path = token_path.join("token");
        fs::create_dir_all(token_path.as_path()).unwrap();

        let mut provider_path = std::env::current_exe().unwrap_or(PathBuf::from("."));
        provider_path = provider_path.join("endpoints");

        log::info!("Http Client used: {http_client}");
        Self {
            http_client,
            token_path,
            provider_path,
        }
    }
}

#[async_trait::async_trait]
impl Extio for ActualInterface {
    type Error = OAuth2Error;

    fn read_file(&self, path: &Path) -> Result<Vec<u8>, Self::Error> {
        let result = fs::read(path)?;
        Ok(result)
    }
    fn write_file(&self, path: &Path, data: &[u8]) -> Result<(), Self::Error> {
        let mut file = File::create(path)?;
        file.write_all(data)?;
        Ok(())
    }
    fn delete_file(&self, path: &Path) -> Result<(), Self::Error> {
        fs::remove_file(path)?;
        Ok(())
    }
    async fn http_request(&self, req: Request<Vec<u8>>) -> Result<Response<Vec<u8>>, Self::Error> {
        match &self.http_client {
            HttpClient::Curl(curl) => curl.send(req).await,
            HttpClient::Reqwest(reqwest) => reqwest.send(req).await,
        }
    }
}

pub trait ExtioExtended: Extio {
    fn token_path(&self) -> &PathBuf;
    fn provider_path(&self) -> &PathBuf;
}

impl ExtioExtended for ActualInterface {
    fn token_path(&self) -> &PathBuf {
        &self.token_path
    }

    fn provider_path(&self) -> &PathBuf {
        &self.provider_path
    }
}
