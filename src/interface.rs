use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};

use directories::UserDirs;
use extio::Extio;
use oauth2::http::{Request, Response};

use crate::{error::OAuth2Error, http_client::curl::Curl};

#[derive(Clone)]
pub struct ActualInterface {
    curl: Curl,
    token_path: PathBuf,
}

impl ActualInterface {
    pub fn new() -> Self {
        let token_path = UserDirs::new().unwrap();
        let mut token_path = token_path.home_dir().to_owned();
        token_path = token_path.join("token");
        fs::create_dir_all(token_path.as_path()).unwrap();

        Self {
            curl: Curl::new(),
            token_path,
        }
    }
}

#[async_trait::async_trait]
impl Extio for ActualInterface {
    type Error = OAuth2Error;

    fn read_file(&self, path: &Path) -> Result<Vec<u8>, Self::Error> {
        let input_path = self.token_path.join(path);
        let result = fs::read(input_path)?;
        Ok(result)
    }
    fn write_file(&self, path: &Path, data: &[u8]) -> Result<(), Self::Error> {
        let input_path = self.token_path.join(path);
        let mut file = File::create(input_path)?;
        file.write_all(data)?;
        Ok(())
    }
    fn delete_file(&self, path: &Path) -> Result<(), Self::Error> {
        let input_path = self.token_path.join(path);
        fs::remove_file(input_path)?;
        Ok(())
    }
    async fn http_request(&self, req: Request<Vec<u8>>) -> Result<Response<Vec<u8>>, Self::Error> {
        self.curl.send(req).await
    }
}
