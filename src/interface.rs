use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};

use directories::UserDirs;
use extio::Extio;
use http::{Request, Response};

use crate::{curl::Curl, error::OAuth2Error};

#[derive(Clone)]
pub struct ActualInterface {
    curl: Curl,
    file_directory: PathBuf,
}

impl ActualInterface {
    pub fn new() -> Self {
        let file_directory = UserDirs::new().unwrap();
        let mut file_directory = file_directory.home_dir().to_owned();
        file_directory = file_directory.join("token");
        fs::create_dir_all(file_directory.as_path()).unwrap();

        Self {
            curl: Curl::new(),
            file_directory,
        }
    }
}

#[async_trait::async_trait]
impl Extio for ActualInterface {
    type Error = OAuth2Error;

    fn read_file(&self, path: &Path) -> Result<Vec<u8>, Self::Error> {
        let input_path = self.file_directory.join(path);
        let result = fs::read(input_path)?;
        Ok(result)
    }
    fn write_file(&self, path: &Path, data: &[u8]) -> Result<(), Self::Error> {
        let input_path = self.file_directory.join(path);
        let mut file = File::create(input_path)?;
        file.write_all(data)?;
        Ok(())
    }
    fn delete_file(&self, path: &Path) -> Result<(), Self::Error> {
        let input_path = self.file_directory.join(path);
        fs::remove_file(input_path)?;
        Ok(())
    }
    async fn http_request(&self, req: Request<Vec<u8>>) -> Result<Response<Vec<u8>>, Self::Error> {
        self.curl.send(req).await
    }
}
