use std::fmt::Display;

use thiserror::Error;
use tokio::{
    fs::File,
    io::{AsyncBufRead, AsyncBufReadExt, BufReader},
};

use crate::container_image_scanner::{
    ExternalError,
    image::extractor::{Locator, LocatorError},
};

#[derive(Debug)]
pub struct OperatingSystem {
    pub name: String,
    pub version: String,
    pub version_id: String,
}

impl Display for OperatingSystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "name: '{}', version_id: '{}'",
            self.name, self.version_id
        )
    }
}

#[derive(Error, Debug)]
enum OperatingSystemDetectionError {
    #[error("Failed to read the operating system file")]
    ReadError(#[from] std::io::Error),
    #[error("Unknown operating system")]
    Unknown,
}

pub const OS_FILES: &[&str] = &["etc/os-release", "usr/lib/os-release"];

pub async fn operating_system<T>(locator: &T) -> Result<OperatingSystem, ExternalError>
where
    T: Locator,
{
    for path in OS_FILES {
        let path = match locator.locate(path).await {
            Ok(x) => x,
            Err(LocatorError::NotFound(_)) => continue,
            Err(x) => return Err(x.into()),
        };
        let osd = OperatingSystemDetector::new(path.open().await);
        let os = osd.detect_operating_system().await?;
        return Ok(os);
    }
    Err(LocatorError::NotFound("No operating system definition".to_owned()).into())
}

struct OperatingSystemDetector<T> {
    reader: T,
}

impl<T> OperatingSystemDetector<T>
where
    T: AsyncBufRead + Unpin,
{
    fn new(reader: T) -> Self {
        OperatingSystemDetector { reader }
    }

    async fn detect_operating_system(
        self,
    ) -> Result<OperatingSystem, OperatingSystemDetectionError> {
        let mut lines = self.reader.lines();
        let mut os_name = None;
        let mut os_version_id = None;
        let mut os_version = None;

        while let Ok(Some(line)) = lines.next_line().await {
            let line = line.trim();
            if line.starts_with("ID=") {
                os_name = Some(
                    line.split('=')
                        .nth(1)
                        .unwrap_or("")
                        .trim_matches('"')
                        .to_string(),
                );
            }
            if line.starts_with("VERSION_ID=") {
                os_version_id = Some(
                    line.split('=')
                        .nth(1)
                        .unwrap_or("")
                        .trim_matches('"')
                        .to_string(),
                );
            }
            if line.starts_with("VERSION=") {
                os_version = Some(
                    line.split('=')
                        .nth(1)
                        .unwrap_or("")
                        .trim_matches('"')
                        .to_string(),
                );
            }
        }
        if os_name.is_none() || os_version_id.is_none() || os_version.is_none() {
            return Err(OperatingSystemDetectionError::Unknown);
        }
        Ok(OperatingSystem {
            name: os_name.unwrap(),
            version_id: os_version_id.unwrap(),
            version: os_version.unwrap(),
        })
    }
}

impl OperatingSystemDetector<BufReader<File>> {
    #[cfg(test)]
    async fn try_open<T>(root: T) -> Result<Self, std::io::Error>
    where
        T: AsRef<std::path::Path>,
    {
        let file = File::open(root).await?;

        let reader = BufReader::new(file);
        Ok(OperatingSystemDetector { reader })
    }
}

impl From<&'static str> for OperatingSystemDetector<&[u8]> {
    fn from(content: &'static str) -> Self {
        let reader = content.as_bytes();
        OperatingSystemDetector { reader }
    }
}

#[cfg(test)]
mod test {

    use tokio::{fs::File, io::AsyncWriteExt};

    use crate::container_image_scanner::detection::OperatingSystemDetector;

    #[tokio::test]
    async fn test_os_detection_ubuntu() {
        let content = r#"PRETTY_NAME="Ubuntu 24.04.2 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.2 LTS (Noble Numbat)"
VERSION_CODENAME=noble
ID=ubuntu
ID_LIKE=debian"#;
        let detector = OperatingSystemDetector::from(content);
        let os = detector.detect_operating_system().await.unwrap();
        assert_eq!(os.name, "ubuntu");
        assert_eq!(os.version_id, "24.04");
    }

    #[tokio::test]
    async fn test_os_detection_debian() {
        let content = r#"PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
    NAME="Debian GNU/Linux"
    VERSION_ID="12"
    VERSION="12 (bookworm)"
    VERSION_CODENAME=bookworm
    ID=debian"#;
        // let os = OperatingSystem::detect(&fs).await.unwrap();
        let detector = OperatingSystemDetector::from(content);
        let os = detector.detect_operating_system().await.unwrap();
        assert_eq!(os.name, "debian");
        assert_eq!(os.version_id, "12");
    }

    #[tokio::test]
    async fn test_os_detection_open_euler() {
        let content = r#"NAME="openEuler"
    VERSION="24.03 (LTS-SP1)"
    ID="openEuler"
    VERSION_ID="24.03"
    PRETTY_NAME="openEuler 24.03 (LTS-SP1)""#;
        let detector = OperatingSystemDetector::from(content);
        let os = detector.detect_operating_system().await.unwrap();
        assert_eq!(os.name, "openEuler");
        assert_eq!(os.version_id, "24.03");
        assert_eq!(os.version, "24.03 (LTS-SP1)");
    }

    #[tokio::test]
    async fn test_os_detection_from_file() {
        let content = r#"PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
    NAME="Debian GNU/Linux"
    VERSION_ID="12"
    VERSION="12 (bookworm)"
    VERSION_CODENAME=bookworm
    ID=debian"#;
        let mut file = File::create("/tmp/os-release").await.unwrap();
        file.write_all(content.as_bytes()).await.unwrap();
        let detector = OperatingSystemDetector::try_open("/tmp/os-release")
            .await
            .unwrap();
        let os = detector.detect_operating_system().await.unwrap();
        assert_eq!(os.name, "debian");
        assert_eq!(os.version_id, "12");
        assert_eq!(os.version, "12 (bookworm)");
    }
}
