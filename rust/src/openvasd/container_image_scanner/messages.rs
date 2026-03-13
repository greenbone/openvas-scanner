use std::{fmt::Display, time::Duration};

use chrono::TimeDelta;
use scannerlib::models;

use crate::{
    container_image_scanner::{
        detection::OperatingSystem,
        image::Image,
        scheduling::db::{DBResults, DataBase},
    },
    database::dao::RetryExec,
};

#[derive(Debug, Clone)]
pub struct CustomerMessage<T> {
    kind: models::ResultType,
    image: Option<T>,
    digest: Option<T>,
    msg: String,
    detail: Option<models::Detail>,
}

impl<T> CustomerMessage<T> {
    fn new(
        kind: models::ResultType,
        image: Option<T>,
        digest: Option<T>,
        msg: String,
        detail: Option<models::Detail>,
    ) -> Self {
        Self {
            kind,
            image,
            digest,
            msg,
            detail,
        }
    }

    pub fn log(
        image: Option<T>,
        digest: Option<T>,
        msg: String,
        detail: Option<models::Detail>,
    ) -> Self {
        Self::new(models::ResultType::Log, image, digest, msg, detail)
    }

    pub fn error(image: Option<T>, msg: String, detail: Option<models::Detail>) -> Self {
        Self::new(models::ResultType::Error, image, None, msg, detail)
    }
}

#[derive(Debug, PartialEq, PartialOrd)]
pub enum DetailPair<'a> {
    OS(&'a OperatingSystem),
    OSCpe(&'a OperatingSystem),
    HostName(&'a Image),
    Architecture(&'a str),
    Packages(Vec<String>),
}

impl<'a> DetailPair<'a> {
    pub fn name(&self) -> String {
        match self {
            DetailPair::OS(_) => "best_os_txt",
            DetailPair::OSCpe(_) => "best_os_cpe",
            DetailPair::Architecture(_) => "ARCHITECTURE",
            DetailPair::Packages(_) => "PACKAGES",
            DetailPair::HostName(_) => "hostname",
        }
        .into()
    }

    pub fn value(&self) -> String {
        match self {
            DetailPair::OS(os) => format!("{} {}", os.name, os.version),
            DetailPair::Architecture(arch) => arch.to_string(),
            DetailPair::Packages(items) => items.join(","),
            DetailPair::OSCpe(os) => {
                // as requested by customer.
                format!(
                    "cpe:/o:{}:{}:{}::~~~~~{}",
                    os.name,
                    os.name,
                    os.version_id,
                    os.version
                        .chars()
                        .map(|x| match x {
                            x if x.is_ascii_alphanumeric() => x,
                            _ => '_',
                        })
                        .collect::<String>()
                )
            }
            DetailPair::HostName(image) => image.to_string(),
        }
    }

    pub fn source_name(&self) -> String {
        "image_digest".into()
    }

    pub fn source_description(&self) -> String {
        concat!(
            "The information is originating from the image (found in the ip-address field)",
            "If you decide to pull that image manually be aware that you have to remove `oci://`.",
            "For an example: `podman pull localhost/my_repo/my_image@sha256:cf8a7abda98821fd2d132c88c27328c3ee2cbbcd5d5ce6522c435aa1b6844859`"
        ).into()
    }
}

impl<'a> From<DetailPair<'a>> for models::Detail {
    fn from(value: DetailPair) -> Self {
        Self {
            name: value.name(),
            value: value.value(),
            source: models::Source {
                s_type: "openvasd/container-image-scanner".to_string(),
                name: value.source_name(),
                description: value.source_description(),
            },
        }
    }
}

impl<T> CustomerMessage<T>
where
    T: Display + Clone + Sync,
{
    pub fn host_start_end(image: T, digest: T, scan_duration: Duration) -> [Self; 2] {
        let end = chrono::Utc::now();
        let start = TimeDelta::from_std(scan_duration)
            .into_iter()
            .filter_map(|x| end.checked_sub_signed(x))
            .next()
            .unwrap_or(end);

        [
            Self::new(
                models::ResultType::HostStart,
                Some(image.clone()),
                Some(digest.clone()),
                start.to_rfc3339(),
                None,
            ),
            Self::new(
                models::ResultType::HostEnd,
                Some(image),
                Some(digest),
                end.to_rfc3339(),
                None,
            ),
        ]
    }

    pub fn host_detail(image: T, digest: T, detail: DetailPair) -> Self {
        Self::new(
            models::ResultType::HostDetail,
            Some(image),
            Some(digest),
            "Host Detail".into(),
            Some(detail.into()),
        )
    }

    pub async fn store(self, pool: &DataBase, scan_id: &str) {
        store(pool, scan_id, &[self]).await
    }
}

impl<T> From<CustomerMessage<T>> for models::Result
where
    T: Display,
{
    fn from(val: CustomerMessage<T>) -> Self {
        models::Result {
            id: 0, // id is set on storage
            r_type: val.kind,
            ip_address: val.digest.map(|x| x.to_string()),
            hostname: val.image.map(|x| x.to_string()),
            oid: Some("openvasd/container-image-scanner".to_owned()),
            port: None,
            protocol: None,
            message: Some(val.msg),
            detail: val.detail,
        }
    }
}

pub async fn store<'a, T>(pool: &DataBase, id: &str, results: &'a [T])
where
    T: 'a + Into<models::Result> + Clone + Sync,
{
    if let Err(error) = DBResults::new(pool, (id, results)).retry_exec().await {
        tracing::warn!(%error, id, amount_of_results=results.len(), "Scan results lost.");
    }
}

#[cfg(test)]
mod test {

    use crate::container_image_scanner::{
        detection::OperatingSystemDetector, messages::DetailPair,
    };

    #[tokio::test]
    async fn test_different_cpe() {
        let content = r#"
        Name="EulerOS"
        VERSION="2.0 (SP12)"
        ID="euleros"
        VERSION_ID="2.0"
        "#;
        let os = OperatingSystemDetector::from(content)
            .detect_operating_system()
            .await
            .unwrap();
        let content = r#"
        Name="EulerOS"
        VERSION="2.0 (SP12 x86_64)"
        ID="euleros"
        VERSION_ID="2.0"
        "#;
        let os_2 = OperatingSystemDetector::from(content)
            .detect_operating_system()
            .await
            .unwrap();
        assert_ne!(
            DetailPair::OSCpe(&os).value(),
            DetailPair::OSCpe(&os_2).value()
        )
    }
}
