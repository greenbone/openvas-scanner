use std::{fmt::Display, time::Duration};

use chrono::TimeDelta;
use scannerlib::{SQLITE_LIMIT_VARIABLE_NUMBER, models};
use sqlx::{Acquire, QueryBuilder, Row, SqlitePool, query};

use crate::container_image_scanner::{detection::OperatingSystem, image::Image};

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
                format!("cpe:/o:{}:{}:{}", os.name, os.name, os.version_id)
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
    T: Display + Clone,
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

    pub async fn store(self, pool: &SqlitePool, scan_id: &str) {
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

pub async fn store<'a, T>(pool: &SqlitePool, id: &str, results: &'a [T])
where
    T: 'a + Into<models::Result> + Clone,
{
    if let Err(error) = retry_store(pool, id, results).await {
        tracing::warn!(%error, id, amount_of_results=results.len(), "Scan results lost.");
    }
}

pub struct SqliteRetry {
    retries: u8,
}

impl Default for SqliteRetry {
    fn default() -> Self {
        Self {
            retries: Self::MAX_RETRIES,
        }
    }
}

impl SqliteRetry {
    // Not configurable at purpose. This is a internal sqlite DB measurement and should not be up
    // to a customer to change.
    pub const MAX_RETRIES: u8 = 5;
    pub fn error_is_retryable(error: &sqlx::Error) -> bool {
        match &error {
            // waiting for if let guards to get rid of unwrap ...
            sqlx::Error::Database(database_error) if database_error.code().is_some() => {
                let code: i64 = database_error
                    .code()
                    .map(|x| x.parse())
                    .filter(|x| x.is_ok())
                    .map(|x| x.unwrap())
                    .unwrap_or_default();
                let known_codes = [
                    5,   // https://sqlite.org/rescode.html#busy
                    6,   // https://sqlite.org/rescode.html#locked
                    513, // https://sqlite.org/rescode.html#error_retry
                    517, // https://sqlite.org/rescode.html#busy_snapshot
                    773, // https://sqlite.org/rescode.html#busy_timeout
                ];
                known_codes.iter().any(|x| x == &code)
            }
            _ => false,
        }
    }
    pub fn is_retryable(&mut self, error: &sqlx::Error) -> bool {
        self.retries -= 1;
        self.retries > 0 && Self::error_is_retryable(error)
    }

    pub fn calculate_sleep(&self) -> Duration {
        Self::calculate_sleep_based_on(self.retries)
    }

    pub fn calculate_sleep_based_on(retries: u8) -> Duration {
        let seconds = (Self::MAX_RETRIES - retries) as u64;
        Duration::from_secs(seconds)
    }
}

async fn retry_store<'a, T>(
    pool: &SqlitePool,
    id: &str,
    results: &'a [T],
) -> Result<(), sqlx::Error>
where
    T: 'a + Into<models::Result> + Clone,
{
    let mut retry = SqliteRetry::default();
    loop {
        match try_store(pool, id, results).await {
            Ok(_) => return Ok(()),
            Err(error) if retry.is_retryable(&error) => {
                tracing::debug!(
                            id,
                            %error,
                            results=results.len(),
                            "Retrying to store results.");
                // also not configurable for the same reasons as max_tries;

                tokio::time::sleep(retry.calculate_sleep()).await;
            }
            Err(error) => return Err(error),
        }
    }
}
async fn try_store<'a, T>(pool: &SqlitePool, id: &str, results: &'a [T]) -> Result<(), sqlx::Error>
where
    T: 'a + Into<models::Result> + Clone,
{
    if results.is_empty() {
        return Ok(());
    }
    let mut conn = pool.acquire().await?;
    let mut tx = conn.begin().await?;
    let base_id = match query(
        r#"
                SELECT COUNT(*) AS result_count
                FROM results
                WHERE scan_id = ? "#,
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    {
        Ok(x) => x.get::<i64, _>("result_count"),
        Err(sqlx::Error::RowNotFound) => 0,
        Err(e) => {
            return Err(e);
        }
    };
    tracing::trace!(id, base_id, "Results.");
    let mut builder = QueryBuilder::new(
        r#"
            INSERT INTO results (
                scan_id,
                id,
                type,
                ip_address,
                hostname,
                oid,
                port,
                protocol,
                message,
                detail_name,
                detail_value,
                source_type,
                source_name,
                source_description
            )
            "#,
    );

    for results in results.chunks(SQLITE_LIMIT_VARIABLE_NUMBER / 14) {
        builder.push_values(results.iter().enumerate(), |mut b, (idx, result)| {
            let result: models::Result = result.to_owned().into();
            let detail = result.detail.unwrap_or_default();
            b.push_bind(id)
                .push_bind(idx as i64 + base_id)
                .push_bind(result.r_type.to_string())
                .push_bind(result.ip_address.unwrap_or_default())
                .push_bind(result.hostname.unwrap_or_default())
                .push_bind(result.oid.unwrap_or_default())
                .push_bind(result.port.unwrap_or_default())
                .push_bind(result.protocol.map(|x| x.to_string()).unwrap_or_default())
                .push_bind(result.message.unwrap_or_default())
                .push_bind(detail.name)
                .push_bind(detail.value)
                .push_bind(detail.source.s_type)
                .push_bind(detail.source.name)
                .push_bind(detail.source.description);
        });

        let query = builder.build();
        query.execute(&mut *tx).await?;
    }

    tx.commit().await?;

    Ok(())
}
