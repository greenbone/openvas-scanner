use std::{fmt::Display, time::Duration};

use scannerlib::{SQLITE_LIMIT_VARIABLE_NUMBER, models};
use sqlx::{Acquire, QueryBuilder, Row, SqlitePool, query};

#[derive(Debug, Clone)]
pub struct CustomerMessage<T> {
    kind: models::ResultType,
    image: Option<T>,
    msg: String,
    detail: Option<models::Detail>,
}

impl<T> CustomerMessage<T> {
    fn new(
        kind: models::ResultType,
        image: Option<T>,
        msg: String,
        detail: Option<models::Detail>,
    ) -> Self {
        Self {
            kind,
            image,
            msg,
            detail,
        }
    }

    pub fn log(image: Option<T>, msg: String, detail: Option<models::Detail>) -> Self {
        Self::new(models::ResultType::Log, image, msg, detail)
    }

    pub fn error(image: Option<T>, msg: String, detail: Option<models::Detail>) -> Self {
        Self::new(models::ResultType::Error, image, msg, detail)
    }
}

impl<T> CustomerMessage<T>
where
    T: Display + Clone,
{
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
            ip_address: None,
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

async fn retry_store<'a, T>(
    pool: &SqlitePool,
    id: &str,
    results: &'a [T],
) -> Result<(), sqlx::Error>
where
    T: 'a + Into<models::Result> + Clone,
{
    // Not configurable at purpose. This is a internal sqlite DB measurement and should not be up
    // to a customer to change.
    const MAX_RETRIES: u8 = 5;
    let mut retries = MAX_RETRIES;
    loop {
        match try_store(pool, id, results).await {
            Ok(_) => return Ok(()),
            Err(error) => {
                match &error {
                    // waiting for if let guards to get rid of unwrap ...
                    sqlx::Error::Database(database_error)
                        if database_error.code().is_some() && retries > 0 =>
                    {
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
                        if !known_codes.iter().any(|x| x == &code) {
                            return Err(error);
                        }

                        retries -= 1;
                        let seconds = (MAX_RETRIES - retries) as u64;
                        tracing::debug!(
                            id, 
                            MAX_RETRIES, 
                            sleep_seconds=seconds, 
                            %error, 
                            results=results.len(), 
                            "Retrying to store results.");
                        // also not configurable for the same reasons as max_tries;
                        tokio::time::sleep(Duration::from_secs(seconds)).await;
                    }
                    _ => return Err(error),
                }
            }
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
