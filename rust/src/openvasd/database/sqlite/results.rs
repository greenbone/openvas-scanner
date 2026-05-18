use futures::StreamExt;
use scannerlib::models;
use sqlx::{Acquire, Row, SqlitePool, sqlite::SqliteRow};

use crate::database::{
    dao::{DAOError, DAOPromiseRef, DAOStreamer, Execute, Fetch, StreamFetch},
    sqlite::insert_values_chunked,
};
fn row_to_result(row: SqliteRow) -> models::Result {
    let detail = match (
        row.try_get::<Option<String>, _>("detail_name")
            .unwrap_or(None),
        row.try_get::<Option<String>, _>("detail_value")
            .unwrap_or(None),
        row.try_get::<Option<String>, _>("source_type")
            .unwrap_or(None),
        row.try_get::<Option<String>, _>("source_name")
            .unwrap_or(None),
        row.try_get::<Option<String>, _>("source_description")
            .unwrap_or(None),
    ) {
        (Some(name), Some(value), Some(s_type), Some(name_src), Some(description)) => {
            Some(models::Detail {
                name,
                value,
                source: models::Source {
                    s_type,
                    name: name_src,
                    description,
                },
            })
        }
        _ => None,
    };
    let r_type = row
        .get::<String, _>("type")
        .parse::<models::ResultType>()
        .unwrap_or_default();

    models::Result {
        id: row.get::<i64, _>("id") as usize,
        r_type,
        ip_address: row
            .try_get::<Option<String>, _>("ip_address")
            .unwrap_or(None),
        hostname: row.try_get::<Option<String>, _>("hostname").unwrap_or(None),
        oid: row.try_get::<Option<String>, _>("oid").unwrap_or(None),
        port: row.try_get::<Option<i16>, _>("port").unwrap_or(None),
        protocol: row
            .try_get::<Option<String>, _>("protocol")
            .unwrap_or(None)
            .and_then(|s| s.parse::<models::Protocol>().ok()),
        message: row.try_get::<Option<String>, _>("message").unwrap_or(None),
        detail,
    }
}

#[derive(Debug, Clone)]
pub struct DBResults<'o, T> {
    input: T,
    pool: &'o SqlitePool,
}

impl<'o, T> DBResults<'o, T> {
    pub fn new(pool: &'o SqlitePool, input: T) -> DBResults<'o, T> {
        DBResults { input, pool }
    }
}

impl<'o> StreamFetch<models::Result> for DBResults<'o, (String, Option<usize>, Option<usize>)> {
    fn stream_fetch(self) -> DAOStreamer<models::Result> {
        let (id, from, to) = self.input;
        const SQL_BASE: &str = r#"
    SELECT id, type, ip_address, hostname, oid, port, protocol, message,
        detail_name, detail_value, source_type, source_name, source_description
    FROM results
    WHERE scan_id = ?
"#;

        const SQL_BASE_AND_GTE: &str = r#"
    SELECT id, type, ip_address, hostname, oid, port, protocol, message,
        detail_name, detail_value, source_type, source_name, source_description
    FROM results
    WHERE scan_id = ? AND id >= ?
"#;

        const SQL_BASE_AND_LTE: &str = r#"
    SELECT id, type, ip_address, hostname, oid, port, protocol, message,
        detail_name, detail_value, source_type, source_name, source_description
    FROM results
    WHERE scan_id = ? AND id <= ?
"#;

        const SQL_BASE_AND_GTE_LTE: &str = r#"
    SELECT id, type, ip_address, hostname, oid, port, protocol, message,
        detail_name, detail_value, source_type, source_name, source_description
    FROM results
    WHERE scan_id = ? AND id >= ? AND id <= ?
"#;

        let sql: &'static str = match (from, to) {
            (None, None) => SQL_BASE,
            (Some(_), None) => SQL_BASE_AND_GTE,
            (None, Some(_)) => SQL_BASE_AND_LTE,
            (Some(_), Some(_)) => SQL_BASE_AND_GTE_LTE,
        };
        let mut query = sqlx::query(sql).bind(id);

        if let Some(from_id) = from {
            query = query.bind(from_id as i64);
        }
        if let Some(to_id) = to {
            query = query.bind(to_id as i64);
        }

        let result = query
            .fetch(self.pool)
            .map(|x| x.map(row_to_result).map_err(DAOError::from));
        Box::pin(result)
    }
}

impl<'o> Fetch<models::Result> for DBResults<'o, (String, usize)> {
    fn fetch<'a, 'b>(&'a self) -> DAOPromiseRef<'b, models::Result>
    where
        'a: 'b,
    {
        {
            const SQL: &str = r#"
    SELECT id, type, ip_address, hostname, oid, port, protocol, message,
        detail_name, detail_value, source_type, source_name, source_description
    FROM results
    WHERE scan_id = ? AND id = ?
"#;

            Box::pin(async move {
                let (id, result_id) = &self.input;
                sqlx::query(SQL)
                    .bind(id)
                    .bind(*result_id as i64)
                    .fetch_one(self.pool)
                    .await
                    .map(row_to_result)
                    .map_err(DAOError::from)
            })
        }
    }
}

impl<'o, T> Execute<()> for DBResults<'o, (&'o str, &'o [T])>
where
    T: 'o + Sync + Into<models::Result> + Clone,
{
    fn exec<'a, 'b>(&'a self) -> DAOPromiseRef<'b, ()>
    where
        'a: 'b,
    {
        Box::pin(async move {
            let (id, results) = &self.input;
            try_store(self.pool, id, results)
                .await
                .map_err(DAOError::from)
        })
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
    let base_id = match sqlx::query(
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
    let results = results
        .iter()
        .enumerate()
        .map(|(idx, result)| (base_id + idx as i64, result.to_owned().into()))
        .collect::<Vec<(i64, models::Result)>>();

    insert_values_chunked(
        &mut *tx,
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
        |mut b, (result_id, result)| {
            let detail = result.detail.clone().unwrap_or_default();
            b.push_bind(id)
                .push_bind(*result_id)
                .push_bind(result.r_type.to_string())
                .push_bind(result.ip_address.clone().unwrap_or_default())
                .push_bind(result.hostname.clone().unwrap_or_default())
                .push_bind(result.oid.clone().unwrap_or_default())
                .push_bind(result.port.unwrap_or_default())
                .push_bind(result.protocol.map(|x| x.to_string()).unwrap_or_default())
                .push_bind(result.message.clone().unwrap_or_default())
                .push_bind(detail.name)
                .push_bind(detail.value)
                .push_bind(detail.source.s_type)
                .push_bind(detail.source.name)
                .push_bind(detail.source.description);
        },
        &results,
        14,
    )
    .await?;

    tx.commit().await?;

    Ok(())
}
