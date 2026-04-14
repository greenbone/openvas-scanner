use futures::StreamExt;
use scannerlib::{SQLITE_LIMIT_VARIABLE_NUMBER, models};
use sqlx::{Acquire, QueryBuilder, Row, SqlitePool, sqlite::SqliteRow};

use crate::database::dao::{DAOError, DAOPromiseRef, DAOStreamer, Execute, Fetch, StreamFetch};
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
    let mut offset = base_id;
    for results in results.chunks(SQLITE_LIMIT_VARIABLE_NUMBER / 14) {
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
        builder.push_values(results.iter().enumerate(), |mut b, (idx, result)| {
            let result: models::Result = result.to_owned().into();
            let detail = result.detail.unwrap_or_default();
            b.push_bind(id)
                .push_bind(idx as i64 + offset)
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
        offset += results.len() as i64;
    }

    tx.commit().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scans::tests::create_pool;
    use sqlx::query_scalar;

    async fn insert_test_scan(pool: &SqlitePool) -> String {
        let row = sqlx::query("INSERT INTO client_scan_map(client_id, scan_id) VALUES (?, ?)")
            .bind("test-client")
            .bind("test-scan-id")
            .execute(pool)
            .await
            .unwrap();
        let id = row.last_insert_rowid();
        sqlx::query("INSERT INTO scans (id, auth_data) VALUES (?, ?)")
            .bind(id)
            .bind("")
            .execute(pool)
            .await
            .unwrap();
        id.to_string()
    }

    fn make_results(n: usize) -> Vec<models::Result> {
        (0..n)
            .map(|i| models::Result {
                message: Some(format!("result-{i}")),
                ..Default::default()
            })
            .collect()
    }

    #[tokio::test]
    async fn store_single_chunk() -> crate::Result<()> {
        let (_config, pool) = create_pool().await?;
        let scan_id = insert_test_scan(&pool).await;

        let results = make_results(10);
        try_store(&pool, &scan_id, &results).await?;

        let count: i64 = query_scalar("SELECT COUNT(*) FROM results WHERE scan_id = ?")
            .bind(&scan_id)
            .fetch_one(&pool)
            .await?;
        assert_eq!(count, 10);

        let ids: Vec<i64> = query_scalar("SELECT id FROM results WHERE scan_id = ? ORDER BY id")
            .bind(&scan_id)
            .fetch_all(&pool)
            .await?;
        assert_eq!(ids, (0..10).collect::<Vec<i64>>());

        Ok(())
    }

    #[tokio::test]
    async fn store_multi_chunk_ids_are_sequential() -> crate::Result<()> {
        let (_config, pool) = create_pool().await?;
        let scan_id = insert_test_scan(&pool).await;

        let chunk_size = SQLITE_LIMIT_VARIABLE_NUMBER / 14;
        let n = chunk_size + 1;
        let results = make_results(n);
        try_store(&pool, &scan_id, &results).await?;

        let count: i64 = query_scalar("SELECT COUNT(*) FROM results WHERE scan_id = ?")
            .bind(&scan_id)
            .fetch_one(&pool)
            .await?;
        assert_eq!(count, n as i64);

        let ids: Vec<i64> = query_scalar("SELECT id FROM results WHERE scan_id = ? ORDER BY id")
            .bind(&scan_id)
            .fetch_all(&pool)
            .await?;
        let expected: Vec<i64> = (0..n as i64).collect();
        assert_eq!(ids, expected);

        Ok(())
    }

    #[tokio::test]
    async fn append_results_continues_ids() -> crate::Result<()> {
        let (_config, pool) = create_pool().await?;
        let scan_id = insert_test_scan(&pool).await;

        let first_batch = make_results(100);
        try_store(&pool, &scan_id, &first_batch).await?;

        let second_batch = make_results(50);
        try_store(&pool, &scan_id, &second_batch).await?;

        let count: i64 = query_scalar("SELECT COUNT(*) FROM results WHERE scan_id = ?")
            .bind(&scan_id)
            .fetch_one(&pool)
            .await?;
        assert_eq!(count, 150);

        let ids: Vec<i64> = query_scalar("SELECT id FROM results WHERE scan_id = ? ORDER BY id")
            .bind(&scan_id)
            .fetch_all(&pool)
            .await?;
        let expected: Vec<i64> = (0..150).collect();
        assert_eq!(ids, expected);

        Ok(())
    }
}
