use std::pin::Pin;

use futures::StreamExt;
use greenbone_scanner_framework::InternalIdentifier;
use scannerlib::models::{self, Scan};

use sqlx::{Acquire, QueryBuilder, Row, SqlitePool, query, sqlite::SqliteRow};

use crate::{
    container_image_scanner::image::{Image, ImageState},
    database::dao::{
        DAOError, DAOPromise, DAOPromiseRef, DAOResult, DAOStreamer, Fetch, Insert, StreamFetch,
    },
};

#[derive(Debug, Clone)]
pub struct SqliteScan<'o, C, T> {
    client_id: C,
    scan: T,
    pool: &'o SqlitePool,
}

impl<'o, C, T> SqliteScan<'o, C, T> {
    pub fn new(client_id: C, scan: T, pool: &'o SqlitePool) -> SqliteScan<'o, C, T> {
        SqliteScan {
            client_id,
            scan,
            pool,
        }
    }
}

impl<'o> Insert for SqliteScan<'o, &str, &Scan> {
    fn insert<'a, 'b>(&'a self) -> DAOPromiseRef<'b, ()>
    where
        'a: 'b,
    {
        Box::pin(async move {
            let scan = &self.scan;
            let mut conn = self.pool.acquire().await?;
            let mut tx = conn.begin().await?;
            let row = query(
                r#"
            INSERT INTO client_scan_map(scan_id, client_id) VALUES (?, ?)
            "#,
            )
            .bind(&scan.scan_id)
            .bind(self.client_id)
            .execute(&mut *tx)
            .await?;
            let id = row.last_insert_rowid();
            let _ = query("INSERT INTO scans(id) VALUES (?)")
                .bind(id)
                .execute(&mut *tx)
                .await?;
            tracing::debug!(internal_id = id, "creating scan");
            if !scan.target.hosts.is_empty() {
                let mut builder = QueryBuilder::new("INSERT INTO registry (id, host) ");
                builder.push_values(&scan.target.hosts, |mut b, registry| {
                    b.push_bind(id).push_bind(registry);
                });
                let query = builder.build();
                query.execute(&mut *tx).await?;
            }
            if !scan.target.credentials.is_empty() {
                let mut builder =
                    QueryBuilder::new("INSERT INTO credentials (id, username, password) ");
                builder.push_values(
                    scan.target
                        .credentials
                        .iter()
                        .filter_map(|c| match &c.credential_type {
                            models::CredentialType::UP {
                                username,
                                password,
                                privilege: _,
                            } => Some((username, password)),
                            _ => None,
                        }),
                    |mut b, (username, password)| {
                        b.push_bind(id).push_bind(username).push_bind(password);
                    },
                );
                let query = builder.build();
                query.execute(&mut *tx).await?;
            }
            if !scan.scan_preferences.is_empty() {
                let mut builder = QueryBuilder::new("INSERT INTO preferences (id, key, value) ");
                builder.push_values(&scan.scan_preferences, |mut b, pref| {
                    b.push_bind(id).push_bind(&pref.id).push_bind(&pref.value);
                });
                let query = builder.build();
                query.execute(&mut *tx).await?;
            }
            Image::insert(
                &mut tx,
                id,
                ImageState::Excluded,
                scan.target.excluded_hosts.clone(),
            )
            .await?;
            tx.commit().await?;
            Ok(())
        })
    }
}

impl<'o> Fetch<Option<InternalIdentifier>> for SqliteScan<'o, &str, &str> {
    fn fetch<'a, 'b>(&'a self) -> DAOPromiseRef<'b, Option<InternalIdentifier>>
    where
        'a: 'b,
    {
        Box::pin(async move {
            let x = query("SELECT id FROM client_scan_map WHERE client_id = ? AND scan_id = ?")
                .bind(self.client_id)
                .bind(self.scan)
                .fetch_optional(self.pool)
                .await?;
            Ok(x.map(|r| r.get::<i64, _>("id")).map(|x| x.to_string()))
        })
    }
}

impl<'o> StreamFetch<String> for SqliteScan<'o, String, ()> {
    fn stream_fetch(self) -> DAOStreamer<String> {
        let result = query(
            r#"
                SELECT scan_id FROM client_scan_map WHERE client_id = ?
            "#,
        )
        .bind(self.client_id)
        .fetch(self.pool)
        .map(|x| {
            x.map(|x| x.get::<String, _>("scan_id"))
                .map_err(|_| DAOError::Infrastructure)
        });
        Box::pin(result)
    }
}
