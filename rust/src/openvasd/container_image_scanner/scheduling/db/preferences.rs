use futures::StreamExt;
use sqlx::{Row, SqlitePool, query};

use crate::database::dao::{DAOError, DAOStreamer, StreamFetch};

#[derive(Debug, Clone)]
pub struct SqlitePreferences<'o, T> {
    input: T,
    pool: &'o SqlitePool,
}

impl<'o, T> SqlitePreferences<'o, T> {
    pub fn new(pool: &'o SqlitePool, input: T) -> SqlitePreferences<'o, T> {
        SqlitePreferences { input, pool }
    }
}

impl<'o> StreamFetch<(String, String)> for SqlitePreferences<'o, String> {
    fn stream_fetch(self) -> DAOStreamer<(String, String)> {
        let result = query(
            r#"SELECT key, value
                FROM preferences
                WHERE id = ? "#,
        )
        .bind(self.input)
        .fetch(self.pool)
        .map(|row| {
            let row = row.map_err(DAOError::from)?;
            let key: String = row.get("key");
            let value: String = row.get("value");
            Ok((key, value))
        });
        Box::pin(result)
    }
}
