use futures::StreamExt;
use sqlx::{Row, query};

use crate::database::dao::{DAOError, DAOStreamer, StreamFetch};

pub type DBPreferences<'o, T> = super::DB<'o, T>;

impl<'o> StreamFetch<(String, String)> for DBPreferences<'o, String> {
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
