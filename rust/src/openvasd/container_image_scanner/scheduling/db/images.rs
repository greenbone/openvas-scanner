use sqlx::{Row, SqlitePool, sqlite::SqliteRow};

use crate::{
    container_image_scanner::image::{Credential, ImageID},
    database::dao::{DAOError, DAOPromiseRef, Execute},
};

impl TryFrom<&SqliteRow> for Credential {
    type Error = DAOError;

    fn try_from(row: &SqliteRow) -> Result<Self, Self::Error> {
        let username: Option<String> = row.get("username");
        let password: Option<String> = row.get("password");
        match (username, password) {
            (None, None) => Err(DAOError::NotFound),
            (None, Some(_)) => Err(DAOError::Corrupt),
            (user, pass) => Ok(Credential {
                username: user.unwrap_or_default(),
                password: pass.unwrap_or_default(),
            }),
        }
    }
}
#[derive(Debug, Clone)]
pub struct SqliteImages<'o, T> {
    input: T,
    pool: &'o SqlitePool,
}

impl<'o, T> SqliteImages<'o, T> {
    pub fn new(pool: &'o SqlitePool, input: T) -> SqliteImages<'o, T> {
        SqliteImages { input, pool }
    }
}

impl<'o> Execute<Vec<(ImageID, Option<Credential>)>> for SqliteImages<'o, (usize, usize)> {
    fn exec<'a, 'b>(&'a self) -> DAOPromiseRef<'b, Vec<(ImageID, Option<Credential>)>>
    where
        'a: 'b,
    {
        Box::pin(async move {
            let (max_scanning, batch_size) = self.input;

            let mut tx = self.pool.begin().await?;
            let scan_limit = match max_scanning {
                0 => -1,
                max => {
                    let max = max as i64;
                    let current_scanning: (i64,) =
                        sqlx::query_as("SELECT COUNT(*) FROM images WHERE status = 'scanning'")
                            .fetch_one(&mut *tx)
                            .await?;
                    if current_scanning.0 >= max {
                        0
                    } else {
                        max - current_scanning.0
                    }
                }
            };
            if scan_limit == 0 {
                return Ok(vec![]);
            }
            let limit = match batch_size {
                0 => scan_limit,
                max if max > scan_limit as usize => scan_limit, // -1 will be usize::MAX
                max => max as i64,
            };

            let rows = sqlx::query(
                r#"
    SELECT i.id, i.image, c.username, c.password
    FROM images i
    LEFT JOIN credentials c ON i.id = c.id
    WHERE i.status = 'pending'
    LIMIT ?
    "#,
            )
            .bind(limit)
            .fetch_all(&mut *tx)
            .await?;
            let mut result = Vec::with_capacity(rows.len());
            for row in rows {
                let credentials = Credential::try_from(&row).ok();
                let id: ImageID = row.into();

                sqlx::query(
                    r#"
        UPDATE images
        SET status = 'scanning'
        WHERE id = ? AND image = ?
        "#,
                )
                .bind(id.id())
                .bind(id.image())
                .execute(&mut *tx)
                .await?;
                result.push((id, credentials));
            }
            tx.commit().await?;

            Ok(result)
        })
    }
}
