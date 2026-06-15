use std::{collections::HashMap, str::FromStr};

use futures::StreamExt;
use sqlx::{Row, sqlite::SqliteRow};

use crate::{
    container_image_scanner::{
        image::{Credential, Image, ImageID, ImageParseError, ImageState},
        scheduling::ProcessingImage,
    },
    database::dao::{DAOError, DAOPromiseRef, Execute, Fetch},
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

pub type DBImages<'o, T> = super::DB<'o, T>;

impl From<SqliteRow> for ImageID {
    fn from(row: SqliteRow) -> Self {
        let id: i64 = row.get("id");
        Self {
            id: id.to_string(),
            image: row.get("image"),
        }
    }
}

impl<'o> Fetch<Option<ImageState>> for DBImages<'o, (&'o str, &'o Image)> {
    fn fetch<'a, 'b>(&'a self) -> DAOPromiseRef<'b, Option<ImageState>>
    where
        'a: 'b,
    {
        Box::pin(async move {
            let (id, image) = &self.input;
            let hdf = sqlx::query_scalar::<_, String>(
                "SELECT status FROM images WHERE id = ? AND image = ?",
            )
            .bind(id)
            .bind(image.to_string())
            .fetch_optional(self.pool)
            .await;
            match hdf {
                Ok(x) => Ok(x.map(|x| ImageState::from_str(&x).unwrap())),
                Err(err) => Err(DAOError::from(err)),
            }
        })
    }
}
impl<'o> Execute<()> for DBImages<'o, (&'o ImageID, ImageState)> {
    fn exec<'a, 'b>(&'a self) -> DAOPromiseRef<'b, ()>
    where
        'a: 'b,
    {
        Box::pin(async move {
            let (ids, status) = &self.input;
            sqlx::query(
                r#"
            UPDATE images
            SET status = ?
            WHERE id = ? AND image = ?"#,
            )
            .bind(status.as_ref())
            .bind(ids.id())
            .bind(ids.image())
            .execute(self.pool)
            .await
            .map_err(DAOError::from)
            .map(|_| ())
        })
    }
}

impl<'o> Execute<Vec<(ImageID, Option<Credential>)>> for DBImages<'o, (usize, usize)> {
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
                max if max > scan_limit as usize => scan_limit,
                max => max as i64,
            };

            let rows = sqlx::query(
                r#"
    SELECT i.id, i.image, c.username, c.password
    FROM images i
    JOIN scans s ON s.id = i.id
    LEFT JOIN credentials c ON i.id = c.id
    WHERE i.status = 'pending'
    ORDER BY s.host_finished ASC, s.id ASC, i.image ASC
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
impl<'o> Fetch<Vec<ProcessingImage>> for DBImages<'o, usize> {
    fn fetch<'a, 'b>(&'a self) -> DAOPromiseRef<'b, Vec<ProcessingImage>>
    where
        'a: 'b,
    {
        Box::pin(async move {
            let limit = if self.input == 0 {
                254
            } else {
                self.input as i64
            };
            let mut stream = sqlx::query(
                r#"
        WITH running_count AS (
            SELECT COUNT(*) AS running_total
            FROM scans
            WHERE status = 'running'
        ),
        selected_scans AS (
            SELECT id
            FROM scans
            WHERE status = 'requested'
            ORDER BY created_at ASC
            LIMIT (
                SELECT CASE
                    WHEN running_total < ? THEN 1
                    ELSE 0
                END
                FROM running_count
            )
        )
        SELECT 
            r.id,
            r.host AS registry,
            c.username,
            c.password
        FROM registry r
        JOIN selected_scans s
          ON r.id = s.id
        LEFT JOIN credentials c
          ON r.id = c.id
        "#,
            )
            .bind(limit)
            .fetch(self.pool);
            type ImageResult = Result<Image, ImageParseError>;

            let mut map: HashMap<i64, (Vec<ImageResult>, Option<Credential>)> = HashMap::new();

            while let Some(row_result) = stream.next().await {
                let row = match row_result {
                    Ok(x) => x,
                    Err(e) => {
                        unreachable!(
                            "Unreachable: SQL query failed despite static structure. Error: {}",
                            e
                        )
                    }
                };

                let registry: String = row.get("registry");
                let image = registry.parse();

                let id: i64 = row.get("id");
                let credential = Credential::try_from(&row).ok();

                let entry = map.entry(id).or_insert_with(|| (Vec::new(), credential));

                entry.0.push(image);
            }

            map.into_iter()
                .map(|(id, (image, credentials))| {
                    Ok(ProcessingImage {
                        id: id.to_string(),
                        image,
                        credentials,
                    })
                })
                .collect()
        })
    }
}

#[cfg(test)]
mod test {
    use std::{
        str::FromStr,
        sync::atomic::{AtomicU64, Ordering},
    };

    use scannerlib::models;

    use crate::{
        container_image_scanner::{
            endpoints::scans::scans_utils::Fakes,
            image::{Image, ImageState, RegistryError},
            scheduling::db::{images::DBImages, scan::DBScan},
        },
        database::dao::Execute,
    };

    static IMAGE_COUNTER: AtomicU64 = AtomicU64::new(0);
    static SCAN_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn image_url() -> String {
        format!(
            "oci://myregistry/myscan{}:my_tag{}",
            SCAN_COUNTER.load(Ordering::Relaxed),
            IMAGE_COUNTER.fetch_add(1, Ordering::Relaxed),
        )
    }

    fn generate_scan(image_amount: u64) -> models::Scan {
        models::Scan {
            scan_id: SCAN_COUNTER.fetch_add(1, Ordering::Relaxed).to_string(),
            target: models::Target {
                hosts: (0..image_amount).map(|_| image_url()).collect(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn select_next_images_based_on_the_scan_with_the_least_amount_of_host_finished() {
        let mut fakes = Fakes::init().await;
        let scans = [generate_scan(10), generate_scan(3), generate_scan(5)];
        let mut ids = Vec::with_capacity(scans.len());
        let pool = fakes.pool();
        for s in scans {
            let images: Vec<Result<Image, RegistryError>> = s
                .target
                .hosts
                .iter()
                .map(|x| Image::from_str(x as &str).map_err(|_| RegistryError::no_tag()))
                .collect();
            let scan_id = fakes.simulate_start_scan("me", s).await.0;
            let scan_id = fakes.internal_id("me", &scan_id).await;
            // insert all the images and set the corresponding status values for scan
            DBScan::new(&pool, (&scan_id as &str, &images as &[_]))
                .exec()
                .await
                .unwrap();
            ids.push(scan_id);
        }
        let validate = async |rounds, ids| {
            for _ in 0..rounds {
                for id in &ids {
                    let mut requested = DBImages::new(&pool, (0, 1)).exec().await.unwrap();
                    assert_eq!(requested.len(), 1);
                    let rid = requested.pop().unwrap().0;
                    assert_eq!(id, &rid.id);
                    // mark as failed to trigger host_finished trigger
                    DBImages::new(&pool, (&rid, ImageState::Failed))
                        .exec()
                        .await
                        .unwrap();
                }
            }
        };

        validate(3, ids.clone()).await;
        ids.remove(1);
        validate(2, ids.clone()).await;
        ids.remove(1);
        validate(5, ids.clone()).await;
    }
}
