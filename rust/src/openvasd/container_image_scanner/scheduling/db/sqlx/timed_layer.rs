use crate::{
    container_image_scanner::benchy::{BenchType, Benched},
    database::dao::{DAOError, Execute, Fetch},
};

pub type DBTimedLayer<'o, T> = super::DB<'o, T>;

impl<'o> Execute<()> for DBTimedLayer<'o, (&'o str, &'o str, &'o Benched)> {
    fn exec<'a, 'b>(&'a self) -> crate::database::dao::DAOPromiseRef<'b, ()>
    where
        'a: 'b,
    {
        Box::pin(async move {
            let (scan_id, image, benched) = self.input;
            sqlx::query(
                r#"INSERT INTO timed_layer (scan_id, image, layer_index, kind, micro_seconds)
            VALUES(?, ?, ?, ?, ?)"#,
            )
            .bind(scan_id)
            .bind(image)
            .bind(benched.layer_index.map(|x| x as i64).unwrap_or_default())
            .bind(benched.kind.as_ref())
            .bind(benched.micro_seconds as i64)
            .execute(self.pool)
            .await
            .map(|_| ())
            .map_err(DAOError::from)
        })
    }
}

impl<'o> Fetch<Vec<Benched>> for DBTimedLayer<'o, (&'o str, &'o str)> {
    fn fetch<'a, 'b>(&'a self) -> crate::database::dao::DAOPromiseRef<'b, Vec<Benched>>
    where
        'a: 'b,
    {
        Box::pin(async move {
            use sqlx::Row;

            let (scan_id, image) = self.input;
            let result = sqlx::query(
                r#"SELECT layer_index, kind, micro_seconds
               FROM timed_layer
               WHERE scan_id = ? AND image = ? "#,
            )
            .bind(scan_id)
            .bind(image)
            .fetch_all(self.pool)
            .await?;
            Ok(result
                .iter()
                .map(|row| Benched {
                    kind: BenchType::from(row.get::<&str, _>("kind")),
                    // it's very unlikely that we ever reach the duration limit of i64
                    micro_seconds: row.get::<i64, _>("micro_seconds") as u128,
                    layer_index: Some(row.get::<i64, _>("layer_index") as usize),
                })
                .collect())
        })
    }
}
