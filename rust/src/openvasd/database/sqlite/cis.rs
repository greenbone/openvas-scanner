// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use super::insert_values_chunked;
use crate::container_image_scanner::image::{Image, ImageState};
use scannerlib::models;
use std::str::FromStr;

impl super::SqliteDatabase {
    async fn cis_insert(&self, client_id: &str, scan: &models::Scan) -> anyhow::Result<i64> {
        let mut tx = self.pool.begin().await?;

        let scan_oid = self.scan_generic_insert(&mut tx, client_id, scan).await?;

        insert_values_chunked(
            &mut *tx,
            "INSERT INTO registry (id, host)",
            |mut b, registry| {
                b.push_bind(scan_oid).push_bind(registry);
            },
            &scan.target.hosts,
            2,
        )
        .await?;

        let excluded_images = scan
            .target
            .excluded_hosts
            .iter()
            .map(|image| {
                Image::from_str(image)
                    .map(|image| image.to_string())
                    .unwrap_or_else(|_| image.clone())
            })
            .collect::<Vec<_>>();

        insert_values_chunked(
            &mut *tx,
            "INSERT OR IGNORE INTO images (id, image, status)",
            |mut b, img| {
                b.push_bind(scan_oid)
                    .push_bind(img)
                    .push_bind(ImageState::Excluded.as_ref());
            },
            &excluded_images,
            3,
        )
        .await?;

        tx.commit().await?;
        Ok(scan_oid)
    }

    async fn cis_get(&self, scan_oid: i64) -> anyhow::Result<models::Scan> {
        let mut conn = self.pool.acquire().await?;

        let hosts: Vec<String> = sqlx::query_scalar("SELECT host FROM registry WHERE id = ?")
            .bind(scan_oid)
            .fetch_all(&mut *conn)
            .await?;

        let preferences: Vec<models::ScanPreference> =
            sqlx::query_as("SELECT key, value FROM preferences WHERE id = ?")
                .bind(scan_oid)
                .fetch_all(&mut *conn)
                .await?;

        let scan_id = sqlx::query_scalar("SELECT scan_id FROM client_scan_map WHERE id = ?")
            .bind(scan_oid)
            .fetch_one(&mut *conn)
            .await?;

        let auth_data: String = sqlx::query_scalar("SELECT auth_data FROM scans WHERE id = ?")
            .bind(scan_oid)
            .fetch_one(&mut *conn)
            .await?;

        // TODO: filter and verify in insert
        let credentials: Vec<models::Credential> = self.decrypt(&auth_data).await?;

        Ok(models::Scan {
            scan_id,
            target: models::Target {
                hosts,
                credentials,
                ..Default::default()
            },
            scan_preferences: preferences,
            ..Default::default()
        })
    }
}
