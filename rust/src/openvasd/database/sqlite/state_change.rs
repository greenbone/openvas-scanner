// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use sqlx::{Row, query::QueryAs};
use std::collections::HashMap;

use scannerlib::models;
use sqlx::{
    FromRow, Sqlite,
    query::Query,
    sqlite::{SqliteArguments, SqliteRow},
};

pub(crate) fn status_query<'a>(id: i64) -> Query<'a, Sqlite, SqliteArguments> {
    sqlx::query(r#"
        SELECT created_at, start_time, end_time, host_dead, host_alive, host_queued, host_excluded, host_all, status
        FROM scans
        WHERE id = ?
        "#)
        .bind(id)
}

pub(crate) fn host_scanning_query<'a>(
    id: i64,
) -> QueryAs<'a, Sqlite, ScanningHost, SqliteArguments> {
    sqlx::query_as(
        r#"
        SELECT host_ip, progress
        FROM host_scanning
        WHERE id = ?
        "#,
    )
    .bind(id)
}

pub(crate) fn row_to_models_status(
    scan_row: SqliteRow,
    scanning_hosts_rows: Vec<ScanningHost>,
) -> models::Status {
    let excluded = scan_row.get("host_excluded");
    let dead = scan_row.get("host_dead");
    let alive = scan_row.get("host_alive");
    let finished = excluded + dead + alive;

    let host_progress: HashMap<String, i32> = scanning_hosts_rows
        .into_iter()
        .map(|sh| (sh.host_ip, sh.progress))
        .collect();

    let host_info = models::HostInfo {
        all: scan_row.get("host_all"),
        excluded,
        dead,
        alive,
        queued: scan_row.get("host_queued"),
        finished,
        scanning: Some(host_progress),
        remaining_vts_per_host: Default::default(),
    };
    models::Status {
        start_time: scan_row.get("start_time"),
        end_time: scan_row.get("end_time"),
        // should never fail as we just allow parseable values to be stored in the DB
        status: scan_row.get::<String, _>("status").parse().unwrap(),
        host_info: Some(host_info),
    }
}

#[derive(FromRow, Debug)]
pub struct ScanningHost {
    pub host_ip: String,
    pub progress: i32,
}
