// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use super::error::{Result, SmbError};
use smb::{
    AdditionalInfo, Client, ClientConfig, FileAccessMask, FileCreateArgs, Resource, UncPath,
};
use std::{
    collections::{HashMap, HashSet},
    io::Cursor,
};
use tokio::sync::{Mutex, MutexGuard};

use binrw::BinWrite;
type BorrowedHandle<'a> = MutexGuard<'a, SmbHandle>;
pub type HandleId = i32;

pub const MIN_HANDLE_ID: HandleId = 9000;

#[derive(Default)]
pub struct SmbHandle {
    /// SMB Client
    handle: Client,
    target_path: Option<UncPath>,
}

impl SmbHandle {
    pub async fn new(
        server: String,
        share: String,
        username: String,
        password: String,
    ) -> Result<Self> {
        let mut config = ClientConfig::default();
        config.connection.auth_methods.ntlm = true;

        let handle = Client::new(config);
        let target_path = UncPath::new(&server)
            .map_err(SmbError::from)?
            .with_share(share.as_str())
            .map_err(SmbError::from)?;

        handle
            .share_connect(&target_path, &username, password)
            .await
            .map_err(SmbError::from)?;

        Ok(Self {
            handle,
            target_path: Some(target_path),
        })
    }

    pub async fn disconnect(&mut self) -> Result<()> {
        self.handle.close().await.map_err(SmbError::from)
    }

    pub async fn get_full_info(&self, filename: String) -> Result<String> {
        // Safe to unwrap because there is always a server and share.
        let target_path = self
            .target_path
            .clone()
            .unwrap()
            .with_path(filename.as_str());

        // Define read access mask
        let file_open_args =
            FileCreateArgs::make_open_existing(FileAccessMask::new().with_generic_read(true));

        let resource = self.handle.create_file(&target_path, &file_open_args).await;

        // From openvas-smb the query secinfo flags are 0x7 which means the following three.
        let additional_info = AdditionalInfo::new()
            .with_owner_security_information(true)
            .with_group_security_information(true)
            .with_dacl_security_information(true);

        let response = match resource {
            Ok(Resource::File(f)) => {
                let r = f
                    .query_security_info(additional_info)
                    .await
                    .map_err(|e| SmbError::SmbQuery(e.to_string()))?;
                f.close().await.map_err(|e| SmbError::Smb(e.to_string()))?;
                r
            }
            Ok(Resource::Directory(d)) => {
                let r = d
                    .query_security_info(additional_info)
                    .await
                    .map_err(|e| SmbError::SmbQuery(e.to_string()))?;
                d.close().await.map_err(|e| SmbError::Smb(e.to_string()))?;
                r
            }
            Ok(Resource::Pipe(p)) => {
                let r = p
                    .query_security_info(additional_info)
                    .await
                    .map_err(|e| SmbError::SmbQuery(e.to_string()))?;
                p.close().await.map_err(|e| SmbError::Smb(e.to_string()))?;
                r
            }
            Err(e) => return Err(SmbError::Smb(e.to_string())),
        };

        // convert response to SDDL format
        let mut writer = Cursor::new(Vec::new());
        response
            .write(&mut writer)
            .map_err(|e| SmbError::SerializeError(e.to_string()))?;
        let raw_sd = writer.into_inner();
        let sd = sddl::SecurityDescriptor::from_bytes(&raw_sd)
            .map_err(|e| SmbError::SerializeError(e.to_string()))?;
        let ret = format!("{}", sd);

        Ok(ret)
    }
}

#[derive(Default)]
pub struct SmbHandles {
    handles: HashMap<HandleId, Mutex<SmbHandle>>,
}

impl SmbHandles {
    pub async fn get_by_id(&self, id: HandleId) -> Result<BorrowedHandle<'_>> {
        Ok(self
            .handles
            .get(&id)
            .ok_or(SmbError::SMBHandleIdNotFound(id))?
            .lock()
            .await)
    }

    /// Return the next available session ID
    pub fn next_handle_id(&self) -> Result<HandleId> {
        // Note that the first session ID we will
        // hand out is an arbitrary high number, this is only to help
        // debugging.
        let taken_ids: HashSet<_> = self.handles.keys().collect();
        if taken_ids.is_empty() {
            Ok(MIN_HANDLE_ID)
        } else {
            let max_val = **taken_ids.iter().max().unwrap() + 1;
            Ok((MIN_HANDLE_ID..=max_val)
                .find(|id| !taken_ids.contains(id))
                .unwrap())
        }
    }

    pub fn insert(&mut self, handle_id: HandleId, handle: Mutex<SmbHandle>) {
        self.handles.insert(handle_id, handle);
    }

    pub fn remove(&mut self, handle_id: HandleId) -> Result<()> {
        self.handles.remove(&handle_id);
        Ok(())
    }
}
