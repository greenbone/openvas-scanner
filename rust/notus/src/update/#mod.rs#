// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use std::{marker::PhantomData, fmt::Display, fs::File, io::Read};

use feed::{SignatureChecker, HashSumFileItem, VerifyError};
use nasl_syntax::{Loader, AsBufReader};
use storage::Dispatcher;
use crate::loader::hashsum::HashsumAdvisoryLoader;

/// Updates notus advisories and uses given storage to store the descriptive
/// information
pub struct Update<S, L, R, K> {
    /// Is used to store data
    dispatcher: S,
    /// Is used to load notus advisories files by a relative path
    loader: L,
    /// How often loader or storage should retry before giving up when a retryable error occurs.
    max_retry: usize,
    feed_version_set: bool,
    phanton: PhantomData<(R,K)>,
    
}

impl<'a, R, S, L, K> SignatureChecker for Update<R, S, L, K>
where
    S: Sync + Send + Dispatcher<K>,
    K: AsRef<str> + Display + Default + From<String>,
    L: Sync + Send + Loader + AsBufReader<File>,
    R: Read + 'a,
{}

impl<'a, S, L,  K, R> Update<S, L,K,R>
where
    S: Sync + Send + Dispatcher<K>,
    K: AsRef<str> + Display + Default + From<String>,
    L: Sync + Send + Loader + AsBufReader<File>,
    R: Read + 'a,
{
    /// Creates an updater. This updater is implemented as a iterator.
    ///
    /// It will iterate through the filenames retrieved by the verifier and execute each found
    /// `.nasl` script in description mode. When there is no filename left than it will handle the
    /// corresponding `plugin_feed_info.inc` to set the feed version. This is done after each file
    /// has run in description mode because some legacy systems consider a feed update done when
    /// the version is set.
    pub fn init(
        max_retry: usize,
        loader: L,
        storage: S,
    ) -> Self {
        Self {
            max_retry,
            loader,
            dispatcher: storage,
            feed_version_set: false,
            phanton: PhantomData,
        }
    }

    /// Perform a signature check of the sha256sums file
    pub fn verify_signature(&self) -> Result<(), VerifyError> {
        //self::SignatureChecker::signature_check(&path)
        let path = self.loader.root_path().unwrap();
        <Update<R, S, L, K> as self::SignatureChecker>::signature_check(&path)
    }
}

