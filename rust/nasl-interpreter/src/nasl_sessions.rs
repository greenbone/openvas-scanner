// Copyright (C) 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

//! Defines functions and structures for handling sessions

use std::{sync::{Arc, Mutex}, collections::HashMap};

use crate::nasl_ssh::*;

/// Sessions holder, Holds an array of Tables for different protocols
#[derive(Default)]
pub struct Sessions {
    sessions: Arc<Mutex<Vec<SessionTable>>>,
}

pub trait SessionsHandler {
   fn add_table (&self, session_table: SessionTable);
 }

impl SessionsHandler for Sessions {

    fn add_table(&self, session_table: SessionTable) {
        let mut session = Arc::as_ref(&self.sessions).lock().unwrap();
        session.push(session_table);
    }
}

impl Default for Box<dyn SessionsHandler> {
    fn default() -> Self {
        Box::<Sessions>::default()
    }
}


/// Session Table. Stores open sessions for a given protocol type
pub enum SessionTable {
    /// Ssh session table
    Ssh(SshSessionTable),
    /// SMB session table
    Smb,
    /// Nothing
    Nothing,
}

pub trait SessionTableHandler<S>
where
    S: SshSessionHandler + 'static,
{
    //new/// Create a new Session Table for the given type
    //fn new(&self) -> SessionTable;
    /// Add a session to the table of the given type
    fn add_session(&mut self, session: S) -> Option<usize>;
    /// Remove a session from the table
    fn del_session(&self, sid: i32) -> Option<()>;
    fn get_session_by_position(&self, pos: usize) -> Option<&S>;

}

impl<S> SessionTableHandler<S> for SessionTable
where
    S: SshSessionHandler + 'static
{
    //fn new(&self) -> SessionTable{
    //    Self::Nothing
    //}
    fn add_session(&mut self, session: S) -> Option<usize> {
        Some(0)
    }
    fn del_session(&self, session: i32) -> Option<()> {
        Some(())
    }
    fn get_session_by_position(&self, pos: usize) -> Option<&S> {
        None
    }  
}


//#[cfg(test)]
//mod tests
//{
//    use super::*;
// 
//    #[test]
//    fn create_session() {
//        let s = Sessions::default();
//        let st = SessionTable::Nothing;
//        let pos = s.add_table(st);
//        
//    }
// 
//    #[test]
//    fn create_session_multiple_proto() {
//        
//    }
// 
//    
//}
    
