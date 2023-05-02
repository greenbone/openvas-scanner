use crate::manager::VTManager;

/// The default VTManager. It contains a simple vector with all known OIDs
#[derive(Default)]
pub struct DefaultVTManager {
    /// List of available OIDs
    vts: Vec<String>,
}

impl DefaultVTManager {
    pub fn new() -> Self {
        DefaultVTManager { vts: vec![] }
    }
}

impl VTManager for DefaultVTManager {
    fn add_oid(&mut self, oid: String) {
        if self.vts.iter().any(|x| x.eq(&oid)) {
            return;
        }
        self.vts.push(oid);
    }

    fn get_oids(&self) -> &Vec<String> {
        &self.vts
    }

    fn remove_oid(&mut self, oid: String) {
        self.vts.retain(|x| !x.eq(&oid))
    }
}

#[cfg(test)]
mod tests {
    use crate::vt_manager::VTManager;

    use super::DefaultVTManager;

    #[test]
    fn test_default_vt_manager() {
        // Test new Manager
        let mut mng = DefaultVTManager::new();
        assert_eq!(mng.get_oids().len(), 0);

        // Test adding new OID
        mng.add_oid("test".to_string());
        assert_eq!(mng.get_oids().len(), 1);
        assert_eq!(mng.get_oids()[0], "test".to_string());

        // Test adding the same OID
        mng.add_oid("test".to_string());
        assert_eq!(mng.get_oids().len(), 1);

        // Test removing OID
        mng.add_oid("test2".to_string());
        mng.remove_oid("test".to_string());
        assert_eq!(mng.get_oids().len(), 1);
        assert_eq!(mng.get_oids()[0], "test2".to_string());
    }
}
