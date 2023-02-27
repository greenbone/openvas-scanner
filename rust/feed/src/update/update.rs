use nasl_interpreter::{ContextType, FSPluginLoader, Interpreter, Loader, NaslValue, Register};
use sink::Sink;

use super::{Error, Key};

pub struct Update<'a> {
    storage: &'a dyn Sink,
    loader: &'a dyn Loader,
    initial: Vec<(String, ContextType)>,
    max_retry: usize,
}

impl<'a> Update<'a> {
    pub fn new(
        openvas_version: &str,
        max_retry: usize,
        loader: &'a dyn Loader,
        storage: &'a dyn Sink,
    ) -> Self {
        let initial = vec![
            ("description".to_owned(), true.into()),
            ("OPENVAS_VERSION".to_owned(), openvas_version.into()),
        ];
        Self {
            initial,
            max_retry,
            loader,
            storage,
        }
    }
    pub fn single(&self, key: &'a Key) -> Result<i64, Error> {
        let code = match key {
            Key::NASLPath {
                path,
                root_dir_len: _,
            } => {
                let code = FSPluginLoader::load_non_utf8_path(path)?;
                code
            }
        };

        let mut register = Register::root_initial(&self.initial);
        let mut interpreter =
            Interpreter::new(key.as_ref(), self.storage, self.loader, &mut register);
        self.run(key.as_ref(), &code, &mut interpreter)
    }

    fn run(&self, key: &str, code: &str, interpreter: &mut Interpreter) -> Result<i64, Error> {
        for stmt in nasl_syntax::parse(code) {
            match interpreter.retry_resolve(&stmt?, self.max_retry) {
                Ok(NaslValue::Exit(i)) => {
                    self.storage.on_exit()?;
                    return Ok(i);
                }
                Ok(_) => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err(Error::MissingExit {
            key: key.to_owned(),
        })
    }
}
