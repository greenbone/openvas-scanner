use redis::*;
use std::error;
use std::fmt;

pub mod dberror {
    use super::*;

    pub type Result<T> = std::result::Result<T, DbError>;

    #[derive(Debug)]
    pub enum DbError {
        RedisErr(RedisError),
        CustomErr(String),
    }

    impl fmt::Display for DbError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match &*self {
                DbError::RedisErr(..) => write!(f, "Redis Error"),
                DbError::CustomErr(e) => write!(f, "Error: {}", e),
            }
        }
    }

    impl error::Error for DbError {
        fn source(&self) -> Option<&(dyn error::Error + 'static)> {
            match *self {
                DbError::RedisErr(ref e) => Some(e),
                DbError::CustomErr(_) => None,
            }
        }
    }

    impl From<RedisError> for DbError {
        fn from(err: RedisError) -> DbError {
            DbError::RedisErr(err)
        }
    }
}
