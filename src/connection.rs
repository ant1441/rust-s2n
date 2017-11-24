use std::ffi::{self, CStr};

use s2n::*;
pub use s2n::s2n_mode as Mode;

pub struct Connection {
    s2n_connection: *mut s2n_connection,
}

#[derive(Debug, Fail)]
pub enum ConnectionError {
    #[fail(display = "FFI Error: {}", _0)]
    FFIError(#[cause]
             ffi::NulError),
    #[fail(display = "UTF8 Error: {}", _0)]
    Utf8Error(#[cause]
             ::std::str::Utf8Error),
    #[fail(display = "Error wiping connection")]
    ConnectionWipeError,
    #[fail(display = "Error getting curve")]
    GetCurveError,
}
use self::ConnectionError::*;

type ConnectionResult = Result<(), ConnectionError>;

impl Connection {
    pub fn new(mode: Mode) -> Self {
        super::init();
        let s2n_connection = unsafe { s2n_connection_new(mode) };
        Self { s2n_connection }
    }

    pub fn get_curve(&self) -> Result<Option<String>, ConnectionError> {
        let ret = unsafe { s2n_connection_get_curve(self.s2n_connection) };
        if ret.is_null() {
            return Err(GetCurveError);
        }
        let curve = unsafe { CStr::from_ptr(ret) }.to_str().map_err(Utf8Error)?.to_string();
        if curve == "NONE" {
             Ok(None)
        }else{
            Ok(Some(curve))
        }
    }

    pub fn wipe(&mut self) -> ConnectionResult {
        let ret = unsafe { s2n_connection_wipe(self.s2n_connection) };
        match ret {
            0 => Ok(()),
            -1 => Err(ConnectionWipeError),
            _ => unreachable!(),
        }
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        unsafe { s2n_connection_free(self.s2n_connection) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_drop_connection() {
        let connection = Connection::new(Mode::S2N_SERVER);
        drop(connection);
    }

    #[test]
    fn test_connection_wipe() {
        let mut connection = Connection::new(Mode::S2N_SERVER);
        connection.wipe().unwrap();
    }

    #[test]
    fn test_connection_get_curve_no_curve() {
        let connection = Connection::new(Mode::S2N_SERVER);
        assert!(connection.get_curve().unwrap().is_none());
    }
}
