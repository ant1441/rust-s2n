use std::ffi::{self, CStr, CString};

use config::Config;
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
    #[fail(display = "Error setting connection config")]
    ConnectionSetConfigError,
    #[fail(display = "Error setting connection context")]
    ConnectionSetContextError,
    #[fail(display = "Error setting connection file descripter")]
    ConnectionSetFDError,
    #[fail(display = "Error setting connection server name")]
    ConnectionServerNameError,
}
use self::ConnectionError::*;

type ConnectionResult = Result<(), ConnectionError>;

impl Connection {
    pub fn new(mode: Mode) -> Self {
        super::init();
        let s2n_connection = unsafe { s2n_connection_new(mode) };
        Self { s2n_connection }
    }

    pub fn set_config(&mut self, config: &Config) -> ConnectionResult {
        let ret = unsafe { s2n_connection_set_config(self.s2n_connection, config.s2n_config) };
        match ret {
            0 => Ok(()),
            -1 => Err(ConnectionSetConfigError),
            _ => unreachable!(),
        }
    }

    // pub fn set_fd(&mut self, readfd: FD) -> ConnectionResult {
    //     let ret = unsafe { s2n_connection_set_fd(self.s2n_connection, readfd) };
    //     match ret {
    //         0 => Ok(()),
    //         -1 => Err(ConnectionSetFDError),
    //         _ => unreachable!(),
    //     }
    // }

    // pub fn set_read_fd(&mut self, readfd: FD) -> ConnectionResult {
    //     let ret = unsafe { s2n_connection_set_read_fd(self.s2n_connection, readfd) };
    //     match ret {
    //         0 => Ok(()),
    //         -1 => Err(ConnectionSetFDError),
    //         _ => unreachable!(),
    //     }
    // }

    // pub fn set_write_fd(&mut self, readfd: FD) -> ConnectionResult {
    //     let ret = unsafe { s2n_connection_set_write_fd(self.s2n_connection, readfd) };
    //     match ret {
    //         0 => Ok(()),
    //         -1 => Err(ConnectionSetFDError),
    //         _ => unreachable!(),
    //     }
    // }

    pub fn set_server_name(&mut self, server_name: &str) -> ConnectionResult {
        // These must be on seperate lines to ensure the lifetime of the string is longer than the FFI call
        let server_name_c = CString::new(server_name).map_err(FFIError)?;
        let server_name_ptr = server_name_c.as_ptr();

        let ret = unsafe { s2n_set_server_name(self.s2n_connection, server_name_ptr) };
        match ret {
            0 => Ok(()),
            -1 => Err(ConnectionServerNameError),
            _ => unreachable!(),
        }
    }

    pub fn get_server_name(&mut self) -> Option<String> {
        let ret = unsafe { s2n_get_server_name(self.s2n_connection) };
        if ret.is_null() {
            return None;
        }
        unsafe { CStr::from_ptr(ret) }
            .to_str()
            .ok()
            .map(|s| s.to_string())
    }

    pub fn get_curve(&self) -> Result<Option<String>, ConnectionError> {
        let ret = unsafe { s2n_connection_get_curve(self.s2n_connection) };
        if ret.is_null() {
            return Err(GetCurveError);
        }
        let curve = unsafe { CStr::from_ptr(ret) }
            .to_str()
            .map_err(Utf8Error)?
            .to_string();
        if curve == "NONE" {
            Ok(None)
        } else {
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

impl Connection {
    pub fn set_context<T>(&mut self, mut ctx: T) -> ConnectionResult {
        let ctx_ptr = &mut ctx as *mut _ as *mut ::std::os::raw::c_void;

        let ret = unsafe { s2n_connection_set_ctx(self.s2n_connection, ctx_ptr) };
        match ret {
            0 => Ok(()),
            -1 => Err(ConnectionSetContextError),
            _ => unreachable!(),
        }
    }

    //    pub fn s2n_connection_get_ctx<T>(&self) -> Option<T> {
    //        let ctx_ptr = unsafe { s2n_connection_get_ctx(self.s2n_connection) };
    //        if ctx_ptr.is_null() {
    //            None
    //        } else {
    //            let ctx: &mut T = unsafe { &mut *(ctx_ptr as *mut T) };
    //            Some(ctx)
    //        }
    //    }
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
    fn test_connection_set_config() {
        let mut connection = Connection::new(Mode::S2N_SERVER);
        let config = Config::new();
        connection.set_config(&config).unwrap();
    }

    #[test]
    fn test_connection_set_context() {
        let mut connection = Connection::new(Mode::S2N_SERVER);
        let context = "some data";
        connection.set_context(context).unwrap();
    }

    #[test]
    fn test_connection_get_server_name() {
        let mut connection = Connection::new(Mode::S2N_SERVER);
        assert!(connection.get_server_name().is_none());
    }

    // #[test]
    fn test_connection_set_get_server_name() {
        let mut connection = Connection::new(Mode::S2N_SERVER);
        let name = "server.example.com";
        connection.set_server_name(&name).unwrap();
        // assert_eq!(connection.get_server_name().unwrap(), name);

    }

    #[test]
    fn test_connection_get_curve_no_curve() {
        let connection = Connection::new(Mode::S2N_SERVER);
        assert!(connection.get_curve().unwrap().is_none());
    }

    #[test]
    fn test_connection_wipe() {
        let mut connection = Connection::new(Mode::S2N_SERVER);
        connection.wipe().unwrap();
    }
}
