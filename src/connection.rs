use std::ffi::{self, CStr, CString};
use std::fmt;
use std::net::TcpStream;
use std::string::ToString;
use std::io::{self, Read, Write};

use failure::Fail;

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
    #[fail(display = "Error negotiating connection")]
    ConnectionNegotiateError,
    #[fail(display = "Error getting protocol version")]
    ProtocolVersionError,
    #[fail(display = "Error reading")]
    ReadError,
    #[fail(display = "Error sending")]
    SendError,
}
use self::ConnectionError::*;

type ConnectionResult = Result<(), ConnectionError>;

impl Default for Connection {
    fn default() -> Self {
        Self::new(Mode::S2N_SERVER)
    }
}

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

    pub fn set_tcp_stream(&mut self, stream: &TcpStream) -> ConnectionResult {
        use std::os::unix::io::AsRawFd;

        let fd = stream.as_raw_fd();
        self.set_fd(fd)
    }

    pub fn set_fd(&mut self, readfd: ::std::os::unix::io::RawFd) -> ConnectionResult {
        let ret = unsafe { s2n_connection_set_fd(self.s2n_connection, readfd) };
        match ret {
            0 => Ok(()),
            -1 => Err(ConnectionSetFDError),
            _ => unreachable!(),
        }
    }

    pub fn negotiate(&mut self) -> Result<(), ConnectionError> {
        loop {
            return match self.negotiate_nonblocking() {
                       Ok(None) => Ok(()), // Not blocked
                       Ok(_) => continue,
                       Err(e) => Err(e),
                   };
        }
    }

    pub fn negotiate_nonblocking(&mut self) -> Result<Option<Blocked>, ConnectionError> {
        let mut blocked: s2n_blocked_status = s2n_blocked_status::S2N_NOT_BLOCKED;

        let ret = unsafe { s2n_negotiate(self.s2n_connection, &mut blocked) };
        match ret {
            0 => {
                match blocked {
                    s2n_blocked_status::S2N_NOT_BLOCKED => Ok(None),
                    s2n_blocked_status::S2N_BLOCKED_ON_READ => Ok(Some(Blocked::OnRead)),
                    s2n_blocked_status::S2N_BLOCKED_ON_WRITE => Ok(Some(Blocked::OnWrite)),
                }
            }
            -1 => Err(ConnectionNegotiateError),
            _ => unreachable!(),
        }
    }

    pub fn get_client_hello_version(&self) -> Result<ProtocolVersion, ConnectionError> {
        let ret = unsafe { s2n_connection_get_client_hello_version(self.s2n_connection) };
        ProtocolVersion::from_int(ret as ::std::os::raw::c_uint).ok_or(ProtocolVersionError)
    }

    pub fn get_client_protocol_version(&self) -> Result<ProtocolVersion, ConnectionError> {
        let ret = unsafe { s2n_connection_get_client_protocol_version(self.s2n_connection) };
        ProtocolVersion::from_int(ret as ::std::os::raw::c_uint).ok_or(ProtocolVersionError)
    }

    pub fn get_server_protocol_version(&self) -> Result<ProtocolVersion, ConnectionError> {
        let ret = unsafe { s2n_connection_get_server_protocol_version(self.s2n_connection) };
        ProtocolVersion::from_int(ret as ::std::os::raw::c_uint).ok_or(ProtocolVersionError)
    }

    pub fn get_actual_protocol_version(&self) -> Result<ProtocolVersion, ConnectionError> {
        let ret = unsafe { s2n_connection_get_actual_protocol_version(self.s2n_connection) };
        ProtocolVersion::from_int(ret as ::std::os::raw::c_uint).ok_or(ProtocolVersionError)
    }


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

    pub fn get_application_protocol(&mut self) -> Option<String> {
        let ret = unsafe { s2n_get_application_protocol(self.s2n_connection) };
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

    pub fn get_cipher(&mut self) -> Option<String> {
        let ret = unsafe { s2n_connection_get_cipher(self.s2n_connection) };
        if ret.is_null() {
            return None;
        }
        unsafe { CStr::from_ptr(ret) }
            .to_str()
            .ok()
            .map(|s| s.to_string())
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

impl Read for Connection {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut blocked: s2n_blocked_status = s2n_blocked_status::S2N_NOT_BLOCKED;

        let bytes_read = unsafe {
            s2n_recv(self.s2n_connection,
                     buf.as_mut_ptr() as *mut ::std::os::raw::c_void,
                     buf.len() as isize,
                     &mut blocked)
        };

        if bytes_read < 0 {
            return Err(io::Error::new(io::ErrorKind::ConnectionReset, ReadError.compat()));
        }
        if bytes_read == 0 {
            // Connection has been closed
            let _ = self.wipe();
        }
        Ok(bytes_read as usize)
    }

    #[cfg(nightly)]
    #[inline]
    unsafe fn initializer(&self) -> ::std::io::Initializer {
        ::std::io::Initializer::nop()
    }
}

impl Write for Connection {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut blocked: s2n_blocked_status = s2n_blocked_status::S2N_NOT_BLOCKED;

        let bytes_read = unsafe {
            s2n_send(self.s2n_connection,
                     buf.as_ptr() as *mut ::std::os::raw::c_void,
                     buf.len() as isize,
                     &mut blocked)
        };

        if bytes_read <= 0 {
            return Err(io::Error::new(io::ErrorKind::ConnectionReset, SendError.compat()))?;
        }
        Ok(bytes_read as usize)
    }

    fn flush(&mut self) -> io::Result<()> {
        /* noop */
        Ok(())
    }
}

pub enum Blocked {
    OnRead,
    OnWrite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolVersion {
    SSLv2,
    SSLv3,
    TLS10,
    TLS11,
    TLS12,
    UnknownProtocolVersion,
}

impl ProtocolVersion {
    #[allow(non_upper_case_globals)]
    fn from_int(i: ::std::os::raw::c_uint) -> Option<Self> {
        use self::ProtocolVersion::*;
        Some(match i {
                 S2N_SSLv2 => SSLv2,
                 S2N_SSLv3 => SSLv3,
                 S2N_TLS10 => TLS10,
                 S2N_TLS11 => TLS11,
                 S2N_TLS12 => TLS12,
                 S2N_UNKNOWN_PROTOCOL_VERSION => UnknownProtocolVersion,
                 _ => return None,
             })
    }
}


impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::ProtocolVersion::*;
        let s = match *self {
            SSLv2 => "SSLv2",
            SSLv3 => "SSLv3",
            TLS10 => "TLSv1.0",
            TLS11 => "TLSv1.1",
            TLS12 => "TLSv1.2",
            UnknownProtocolVersion => "Unknown Protocol Version",
        };
        write!(f, "{}", s)
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

    #[test]
    fn test_protocolversion_from_int() {
        assert_eq!(ProtocolVersion::UnknownProtocolVersion,
                   ProtocolVersion::from_int(0).unwrap())
    }

    #[test]
    fn test_protocolversion_from_c_int() {
        assert_eq!(ProtocolVersion::TLS12,
                   ProtocolVersion::from_int(S2N_TLS12).unwrap())
    }

    #[test]
    fn test_protocolversion_display() {
        assert_eq!("TLSv1.2", ProtocolVersion::TLS12.to_string())
    }
}
